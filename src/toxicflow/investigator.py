"""LLM investigator. It reaches the graph only through the ToxicFlow MCP server, picks
tools itself, and ends with a proposal that a human must approve.

The final reply is checked against the graph: every `backticked` identifier must be a
real agent, tool, store or capability. If not, a plain summary built from the tool
results is shown instead.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
from dataclasses import dataclass, field

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from openai import OpenAI
from rich.console import Console

from .config import load_env, openai_model
from .service import ToxicFlowService

console = Console()

INSTRUCTIONS = """You are a security investigator for multi-agent MCP setups.
A toxic flow is: an agent reads untrusted input, some agent (maybe another one) is then steered into
reading private data, and some agent (maybe a third) can send that data out. Content travels along
delegation (instructions down, free-text results up) and through shared stores.

Work only from tool results. Never invent agent, tool or store names.
0. Call recall for the agents involved to see what earlier sessions found and changed; say so if a
   finding was already fixed.
1. Compare what a per-agent scan sees with the multi-hop search.
2. Explain the most dangerous flow with its exact path.
3. Find the least disruptive repair that removes every flow and keeps every task working. Check it with
   simulate_repair before proposing. Say why the obvious single fixes are not enough.
4. If any flow is UNKNOWN, say what labelling is missing instead of calling it safe.
5. Call propose_repair once with the chosen actions. You cannot apply changes; a human approves.

Final answer: short markdown. Put every agent, tool, store and capability name in `backticks`."""


@dataclass
class Trace:
    calls: list[dict] = field(default_factory=list)
    proposal: str | None = None


def _result_payload(result) -> str:
    if getattr(result, "structured_content", None) is not None:
        payload = result.structured_content
    elif getattr(result, "structuredContent", None) is not None:
        payload = result.structuredContent
    else:
        payload = "\n".join(getattr(c, "text", "") for c in result.content)
    text = payload if isinstance(payload, str) else json.dumps(payload)
    if getattr(result, "is_error", False) or getattr(result, "isError", False):
        text = "ERROR: " + text
    return text[:12000]


def _summary(text: str, n: int = 160) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 1] + "…"


def validate_reply(reply: str, svc: ToxicFlowService) -> list[str]:
    known = set()
    for label in ("Agent", "Tool", "Store", "Capability", "Task"):
        key = "name" if label == "Capability" else "id"
        known |= {r[0] for r in svc.g.ro_query(f"MATCH (n:{label}) RETURN n.{key}").result_set}
    known |= {r[0] for r in svc.g.ro_query("CALL db.relationshipTypes()").result_set}
    known |= {"TOXIC", "UNKNOWN", "text", "structured", "quarantine", "isolate", "revoke", "cut"}
    known |= {"list_agents", "agent_profile", "tool_info", "one_hop_scan", "find_toxic_flows", "check_tasks",
              "simulate_repair", "search_repairs", "propose_repair", "recall"}  # the MCP tools themselves
    bad = set()
    for tok in re.findall(r"`([^`\n]+)`", reply):
        if tok in known or re.fullmatch(r"prop-\w+", tok):
            continue
        # paths like `a -> b -> c` or `a -[INSTRUCTS]-> b`: every node must exist
        parts = [p.strip() for p in re.split(r"-\[?[A-Z_]*\]?->|->|→", tok)]
        if len(parts) > 1 and all(p in known for p in parts if p):
            continue
        bad.add(tok)
    return sorted(bad)


async def investigate(scenario: str, question: str | None = None, max_turns: int = 16) -> tuple[str, Trace]:
    load_env()
    client = OpenAI()
    model = openai_model()
    params = StdioServerParameters(command=sys.executable, args=["-m", "toxicflow.cli", "mcp", scenario])
    trace = Trace()

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            tools = [
                {
                    "type": "function",
                    "name": t.name,
                    "description": t.description or "",
                    "parameters": t.input_schema if hasattr(t, "input_schema") else t.inputSchema,
                    "strict": False,
                }
                for t in listed.tools
            ]
            console.print(f"[dim]model {model}; MCP tools: {', '.join(t['name'] for t in tools)}[/dim]")

            resp = client.responses.create(
                model=model,
                instructions=INSTRUCTIONS,
                input=question or f"Investigate the '{scenario}' agent setup and propose a repair.",
                tools=tools,
            )
            for _ in range(max_turns):
                calls = [o for o in resp.output if o.type == "function_call"]
                if not calls:
                    break
                outputs = []
                for c in calls:
                    args = json.loads(c.arguments or "{}")
                    result = await session.call_tool(c.name, args)
                    text = _result_payload(result)
                    trace.calls.append({"tool": c.name, "args": args, "result": text})
                    console.print(f"[cyan]→ {c.name}[/cyan]({_summary(json.dumps(args), 120)})  [dim]{_summary(text)}[/dim]")
                    if c.name == "propose_repair" and not text.startswith("ERROR"):
                        m = re.search(r"prop-\w+", text)
                        trace.proposal = m.group(0) if m else trace.proposal
                    outputs.append({"type": "function_call_output", "call_id": c.call_id, "output": text})
                resp = client.responses.create(
                    model=model, instructions=INSTRUCTIONS, previous_response_id=resp.id, input=outputs, tools=tools
                )
            return resp.output_text or "", trace


def run(scenario: str, question: str | None = None) -> int:
    reply, trace = asyncio.run(investigate(scenario, question))
    svc = ToxicFlowService(scenario)
    bad = validate_reply(reply, svc)
    console.rule("Investigator")
    if bad:
        console.print(f"[yellow]Reply named things that are not in the graph {bad}; showing the graph's own result instead.[/yellow]")
        flows = svc.find_toxic_flows()
        console.print(f"{flows['toxic']} toxic flows, {flows['unknown']} unknown.")
        for f in flows["flows"][:3]:
            console.print(f"- {f['status']}: {' -> '.join(f['path'])}")
    else:
        console.print(reply)
    console.print(f"\n[dim]{len(trace.calls)} tool calls via MCP.[/dim]")
    if trace.proposal:
        console.print(f"[bold]Proposal {trace.proposal} is waiting for approval:[/bold] toxicflow approve {scenario} {trace.proposal}")
    return 0
