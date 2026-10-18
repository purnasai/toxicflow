"""Runtime gate in front of real MCP servers.

  toxicflow gate <scenario> <agent> --session S   MCP server (stdio) for one agent: exposes exactly
                                                  the tools the graph says it may call, checks each
                                                  call with the Gate, forwards allowed calls.
  toxicflow replay <scenario> <attack>             drive a scripted multi-agent session through the gate.

Downstream calls go to the real MCP server from data/servers.yaml (started on demand), except
tools listed in data/fixtures/<scenario>.yaml, which need credentials we do not have.
"""

from __future__ import annotations

import json
import os
from contextlib import AsyncExitStack

import anyio
import yaml
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from rich.console import Console
from rich.table import Table

from .gate import Decision, FixtureBackend, Gate, fixture_path
from .queries import DATAFLOW, MAX_HOPS

REACHES = f"""
MATCH p = (:Agent {{id: $src}})-[:{DATAFLOW}*0..{MAX_HOPS}]->(:Agent {{id: $dst}})
RETURN [n IN nodes(p) | n.id] ORDER BY length(p) LIMIT 1
"""

INSTANCE_OF = "MATCH (:Agent {id: $agent})-[c:CAN_CALL]->(:Tool {id: $tool}) RETURN c.instance"
from .labels import DATA
from .service import ToxicFlowService

console = Console(stderr=True)
SANDBOX = DATA / "sandbox"
SEP = "__"


def seed_sandbox() -> None:
    """A tiny fake project for the filesystem server. The secret is fake."""
    proj = SANDBOX / "project"
    proj.mkdir(parents=True, exist_ok=True)
    (proj / ".env").write_text("PAYMENTS_API_KEY=demo_live_4f9a2c-NOT-A-REAL-KEY\nDB_PASSWORD=hunter2-demo\n")
    (proj / "app.py").write_text("def total(items):\n    return sum(i.price for i in items)  # bug: ignores quantity\n")
    mem = SANDBOX / "memory"  # fresh store files for every run
    mem.mkdir(parents=True, exist_ok=True)
    for f in mem.glob("*.json"):
        f.unlink()


def instance_of(g, agent: str, tool: str) -> str:
    rows = g.ro_query(INSTANCE_OF, {"agent": agent, "tool": tool}).result_set
    return rows[0][0] if rows else "default"


class Backends:
    def __init__(self, scenario: str):
        self.fixtures = FixtureBackend(fixture_path(scenario))
        self.specs = {s["id"]: s for s in yaml.safe_load((DATA / "servers.yaml").read_text())["servers"]}
        self.stack = AsyncExitStack()
        self.sessions: dict[str, ClientSession] = {}

    async def __aenter__(self):
        await self.stack.__aenter__()
        return self

    async def __aexit__(self, *exc):
        await self.stack.__aexit__(*exc)

    async def start(self, calls: list[tuple[str, str]]) -> None:
        """Start every real downstream server these (tool, instance) pairs need, in the caller's task.
        (Starting them lazily inside a request handler breaks anyio cancel scopes.)"""
        for tool, instance in sorted(set(calls)):
            if not self.fixtures.handles(tool):
                await self._session(tool.split(".", 1)[0], instance)

    def _key(self, server: str, instance: str) -> str:
        spec = self.specs[server]
        aware = "{INSTANCE}" in json.dumps([spec.get("args", []), spec.get("env", {})])
        return f"{server}/{instance}" if aware else server  # instance-aware servers get one process per instance

    async def _session(self, server: str, instance: str = "default") -> ClientSession:
        key = self._key(server, instance)
        if key not in self.sessions:
            spec = self.specs[server]
            fill = lambda v: v.replace("{SANDBOX}", str(SANDBOX)).replace("{INSTANCE}", instance.replace("/", "_"))  # noqa: E731
            args = [fill(a) for a in spec.get("args", [])]
            env = {k: fill(v) for k, v in spec.get("env", {}).items()}
            params = StdioServerParameters(command=spec["command"], args=args, env={**os.environ, **env})
            read, write = await self.stack.enter_async_context(stdio_client(params))
            session = await self.stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            self.sessions[key] = session
        return self.sessions[key]

    async def call(self, tool: str, args: dict, instance: str = "default") -> tuple[str, bool]:
        if self.fixtures.handles(tool):
            return await self.fixtures.call(tool, args), False
        server, name = tool.split(".", 1)
        result = await (await self._session(server, instance)).call_tool(name, args)
        text = "\n".join(getattr(c, "text", "") for c in result.content)
        return text, bool(getattr(result, "is_error", False) or getattr(result, "isError", False))


def _blocked_text(tool: str, d: Decision) -> str:
    return f"BLOCKED by ToxicFlow ({d.status}): {d.reason}. Path: {' -> '.join(d.path)}. Tool {tool} was not called."


# ------------------------------------------------------------------ MCP proxy


def serve(scenario: str, agent: str, session: str) -> None:
    seed_sandbox()
    svc = ToxicFlowService(scenario)
    svc._agent(agent)
    gate = Gate(svc.g, session)
    schemas = {}
    for f in (DATA / "tools").glob("*.json"):
        d = json.loads(f.read_text())
        for t in d["tools"]:
            schemas[f"{d['server']}.{t['name']}"] = t

    def allowed_tools() -> list[str]:
        q = "MATCH (:Agent {id: $a})-[:CAN_CALL]->(t:Tool) RETURN t.id ORDER BY t.id"
        return [r[0] for r in svc.g.ro_query(q, {"a": agent}).result_set]

    async def on_list_tools(ctx, params) -> types.ListToolsResult:
        tools = []
        for tid in allowed_tools():
            s = schemas[tid]
            tools.append(
                types.Tool(
                    name=tid.replace(".", SEP, 1),
                    description=f"[{tid.split('.')[0]}] {s.get('description', '')}"[:1000],
                    input_schema=s.get("input_schema") or s.get("inputSchema") or {"type": "object"},
                )
            )
        return types.ListToolsResult(tools=tools)

    async def on_call_tool(ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
        tool = params.name.replace(SEP, ".", 1)
        args = params.arguments or {}
        d = gate.check(agent, tool)
        seq = gate.record(agent, tool, d, args)
        console.print(f"[dim]#{seq}[/dim] {agent} {tool}: {d.status} {d.reason}")
        if not d.allowed:
            return types.CallToolResult(content=[types.TextContent(type="text", text=_blocked_text(tool, d))], isError=True)
        text, err = await backends.call(tool, args, instance_of(svc.g, agent, tool))
        if err:
            gate.mark_failed(seq)
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)], isError=err)

    server = Server(f"toxicflow-gate-{agent}", on_list_tools=on_list_tools, on_call_tool=on_call_tool)

    async def main():
        global backends
        async with Backends(scenario) as b:
            await b.start([(t, instance_of(svc.g, agent, t)) for t in allowed_tools()])
            backends = b
            async with stdio_server() as (read, write):
                await server.run(read, write, server.create_initialization_options())

    anyio.run(main)


backends: Backends


# ------------------------------------------------------------------ scripted replay


async def _replay(scenario: str, attack: dict, session: str, svc: ToxicFlowService, use_gate: bool = True) -> list[tuple]:
    gate = Gate(svc.g, session)
    rows = []
    async with Backends(scenario) as b:
        await b.start([(s["tool"], instance_of(svc.g, s["agent"], s["tool"])) for s in attack["steps"]])
        for i, step in enumerate(attack["steps"], 1):
            agent, tool = step["agent"], step["tool"]
            args = json.loads(json.dumps(step.get("args", {})).replace("{SANDBOX}", str(SANDBOX)))
            if "uses" in step:
                n = step["uses"]
                src = attack["steps"][n - 1]["agent"]
                if not rows[n - 1][4].allowed:
                    why = f"step {n} never happened, so its data does not exist"
                elif not svc.g.ro_query(REACHES, {"src": src, "dst": agent}).result_set:
                    why = f"data from step {n} ({src}) has no path to {agent} in the graph"
                else:
                    why = ""
                if why:
                    d = Decision("unreachable", "UNREACHABLE", why + "; this step cannot happen")
                    rows.append((gate.record(agent, tool, d, args), agent, tool, step.get("note", ""), d, ""))
                    continue
            d = gate.check(agent, tool) if use_gate else Decision("allow", "ALLOW", "gate disabled")
            seq = gate.record(agent, tool, d, args)
            out = ""
            if d.allowed:
                out, err = await b.call(tool, args, instance_of(svc.g, agent, tool))
                if err:
                    gate.mark_failed(seq)
            rows.append((seq, agent, tool, step.get("note", ""), d, out))
    return rows


def run_replay(scenario: str, attack_name: str, mode: str = "gate", graph_name: str | None = None) -> dict:
    """mode: 'nogate' (baseline), 'gate', or 'after' (cheapest repair applied first, gate on).
    Returns plain data; the CLI and the UI render it."""
    if mode not in ("nogate", "gate", "after"):
        raise ValueError("mode must be nogate, gate or after")
    seed_sandbox()
    attack = yaml.safe_load((DATA / "attacks" / f"{attack_name}.yaml").read_text())
    if graph_name is None:
        # Never touch the active graph (approved repairs, recorded sessions): replay on a disposable copy.
        from .graph import connect, open_graph

        db, graph_name = connect(), f"toxicflow_{scenario}__replay"
        if graph_name in db.list_graphs():
            db.select_graph(graph_name).delete()
        open_graph(db, scenario).copy(graph_name)  # active state (loaded fresh if missing or out of date)
        svc = ToxicFlowService(scenario, graph_name=graph_name)
    else:
        svc = ToxicFlowService(scenario, reload=True, graph_name=graph_name)
    repair = []
    if mode == "after":
        from .repair import apply_repair, search

        solutions = search(svc.db, svc.g)[0]
        if solutions:
            apply_repair(svc.db, svc.g, solutions[0].actions)
            repair = [a.describe() for a in solutions[0].actions]
    session = f"{attack_name}-{mode}"
    rows = anyio.run(_replay, scenario, attack, session, svc, mode != "nogate")

    sinks = {r[0] for r in svc.g.ro_query("MATCH (t:Tool)-[:HAS_CAP]->(:Capability {name: 'exfil_sink'}) RETURN t.id").result_set}
    secret = attack.get("secret", "\0")
    steps = []
    for (seq, agent, tool, note, d, result), step in zip(rows, attack["steps"]):
        # grounded: the secret must have actually been obtained by the step this one depends on
        present = "uses" not in step or secret in str(rows[step["uses"] - 1][5])
        leaked = d.allowed and tool in sinks and secret in json.dumps(step.get("args", {})) and present
        steps.append(
            {
                "seq": seq, "agent": agent, "tool": tool, "note": note, "status": d.status,
                "reason": d.reason, "path": d.path, "routes": d.routes, "result": _short(result, 300), "leaked": leaked,
            }
        )
    return {
        "title": attack.get("title", attack_name),
        "mode": mode,
        "repair": repair,
        "session": session,
        "graph": svc.g.name,
        "steps": steps,
        "blocked": sum(r[4].decision == "block" for r in rows),
        "unreachable": sum(r[4].status == "UNREACHABLE" for r in rows),
        "leaked_via": [x["tool"] for x in steps if x["leaked"]],
    }


def replay(scenario: str, attack_name: str, after_repair: bool = False, use_gate: bool = True) -> int:
    mode = "after" if after_repair else ("gate" if use_gate else "nogate")
    r = run_replay(scenario, attack_name, mode)
    label = {"nogate": "gate disabled", "gate": "gate on"}.get(mode) or "after repair: " + "; ".join(r["repair"])
    out = Console()
    t = Table(title=f"{r['title']} ({label})", show_lines=True)
    for col in ("#", "agent", "tool", "step", "gate", "reason / result"):
        t.add_column(col, overflow="fold")
    colour = {"ALLOW": "green", "ALLOW_TAINTED": "yellow", "BLOCK": "red", "BLOCK_UNKNOWN": "red", "DENY_NOT_MOUNTED": "red", "UNREACHABLE": "cyan"}
    for x in r["steps"]:
        detail = x["reason"] if x["status"] != "ALLOW" else _short(x["result"])
        if x["path"]:
            detail += f"\npath: {' -> '.join(x['path'])}"
        t.add_row(str(x["seq"]), x["agent"], x["tool"], x["note"], f"[{colour[x['status']]}]{x['status']}[/]", detail)
    out.print(t)
    out.print(f"{r['blocked']} call(s) blocked, {r['unreachable']} step(s) impossible. Session '{r['session']}' recorded in graph {r['graph']}.")
    if r["leaked_via"]:
        out.print(f"[red]Secret left through: {r['leaked_via']}[/red]")
    else:
        out.print("[green]The secret did not leave through any outbound tool.[/green]")
    return 1 if r["leaked_via"] else 0


def _short(text: str, n: int = 140) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 1] + "…"

