"""MCP server exposing the ToxicFlow tool catalogue for one scenario graph.

    toxicflow mcp acme        (stdio)

Each tool runs fixed, parameterised Cypher. There is no tool that accepts Cypher,
and there is no tool that applies a change: proposals wait for a human `approve`.
"""

from __future__ import annotations

import functools
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from .service import InvalidArgument, ToxicFlowService


def _clear_errors(fn):
    """Return validation messages to the model so it can correct its arguments."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except InvalidArgument as exc:
            raise ToolError(str(exc)) from exc

    return wrapper


def build(scenario: str, reload: bool = False) -> MCPServer:
    svc = ToxicFlowService(scenario, reload=reload)
    server = MCPServer(
        name="toxicflow",
        instructions=(
            "Investigate toxic flows in a multi-agent MCP setup stored in FalkorDB. "
            "A toxic flow is untrusted input -> private data read -> outbound sink, possibly across agents. "
            "Use the tools; never guess agent or tool names."
        ),
        log_level="ERROR",
    )

    @server.tool()
    @_clear_errors
    def list_agents() -> list[dict]:
        """List every agent in the setup with its purpose."""
        return svc.list_agents()

    @server.tool()
    @_clear_errors
    def agent_profile(agent: str) -> dict:
        """Tools an agent can call grouped by capability, plus who it delegates to and which shared stores it reads or writes."""
        return svc.agent_profile(agent)

    @server.tool()
    @_clear_errors
    def tool_info(tool: str) -> dict:
        """Capabilities and labelling reason for one tool id such as 'slack.slack_post_message'."""
        return svc.tool_info(tool)

    @server.tool()
    @_clear_errors
    def one_hop_scan() -> dict:
        """Per-agent check only (what a conventional scanner sees). Does not follow delegation or shared stores."""
        return svc.one_hop_scan()

    @server.tool()
    @_clear_errors
    def find_toxic_flows(include_unknown: bool = True) -> dict:
        """Multi-hop search over delegation and shared stores for untrusted -> private -> sink flows, with witness paths.
        Flows that rely on unlabelled tools are reported with status UNKNOWN."""
        return svc.find_toxic_flows(include_unknown)

    @server.tool()
    @_clear_errors
    def check_tasks() -> dict:
        """Which declared tasks are currently broken (an assigned agent can no longer reach a needed tool)."""
        return svc.check_tasks()

    @server.tool()
    @_clear_errors
    def simulate_repair(actions: list[dict[str, Any]]) -> dict:
        """Try interventions on a throwaway copy of the graph and report remaining flows and broken tasks.
        Each action is {"kind": quarantine|isolate|revoke|cut, "a": ..., "b": ...}:
        quarantine/cut: a=parent agent, b=child agent; isolate: a=agent, b=store id; revoke: a=agent, b=capability."""
        return svc.simulate_repair(actions)

    @server.tool()
    @_clear_errors
    def search_repairs(max_actions: int = 4, top: int = 3) -> dict:
        """Search for the cheapest intervention sets that remove every toxic flow while keeping every task working.
        Also explains why each obvious single intervention fails."""
        return svc.search_repairs(max_actions, top)

    @server.tool()
    @_clear_errors
    def propose_repair(actions: list[dict[str, Any]], rationale: str) -> dict:
        """Record a repair proposal for human approval. It is re-simulated first and refused if it is not acceptable."""
        return svc.propose_repair(actions, rationale)

    @server.tool()
    @_clear_errors
    def recall(agent: str) -> list[dict]:
        """Findings and remediations recorded in earlier sessions that involve this agent."""
        return svc.recall(agent)

    return server


def main(scenario: str, reload: bool = False) -> None:
    build(scenario, reload).run("stdio")
