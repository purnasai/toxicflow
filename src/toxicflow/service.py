"""Validated operations over one scenario graph. The MCP server exposes exactly these;
every name an LLM passes in is resolved against the graph before any query runs."""

from __future__ import annotations

from datetime import datetime, timezone

from falkordb import FalkorDB, Graph

from . import queries as Q
from .analyze import Flow, broken_tasks, flows, one_hop
from .graph import connect, load, load_scenario_file
from .memory import recall as recall_findings
from .memory import record
from .repair import COST, Action, Simulator, apply_repair, search


class InvalidArgument(ValueError):
    pass


def _flow_dict(f: Flow) -> dict:
    return {
        "status": f.status,
        "entry": f.entry,
        "reader": f.reader,
        "exit": f.exit,
        "hops": f.hops,
        "path": f.path_in + f.path_out[1:],
        "steps": [f"{a} -[{r}]-> {b}" for a, r, b in f.steps()],
        "untrusted_tools": f.sources,
        "private_tools": f.readers,
        "sink_tools": f.sinks,
        "via_unknown": f.via_unknown,
    }


class ToxicFlowService:
    def __init__(self, scenario: str, db: FalkorDB | None = None, reload: bool = False):
        self.db = db or connect()
        self.scenario = scenario
        name = f"toxicflow_{scenario}"
        if reload or name not in self.db.list_graphs():
            self.g: Graph = load(self.db, load_scenario_file(scenario))
        else:
            self.g = self.db.select_graph(name)

    # ------------------------------------------------------------ name resolution

    def _ids(self, label: str) -> list[str]:
        return [r[0] for r in self.g.ro_query(f"MATCH (n:{label}) RETURN n.id ORDER BY n.id").result_set]

    def _agent(self, agent: str) -> str:
        agents = self._ids("Agent")
        if agent not in agents:
            raise InvalidArgument(f"unknown agent {agent!r}; valid agents: {agents}")
        return agent

    def _action(self, raw: dict) -> Action:
        kind, a, b = raw.get("kind"), raw.get("a"), raw.get("b")
        if kind not in COST:
            raise InvalidArgument(f"kind must be one of {sorted(COST)}")
        self._agent(a)
        if kind in ("quarantine", "cut"):
            self._agent(b)
            n = self.g.ro_query(
                "MATCH (:Agent {id: $a})-[d:DELEGATES_TO]->(:Agent {id: $b}) RETURN count(d)", {"a": a, "b": b}
            ).result_set[0][0]
            if not n:
                raise InvalidArgument(f"no delegation {a} -> {b}; for quarantine/cut, a is the parent and b the child")
        elif kind == "revoke" and b not in ("untrusted_input", "private_read", "exfil_sink", "store_read", "store_write"):
            raise InvalidArgument("for revoke, b is a capability: untrusted_input, private_read, exfil_sink, store_read, store_write")
        elif kind == "isolate" and b not in self._ids("Store"):
            raise InvalidArgument(f"unknown store {b!r}; valid stores: {self._ids('Store')}")
        return Action(kind, a, b)

    # ------------------------------------------------------------ read tools

    def list_agents(self) -> list[dict]:
        rows = self.g.ro_query("MATCH (a:Agent) RETURN a.id, a.purpose ORDER BY a.id").result_set
        return [{"agent": a, "purpose": p} for a, p in rows]

    def agent_profile(self, agent: str) -> dict:
        agent = self._agent(agent)
        caps = self.g.ro_query(
            """
            MATCH (a:Agent {id: $a})-[c:CAN_CALL]->(t:Tool)-[:HAS_CAP]->(cap:Capability)
            RETURN cap.name, collect(t.id) ORDER BY cap.name
            """,
            {"a": agent},
        ).result_set
        rel = self.g.ro_query(
            """
            MATCH (a:Agent {id: $a})
            OPTIONAL MATCH (a)-[d:DELEGATES_TO]->(c:Agent)
            OPTIONAL MATCH (p:Agent)-[pd:DELEGATES_TO]->(a)
            OPTIONAL MATCH (a)-[:WRITES_TO]->(ws:Store)
            OPTIONAL MATCH (rs:Store)-[:FEEDS]->(a)
            RETURN a.purpose, collect(DISTINCT c.id + ' (returns ' + d.returns + ')'),
                   collect(DISTINCT p.id), collect(DISTINCT ws.id), collect(DISTINCT rs.id)
            """,
            {"a": agent},
        ).result_set[0]
        return {
            "agent": agent,
            "purpose": rel[0],
            "tools_by_capability": {c: ids for c, ids in caps},
            "delegates_to": rel[1],
            "delegated_by": rel[2],
            "writes_stores": rel[3],
            "reads_stores": rel[4],
        }

    def tool_info(self, tool: str) -> dict:
        rows = self.g.ro_query(Q.TOOL_INFO, {"tool": tool}).result_set
        if not rows:
            raise InvalidArgument(f"unknown tool {tool!r}; tool ids look like 'server.tool_name'")
        t, desc, caps, why = rows[0]
        return {"tool": t, "capabilities": caps, "why": why, "description": desc[:300]}

    def one_hop_scan(self) -> dict:
        need = {"untrusted_input", "private_read", "exfil_sink"}
        view = one_hop(self.g)
        return {
            "per_agent": {a: [c for c in caps if c in need] for a, caps in view.items()},
            "agents_toxic_on_their_own": [a for a, caps in view.items() if need <= set(caps)],
            "note": "This is what a per-agent scanner sees. It does not follow delegation or shared stores.",
        }

    def find_toxic_flows(self, include_unknown: bool = True) -> dict:
        found = flows(self.g, include_unknown=include_unknown)
        return {
            "toxic": sum(f.status == "TOXIC" for f in found),
            "unknown": sum(f.status == "UNKNOWN" for f in found),
            "flows": [_flow_dict(f) for f in found],
        }

    def check_tasks(self) -> dict:
        return {"broken": broken_tasks(self.g)}

    def recall(self, agent: str) -> list[dict]:
        return recall_findings(self.g, self._agent(agent))

    # ------------------------------------------------------------ what-if tools

    def simulate_repair(self, actions: list[dict]) -> dict:
        acts = tuple(sorted(self._action(a) for a in actions))
        trial = Simulator(self.db, self.g).trial(acts)
        return {
            "actions": [a.describe() for a in acts],
            "cost": trial.cost,
            "removes_all_flows": not trial.remaining,
            "flows_remaining": [_flow_dict(f) for f in trial.remaining],
            "broken_tasks": trial.broken,
            "acceptable": trial.ok,
        }

    def search_repairs(self, max_actions: int = 4, top: int = 3) -> dict:
        solutions, rejected = search(self.db, self.g, max_actions=min(max_actions, 5))
        return {
            "repairs": [
                {"cost": s.cost, "actions": [vars(a) for a in s.actions], "describe": [a.describe() for a in s.actions]}
                for s in solutions[:top]
            ],
            "rejected_single_actions": [
                {
                    "action": t.actions[0].describe(),
                    "reason": f"breaks tasks {t.broken}" if t.broken else f"{len(t.remaining)} flows remain",
                }
                for t in rejected
            ],
        }

    # ------------------------------------------------------------ proposals (human approves)

    def propose_repair(self, actions: list[dict], rationale: str) -> dict:
        """Record a proposal. It is only applied when a human runs `toxicflow approve <id>`."""
        sim = self.simulate_repair(actions)
        if not sim["acceptable"]:
            raise InvalidArgument(f"proposal rejected by simulation: {sim}")
        pid = f"prop-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')}"
        self.g.query(
            "CREATE (:Proposal {id: $id, at: $at, actions: $actions, rationale: $why, status: 'pending', cost: $cost})",
            {
                "id": pid,
                "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "actions": [f"{a['kind']}|{a['a']}|{a['b']}" for a in actions],
                "why": rationale[:2000],
                "cost": sim["cost"],
            },
        )
        return {"proposal": pid, "status": "pending human approval", "simulation": sim}

    def approve(self, proposal_id: str) -> dict:
        rows = self.g.ro_query(
            "MATCH (p:Proposal {id: $id, status: 'pending'}) RETURN p.actions", {"id": proposal_id}
        ).result_set
        if not rows:
            raise InvalidArgument(f"no pending proposal {proposal_id!r}")
        acts = tuple(Action(*s.split("|")) for s in rows[0][0])
        before = flows(self.g, include_unknown=False)
        result = apply_repair(self.db, self.g, acts)
        rid = record(self.g, before, acts, result.ok)
        self.g.query(
            "MATCH (p:Proposal {id: $id}), (r:Remediation {id: $rid}) SET p.status = 'applied' MERGE (p)-[:BECAME]->(r)",
            {"id": proposal_id, "rid": rid},
        )
        return {"remediation": rid, "verified": result.ok, "flows_left": len(result.remaining), "broken_tasks": result.broken}
