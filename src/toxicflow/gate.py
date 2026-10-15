"""Runtime gate. Every tool call in a session is recorded in the graph as a Call node.
Before a call to an outbound (exfil_sink) tool, the gate asks the graph whether, earlier in
this session, untrusted input was read by some agent x, private data was then read by some
agent y, and x can influence y and y can influence the calling agent. If so the call is
blocked and the path is returned as the reason.

The static analysis says what *could* happen; the gate stops what *is* happening, using
the same influence edges. After a repair, the gate's answer changes with the graph.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml
from falkordb import Graph

from .labels import DATA
from .queries import INFLUENCE, MAX_HOPS

ENSURE_SESSION = "MERGE (s:Session {id: $sid}) ON CREATE SET s.started = $at"

NEXT_SEQ = "MATCH (s:Session {id: $sid}) OPTIONAL MATCH (s)-[:HAS_CALL]->(c:Call) RETURN coalesce(max(c.seq), 0) + 1"

RECORD_CALL = """
MATCH (s:Session {id: $sid}), (a:Agent {id: $agent}), (t:Tool {id: $tool})
CREATE (s)-[:HAS_CALL]->(c:Call {seq: $seq, at: $at, decision: $decision, reason: $reason, args: $args})
CREATE (c)-[:BY]->(a)
CREATE (c)-[:OF]->(t)
"""

TOOL_CAPS = "MATCH (t:Tool {id: $tool})-[:HAS_CAP]->(c:Capability) RETURN collect(c.name)"

CAN_CALL = "MATCH (:Agent {id: $agent})-[r:CAN_CALL]->(:Tool {id: $tool}) RETURN count(r)"

# Earlier in this session: an allowed untrusted read by x and an allowed private read by y,
# in either order (data already in context when injected instructions arrive can still be
# sent), with x ~> y ~> calling agent on the current influence edges.
TAINT_PATH = f"""
MATCH (s:Session {{id: $sid}})-[:HAS_CALL]->(c1:Call {{decision: 'allow'}})-[:OF]->(ut:Tool)-[:HAS_CAP]->(:Capability {{name: 'untrusted_input'}})
MATCH (c1)-[:BY]->(x:Agent)
MATCH (s)-[:HAS_CALL]->(c2:Call {{decision: 'allow'}})-[:OF]->(rt:Tool)-[:HAS_CAP]->(:Capability {{name: 'private_read'}})
MATCH (c2)-[:BY]->(y:Agent)
MATCH p1 = (x)-[:{INFLUENCE}*0..{MAX_HOPS}]->(y)
MATCH p2 = (y)-[:{INFLUENCE}*0..{MAX_HOPS}]->(a:Agent {{id: $agent}})
RETURN c1.seq, ut.id, x.id, c2.seq, rt.id, y.id,
       [n IN nodes(p1) | n.id] + tail([n IN nodes(p2) | n.id]) AS path
ORDER BY length(p1) + length(p2), c2.seq DESC
LIMIT 1
"""

# Was this private read steered by earlier untrusted input? (flagged, not blocked)
UNTRUSTED_UPSTREAM = f"""
MATCH (s:Session {{id: $sid}})-[:HAS_CALL]->(c1:Call {{decision: 'allow'}})-[:OF]->(ut:Tool)-[:HAS_CAP]->(:Capability {{name: 'untrusted_input'}})
MATCH (c1)-[:BY]->(x:Agent)
MATCH p = (x)-[:{INFLUENCE}*0..{MAX_HOPS}]->(:Agent {{id: $agent}})
RETURN c1.seq, ut.id, [n IN nodes(p) | n.id] ORDER BY length(p) LIMIT 1
"""


@dataclass
class Decision:
    decision: str  # allow | block
    status: str  # ALLOW | ALLOW_TAINTED | BLOCK | BLOCK_UNKNOWN | DENY_NOT_MOUNTED
    reason: str
    path: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"


class Gate:
    def __init__(self, g: Graph, session: str):
        self.g, self.session = g, session
        self.g.query(ENSURE_SESSION, {"sid": session, "at": _now()})

    def check(self, agent: str, tool: str) -> Decision:
        if not self.g.ro_query(CAN_CALL, {"agent": agent, "tool": tool}).result_set[0][0]:
            return Decision("block", "DENY_NOT_MOUNTED", f"{agent} is not configured to call {tool}")
        caps = set(self.g.ro_query(TOOL_CAPS, {"tool": tool}).result_set[0][0])
        if caps & {"exfil_sink", "unknown"}:
            row = self.g.ro_query(TAINT_PATH, {"sid": self.session, "agent": agent}).result_set
            if row:
                s1, ut, x, s2, rt, y, path = row[0]
                status = "BLOCK" if "exfil_sink" in caps else "BLOCK_UNKNOWN"
                reason = (
                    f"call #{s1} {x} read untrusted input ({ut}); call #{s2} {y} read private data ({rt}); "
                    f"{tool} would send it out from {agent}"
                )
                if status == "BLOCK_UNKNOWN":
                    reason += " — tool is unlabelled, failing closed"
                return Decision("block", status, reason, path)
        if "private_read" in caps:
            row = self.g.ro_query(UNTRUSTED_UPSTREAM, {"sid": self.session, "agent": agent}).result_set
            if row:
                s1, ut, path = row[0]
                return Decision("allow", "ALLOW_TAINTED", f"private read under untrusted influence from call #{s1} ({ut})", path)
        return Decision("allow", "ALLOW", "no toxic flow completed")

    def record(self, agent: str, tool: str, d: Decision, args: dict | None = None) -> int:
        seq = self.g.ro_query(NEXT_SEQ, {"sid": self.session}).result_set[0][0]
        self.g.query(
            RECORD_CALL,
            {
                "sid": self.session,
                "agent": agent,
                "tool": tool,
                "seq": seq,
                "at": _now(),
                "decision": d.decision,
                "reason": d.reason,
                "args": json.dumps(args or {})[:500],
            },
        )
        return seq


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


# ------------------------------------------------------------------ backends


class FixtureBackend:
    """Canned responses for servers that would need real credentials (GitHub, Slack, fetch)."""

    def __init__(self, path: Path):
        self.responses = yaml.safe_load(path.read_text()).get("responses", {}) if path.is_file() else {}

    def handles(self, tool: str) -> bool:
        return tool in self.responses

    async def call(self, tool: str, args: dict) -> str:
        return str(self.responses[tool]).format(**{k: v for k, v in args.items() if isinstance(v, (str, int, float))})


def fixture_path(scenario: str) -> Path:
    return DATA / "fixtures" / f"{scenario}.yaml"
