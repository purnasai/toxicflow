"""Findings and remediations are written back into the graph as nodes, so a later
session can recall what was found, what was changed, and when."""

from __future__ import annotations

from datetime import datetime, timezone

from falkordb import Graph

from .analyze import Flow
from .repair import Action

RECORD = """
CREATE (r:Remediation {id: $rid, at: $at, actions: $actions, cost: $cost, verified: $verified})
WITH r
UNWIND $findings AS f
MERGE (x:Finding {key: f.key})
  ON CREATE SET x.first_seen = $at
SET x.summary = f.summary, x.hops = f.hops, x.status = 'fixed'
MERGE (r)-[:FIXES]->(x)
WITH x, f
MATCH (e:Agent {id: f.entry}), (d:Agent {id: f.reader}), (o:Agent {id: f.exit})
MERGE (x)-[:ENTERS_AT]->(e)
MERGE (x)-[:READS_AT]->(d)
MERGE (x)-[:EXITS_AT]->(o)
"""

RECALL = """
MATCH (a:Agent {id: $agent})<-[:ENTERS_AT|READS_AT|EXITS_AT]-(x:Finding)
OPTIONAL MATCH (r:Remediation)-[:FIXES]->(x)
RETURN x.summary AS finding, x.status AS status, x.first_seen AS first_seen,
       collect(DISTINCT {at: r.at, actions: r.actions}) AS remediations
ORDER BY first_seen
"""


def record(g: Graph, fixed: list[Flow], actions: tuple[Action, ...], verified: bool) -> str:
    at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    rid = f"rem-{at}"
    g.query(
        RECORD,
        {
            "rid": rid,
            "at": at,
            "actions": [a.describe() for a in actions],
            "cost": sum(a.cost for a in actions),
            "verified": verified,
            "findings": [
                {"key": "|".join(f.key), "summary": f.describe(), "hops": f.hops, "entry": f.entry, "reader": f.reader, "exit": f.exit}
                for f in fixed
            ],
        },
    )
    return rid


def recall(g: Graph, agent: str) -> list[dict]:
    res = g.ro_query(RECALL, {"agent": agent})
    cols = [h[1] for h in res.header]
    return [dict(zip(cols, row)) for row in res.result_set]
