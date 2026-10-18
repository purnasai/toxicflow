"""Write the graph's current agent configuration back out as scenario YAML,
so an applied repair produces a concrete config change you can diff and deploy."""

from __future__ import annotations

from collections import defaultdict

import yaml
from falkordb import Graph

from .graph import channel


def export_scenario(g: Graph, original: dict) -> str:
    agents = []
    for agent in original["agents"]:
        rows = g.ro_query(
            """
            MATCH (a:Agent {id: $id})-[c:CAN_CALL]->(t:Tool)
            RETURN t.server, c.instance, collect(t.name) ORDER BY t.server, c.instance
            """,
            {"id": agent["id"]},
        ).result_set
        mounts = []
        for server, instance, names in rows:
            m = {"server": server, "tools": sorted(names)}
            if instance != "default":
                m["instance"] = instance
            mounts.append(m)
        dels = g.ro_query(
            "MATCH (:Agent {id: $id})-[d:DELEGATES_TO]->(c:Agent) RETURN c.id, d.returns, d.channel ORDER BY c.id",
            {"id": agent["id"]},
        ).result_set
        entry = {"id": agent["id"], "purpose": agent["purpose"], "mounts": mounts}
        if dels:
            orig = {d["to"]: d for d in agent.get("delegates", [])}
            entry["delegates"] = []
            for c, r, ch in dels:
                d = {"to": c, "returns": r}
                if r == "structured":
                    keep = orig.get(c, {}).get("fields")
                    # a repair restricted this return to typed fields; the schema itself must be enforced by the deployment
                    same = keep and channel({"to": c, "returns": "structured", "fields": keep}) == ch
                    d["fields"] = keep if same else ({"result_id": "id", "status": "enum"} if ch == "data" else {"status": "enum"})
                entry["delegates"].append(d)
        agents.append(entry)
    out = {k: v for k, v in original.items() if k != "agents"}
    out["agents"] = agents
    return yaml.safe_dump(out, sort_keys=False, width=120)


def mount_diff(before: dict, after: dict) -> list[str]:
    """Human-readable lines for what changed between two scenario dicts."""

    def flat(sc: dict) -> dict[str, set[str]]:
        d: dict[str, set[str]] = defaultdict(set)
        for a in sc["agents"]:
            for m in a.get("mounts", []):
                d[a["id"]].add(f"mount {m['server']}@{m.get('instance', 'default')}")
            for x in a.get("delegates", []):
                d[a["id"]].add(f"delegate {x['to']} returns={x.get('returns', 'text')}")
        return d

    b, a = flat(before), flat(after)
    lines = []
    for agent in sorted(set(b) | set(a)):
        lines += [f"- {agent}: {x}" for x in sorted(b[agent] - a[agent])]
        lines += [f"+ {agent}: {x}" for x in sorted(a[agent] - b[agent])]
    return lines
