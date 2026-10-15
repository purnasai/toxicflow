"""Reference implementation of the flow semantics in plain Python (untrusted and private
meet in some agent m that reaches a sink), written separately
from the Cypher so the two can check each other. Works on the scenario dict + labels only."""

from __future__ import annotations

from toxicflow.labels import load_tools


def influence_edges(scenario: dict, tools) -> dict[str, set[str]]:
    edges: dict[str, set[str]] = {a["id"]: set() for a in scenario["agents"]}
    writers, readers = {}, {}
    for a in scenario["agents"]:
        for d in a.get("delegates", []):
            edges[a["id"]].add(d["to"])
            if d.get("returns", "text") == "text":
                edges[d["to"]].add(a["id"])
        for m in a.get("mounts", []):
            store = f"{m['server']}/{m.get('instance', 'default')}"
            for name in m.get("tools") or [t.name for t in tools.values() if t.server == m["server"]]:
                caps = tools[f"{m['server']}.{name}"].caps
                if "store_write" in caps:
                    writers.setdefault(store, set()).add(a["id"])
                if "store_read" in caps:
                    readers.setdefault(store, set()).add(a["id"])
    for store, ws in writers.items():
        for w in ws:
            edges[w] |= readers.get(store, set())
    return edges


def reach(edges: dict[str, set[str]], start: str) -> set[str]:
    seen, todo = {start}, [start]
    while todo:
        for nxt in edges[todo.pop()]:
            if nxt not in seen:
                seen.add(nxt)
                todo.append(nxt)
    return seen


def agent_caps(scenario: dict, tools) -> dict[str, set[str]]:
    out = {}
    for a in scenario["agents"]:
        caps: set[str] = set()
        for m in a.get("mounts", []):
            for name in m.get("tools") or [t.name for t in tools.values() if t.server == m["server"]]:
                caps |= set(tools[f"{m['server']}.{name}"].caps)
        out[a["id"]] = caps
    return out


def toxic_triples(scenario: dict, include_unknown: bool = False) -> set[tuple[str, str, str]]:
    tools = load_tools()
    edges = influence_edges(scenario, tools)
    caps = agent_caps(scenario, tools)

    def has(agent, cap):
        return cap in caps[agent] or (include_unknown and "unknown" in caps[agent])

    out = set()
    for a1 in caps:
        if not has(a1, "untrusted_input"):
            continue
        for a2 in caps:
            if not has(a2, "private_read"):
                continue
            for m in reach(edges, a1) & reach(edges, a2):
                for a3 in reach(edges, m):
                    if has(a3, "exfil_sink"):
                        out.add((a1, a2, a3))
    return out
