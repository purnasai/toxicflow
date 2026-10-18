"""Flat reference implementation: the same flow, task and repair semantics in plain Python dicts,
with no FalkorDB. It exists for three reasons:

1. as an independent check of the Cypher (written separately, compared in tests and `toxicflow eval`);
2. as an *exact* repair solver: it enumerates every subset of the full intervention space (not only
   the interventions on witness paths that the graph search branches on), so it can certify that the
   graph search's cheapest repair really is the cheapest;
3. as the honest non-graph baseline: the security decision rests on relationship reasoning, which any
   graph library or hand-written BFS can do. FalkorDB is the system of record the agent, the runtime
   gate, the MCP tools and the UI all query and mutate; this module only reads a scenario file.

Semantics mirrored from queries.py / repair.py:
- instruction edges: parent -> child for every delegation; child -> parent when the return channel is
  free text; writer -> reader for agents sharing one store instance (server/instance);
- data edges: all instruction edges, plus child -> parent when the return channel is typed data;
- toxic flow (a1, a2, a3): a1 holds untrusted_input and steers some m over instruction edges, a2 holds
  private_read and its data reaches m over data edges, and m's data reaches a3, which holds exfil_sink;
- a task works if its agent, itself or through up to 4 delegations, can call every needed tool, AND every
  declared `needs_data` pair (producer -> consumer) is still connected by data edges;
- interventions: quarantine (free text -> typed fields: data still flows, instructions do not; cost 1),
  isolate (agent gets its own store instance, cost 2), revoke (drop every tool with a capability, cost 3),
  cut (remove a delegation, cost 4).
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field

from .graph import channel
from .labels import Tool, load_tools

COST = {"quarantine": 1, "isolate": 2, "revoke": 3, "cut": 4}
RISK_CAPS = ("untrusted_input", "private_read", "exfil_sink")


@dataclass
class State:
    tools: dict[str, Tool]
    holds: dict[str, dict[str, str]]  # agent -> {tool_id: instance}
    delegations: dict[tuple[str, str], str]  # (parent, child) -> return channel 'text' | 'data' | 'none'
    tasks: list[tuple[str, str, list[str]]] = field(default_factory=list)
    needs_data: dict[str, list[tuple[str, str]]] = field(default_factory=dict)  # task -> [(producer, consumer)]

    def copy(self) -> "State":
        return State(self.tools, {a: dict(t) for a, t in self.holds.items()}, dict(self.delegations), self.tasks, self.needs_data)


def from_scenario(sc: dict, tools: dict[str, Tool] | None = None) -> State:
    tools = tools or load_tools()
    holds: dict[str, dict[str, str]] = {}
    delegations: dict[tuple[str, str], str] = {}
    for a in sc["agents"]:
        holds[a["id"]] = {}
        for m in a.get("mounts", []):
            names = m.get("tools") or [t.name for t in tools.values() if t.server == m["server"]]
            for n in names:
                holds[a["id"]][f"{m['server']}.{n}"] = m.get("instance", "default")
        for d in a.get("delegates", []):
            delegations[(a["id"], d["to"])] = channel(d)
    tasks = [(t["id"], t["agent"], list(t["needs"])) for t in sc.get("tasks", [])]
    needs = {t["id"]: [tuple(p) for p in t["needs_data"]] for t in sc.get("tasks", []) if t.get("needs_data")}
    return State(tools, holds, delegations, tasks, needs)


def caps_of(st: State, agent: str) -> set[str]:
    return {c for tid in st.holds[agent] for c in st.tools[tid].caps}


def influence(st: State, data: bool = False) -> dict[str, set[str]]:
    """Instruction-carrying edges, or (data=True) data-carrying edges."""
    edges: dict[str, set[str]] = {a: set() for a in st.holds}
    for (p, c), ch in st.delegations.items():
        edges[p].add(c)
        if ch == "text" or (data and ch == "data"):
            edges[c].add(p)
    writers: dict[str, set[str]] = {}
    readers: dict[str, set[str]] = {}
    for a, held in st.holds.items():
        for tid, inst in held.items():
            t = st.tools[tid]
            store = f"{t.server}/{inst}"
            if "store_write" in t.caps:
                writers.setdefault(store, set()).add(a)
            if "store_read" in t.caps:
                readers.setdefault(store, set()).add(a)
    for store, ws in writers.items():
        for w in ws:
            edges[w] |= readers.get(store, set())
    return edges


def _reach(edges: dict[str, set[str]], start: str) -> set[str]:
    seen, todo = {start}, [start]
    while todo:
        for nxt in edges[todo.pop()]:
            if nxt not in seen:
                seen.add(nxt)
                todo.append(nxt)
    return seen


def flows(st: State, include_unknown: bool = False) -> set[tuple[str, str, str]]:
    instr, data = influence(st), influence(st, data=True)
    steer = {a: _reach(instr, a) for a in st.holds}
    carry = {a: _reach(data, a) for a in st.holds}
    caps = {a: caps_of(st, a) for a in st.holds}

    def has(a, cap):
        return cap in caps[a] or (include_unknown and "unknown" in caps[a])

    out = set()
    for a1 in st.holds:
        if not has(a1, "untrusted_input"):
            continue
        for a2 in st.holds:
            if not has(a2, "private_read"):
                continue
            for m in steer[a1] & carry[a2]:
                for a3 in carry[m]:
                    if has(a3, "exfil_sink"):
                        out.add((a1, a2, a3))
    return out


def per_agent_findings(st: State) -> set[str]:
    """Baseline A: agents that hold all three risky capabilities themselves."""
    return {a for a in st.holds if set(RISK_CAPS) <= caps_of(st, a)}


def broken_tasks(st: State) -> dict[str, list[str]]:
    kids: dict[str, set[str]] = {a: set() for a in st.holds}
    for p, c in st.delegations:
        kids[p].add(c)
    out = {}
    for tid, agent, needs in st.tasks:
        reach, frontier = {agent}, {agent}
        for _ in range(4):
            frontier = {k for a in frontier for k in kids[a]} - reach
            reach |= frontier
        missing = sorted(n for n in needs if not any(n in st.holds[a] for a in reach))
        data = influence(st, data=True)
        missing += [f"data {p}>{c}" for p, c in st.needs_data.get(tid, []) if c not in _reach(data, p)]
        if missing:
            out[tid] = missing
    return out


@dataclass(frozen=True, order=True)
class Act:
    kind: str
    a: str
    b: str

    @property
    def cost(self) -> int:
        return COST[self.kind]


def universe(st: State) -> list[Act]:
    """Every intervention the repair model allows on this team (a superset of witness-path candidates)."""
    acts = set()
    for a in st.holds:
        for cap in RISK_CAPS:
            if cap in caps_of(st, a):
                acts.add(Act("revoke", a, cap))
        for tid, inst in st.holds[a].items():
            t = st.tools[tid]
            if {"store_read", "store_write"} & set(t.caps):
                acts.add(Act("isolate", a, f"{t.server}/{inst}"))
    for (p, c), ch in st.delegations.items():
        acts.add(Act("cut", p, c))
        if ch == "text":
            acts.add(Act("quarantine", p, c))
    return sorted(acts, key=lambda x: (x.cost, x))


def apply(st: State, acts) -> State:
    st = st.copy()
    for act in acts:
        if act.kind == "quarantine" and (act.a, act.b) in st.delegations:
            st.delegations[(act.a, act.b)] = "data"
        elif act.kind == "cut":
            st.delegations.pop((act.a, act.b), None)
        elif act.kind == "revoke":
            st.holds[act.a] = {t: i for t, i in st.holds[act.a].items() if act.b not in st.tools[t].caps}
        elif act.kind == "isolate":
            st.holds[act.a] = {
                t: (i + "~" + act.a if f"{st.tools[t].server}/{i}" == act.b else i) for t, i in st.holds[act.a].items()
            }
    return st


def exact_repairs(st: State, max_cost: int = 8, max_actions: int = 5) -> tuple[int | None, list[tuple[Act, ...]], int]:
    """Exhaustive search over the full intervention space.

    Returns (minimum cost or None, every minimum-cost repair, number of subsets evaluated). A repair
    must leave no strict toxic flow and break no task.
    """
    acts = universe(st)
    best, sols, evaluated = None, [], 0
    for n in range(0, max_actions + 1):
        for combo in itertools.combinations(acts, n):
            cost = sum(a.cost for a in combo)
            if cost > max_cost or (best is not None and cost > best):
                continue
            evaluated += 1
            after = apply(st, combo)
            if flows(after) or broken_tasks(after):
                continue
            if best is None or cost < best:
                best, sols = cost, [combo]
            elif cost == best:
                sols.append(combo)
    return best, sorted(sols), evaluated
