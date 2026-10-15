"""Find the cheapest set of interventions that removes every toxic flow
while keeping every declared task working.

Each candidate set is tried on a throwaway copy of the graph (GRAPH.COPY), the derived
influence edges are rebuilt, and the same flow and task queries are re-run. Nothing is
inferred outside the graph: a repair counts only if the graph says the flows are gone.
"""

from __future__ import annotations

import itertools
import uuid
from dataclasses import dataclass

from falkordb import FalkorDB, Graph

from . import queries as Q
from .analyze import Flow, broken_tasks, flows
from .graph import rebuild_derived

# Lower is less disruptive. Quarantine keeps the delegation but only lets structured
# results come back; isolation gives one agent its own copy of a shared store.
COST = {"quarantine": 1, "isolate": 2, "revoke": 3, "cut": 4}


@dataclass(frozen=True, order=True)
class Action:
    kind: str  # quarantine | isolate | revoke | cut
    a: str
    b: str

    @property
    def cost(self) -> int:
        return COST[self.kind]

    def describe(self) -> str:
        return {
            "quarantine": f"make {self.b} return structured results only to {self.a} (no free text)",
            "isolate": f"give {self.a} its own instance of store {self.b}",
            "revoke": f"revoke every '{self.b}' tool from {self.a}",
            "cut": f"remove the delegation {self.a} -> {self.b}",
        }[self.kind]

    def apply(self, g: Graph) -> None:
        if self.kind == "quarantine":
            g.query(Q.QUARANTINE, {"parent": self.a, "child": self.b})
        elif self.kind == "cut":
            g.query(Q.CUT_DELEGATION, {"parent": self.a, "child": self.b})
        elif self.kind == "revoke":
            g.query(Q.REVOKE_CAP, {"agent": self.a, "cap": self.b})
        elif self.kind == "isolate":
            g.query(Q.ISOLATE_STORE, {"agent": self.a, "store": self.b})


def candidates(flow: Flow) -> list[Action]:
    """Every intervention that breaks this flow's witness path."""
    acts = {
        Action("revoke", flow.entry, "untrusted_input"),
        Action("revoke", flow.reader, "private_read"),
        Action("revoke", flow.exit, "exfil_sink"),
    }
    for src, rel, dst in flow.steps():
        if rel == "INSTRUCTS":
            acts.add(Action("cut", src, dst))
        elif rel == "REPORTS_TO":  # child src reports to parent dst
            acts.add(Action("quarantine", dst, src))
            acts.add(Action("cut", dst, src))
        elif rel == "WRITES_TO":
            acts.add(Action("isolate", src, dst))
        elif rel == "FEEDS":
            acts.add(Action("isolate", dst, src))
    return sorted(acts, key=lambda x: (x.cost, x))


@dataclass
class Trial:
    actions: tuple[Action, ...]
    remaining: list[Flow]
    broken: dict[str, list[str]]

    @property
    def cost(self) -> int:
        return sum(a.cost for a in self.actions)

    @property
    def ok(self) -> bool:
        return not self.remaining and not self.broken


class Simulator:
    def __init__(self, db: FalkorDB, base: Graph):
        self.db, self.base = db, base
        self.cache: dict[frozenset[Action], Trial] = {}

    def trial(self, actions: tuple[Action, ...]) -> Trial:
        key = frozenset(actions)
        if key not in self.cache:
            name = f"{self.base.name}__sim_{uuid.uuid4().hex[:8]}"
            self.base.copy(name)
            g = self.db.select_graph(name)
            try:
                for act in actions:
                    act.apply(g)
                rebuild_derived(g)
                self.cache[key] = Trial(tuple(sorted(actions)), flows(g, include_unknown=False), broken_tasks(g))
            finally:
                g.delete()
        return self.cache[key]


def search(db: FalkorDB, base: Graph, max_actions: int = 4) -> tuple[list[Trial], list[Trial]]:
    """Branch on the interventions that break one remaining flow, as in a hitting-set search.

    Returns (solutions sorted by cost, rejected single actions with the reason they failed).
    """
    sim = Simulator(db, base)
    start = sim.trial(())
    solutions: list[Trial] = []
    best = [10**9]

    def dfs(applied: tuple[Action, ...], trial: Trial) -> None:
        if trial.broken:
            return  # interventions only remove capability; a broken task stays broken
        if not trial.remaining:
            solutions.append(trial)
            best[0] = min(best[0], trial.cost)
            return
        if len(applied) >= max_actions:
            return
        for act in candidates(trial.remaining[0]):
            if act in applied or trial.cost + act.cost > best[0]:
                continue
            nxt = tuple(sorted(applied + (act,)))
            dfs(nxt, sim.trial(nxt))

    dfs((), start)
    uniq = {frozenset(s.actions): s for s in solutions}
    ranked = sorted(uniq.values(), key=lambda t: (t.cost, len(t.actions), t.actions))

    first_moves = {a for f in start.remaining for a in candidates(f)}
    rejected = [sim.trial((a,)) for a in sorted(first_moves, key=lambda x: (x.cost, x))]
    return ranked, [t for t in rejected if not t.ok]


def apply_repair(db: FalkorDB, g: Graph, actions: tuple[Action, ...]) -> Trial:
    """Apply to the real graph, rebuild, and verify with the same queries."""
    for act in actions:
        act.apply(g)
    rebuild_derived(g)
    return Trial(actions, flows(g, include_unknown=False), broken_tasks(g))


def all_subsets(cands: list[Action], k: int):
    for n in range(1, k + 1):
        yield from itertools.combinations(cands, n)
