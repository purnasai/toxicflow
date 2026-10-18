"""Detector, repair and gate against hand-derived ground truth (data/expected.yaml)."""
import uuid

import pytest
import yaml

from toxicflow import reference as R
from toxicflow.analyze import flows, one_hop_findings
from toxicflow.gate import Gate
from toxicflow.labels import DATA
from toxicflow.repair import Action, apply_repair, search

EXPECTED = yaml.safe_load((DATA / "expected.yaml").read_text())["scenarios"]
NAMES = list(EXPECTED)
CASES = [(n, c) for n in NAMES for c in EXPECTED[n].get("runtime", [])]


@pytest.mark.parametrize("name", NAMES)
def test_graph_finds_exactly_the_expected_flows(loaded, name):
    sc, g = loaded(name)
    truth = {tuple(t) for t in EXPECTED[name]["flows"]}
    assert {f.key for f in flows(g, include_unknown=False)} == truth  # no invented, no lost path
    assert R.flows(R.from_scenario(sc)) == truth                      # independent flat reference agrees
    assert sorted(one_hop_findings(g)) == sorted(EXPECTED[name]["per_agent"])


@pytest.mark.parametrize("name", NAMES)
def test_graph_repair_is_the_exact_minimum(db, loaded, name):
    sc, g = loaded(name)
    sols, _ = search(db, g)
    cost, exact, _ = R.exact_repairs(R.from_scenario(sc))
    assert cost == EXPECTED[name]["min_repair_cost"]
    assert (sols[0].cost if sols else None) == cost
    norm = lambda acts: tuple(sorted((a.kind, a.a, a.b) for a in acts))  # noqa: E731
    assert {norm(s.actions) for s in sols if s.cost == cost} == {norm(s) for s in exact}


def test_support_is_invisible_to_per_agent_checks(loaded):
    _, g = loaded("support")
    assert one_hop_findings(g) == []
    keys = {f.key for f in flows(g, include_unknown=False)}
    assert ("web", "records", "notifier") in keys   # meets in the tool-less dispatcher
    assert ("web", "notifier", "notifier") in keys  # through the shared notes store


def test_one_permission_change_removes_the_risk_but_breaks_work(db, loaded):
    """support: revoking the ticket reader's untrusted input closes both routes but breaks triage;
    the selected two-change repair (same cost) closes both routes and keeps every task."""
    sc, g = loaded("support")
    st = R.from_scenario(sc)
    one = R.apply(st, [R.Act("revoke", "web", "untrusted_input")])
    assert R.flows(one) == set() and "triage-ticket" in R.broken_tasks(one)
    best = search(db, g)[0][0]
    assert len(best.actions) == 2 and Action("quarantine", "dispatcher", "web") in best.actions
    result = apply_repair(db, g, best.actions)
    assert result.ok


def test_structured_returns_and_separate_store_remove_the_flow(loaded):
    """support_safe differs from support only in wiring; same agents, tools and tasks."""
    sc, g = loaded("support_safe")
    assert flows(g) == []
    assert R.broken_tasks(R.from_scenario(sc)) == {}


@pytest.mark.parametrize("name,case", CASES, ids=[f"{n}:{c['name'][:40]}" for n, c in CASES])
def test_gate_decisions_match_expected(db, loaded, name, case):
    _, g = loaded(name)
    if case.get("repaired"):
        apply_repair(db, g, search(db, g)[0][0].actions)
    gate = Gate(g, f"t-{uuid.uuid4().hex[:6]}")
    got = []
    for agent, tool, _ in case["steps"]:
        d = gate.check(agent, tool)
        gate.record(agent, tool, d)
        got.append(d.status)
    assert got == [e for _, _, e in case["steps"]]
