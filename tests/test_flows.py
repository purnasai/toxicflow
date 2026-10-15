import pytest
from oracle import toxic_triples

from toxicflow.analyze import broken_tasks, flows, one_hop_findings
from toxicflow.repair import Action, apply_repair, search


@pytest.mark.parametrize("name", ["acme", "github_solo", "unlabelled"])
def test_graph_matches_reference(loaded, name):
    sc, g = loaded(name)
    strict = {f.key for f in flows(g) if f.status == "TOXIC"}
    assert strict == toxic_triples(sc)
    loose = {f.key for f in flows(g)}
    assert loose == toxic_triples(sc, include_unknown=True)


def test_acme_one_hop_misses_everything_multi_hop_finds(loaded):
    _, g = loaded("acme")
    assert one_hop_findings(g) == []
    assert len(flows(g, include_unknown=False)) == 8


def test_shared_store_path_has_no_delegation_edge(loaded):
    _, g = loaded("acme")
    f = next(f for f in flows(g) if f.key == ("triage", "coder", "standup"))
    assert ("coder", "WRITES_TO", "memory/team-kb") in f.steps()
    assert ("memory/team-kb", "FEEDS", "standup") in f.steps()


def test_github_solo_both_views_agree(loaded):
    _, g = loaded("github_solo")
    assert one_hop_findings(g) == ["maintainer"]
    assert [f.key for f in flows(g)] == [("maintainer", "maintainer", "maintainer")]


def test_unlabelled_tool_is_unknown_not_safe(loaded):
    _, g = loaded("unlabelled")
    found = flows(g)
    assert found and all(f.status == "UNKNOWN" for f in found)
    f = next(f for f in found if f.key == ("reader", "reader", "helper"))
    assert f.via_unknown == ["everything.trigger-long-running-operation"]


def test_cheapest_repair_is_minimal_and_verified(db, loaded):
    _, g = loaded("acme")
    solutions, rejected = search(db, g)
    assert solutions[0].cost == 3
    assert Action("quarantine", "triage", "coder") in solutions[0].actions
    # The obvious single fixes are all rejected, each for a stated reason.
    assert all(t.remaining or t.broken for t in rejected)
    result = apply_repair(db, g, solutions[0].actions)
    assert result.ok
    assert flows(g, include_unknown=False) == [] and broken_tasks(g) == {}


def test_simulation_leaves_base_graph_untouched(db, loaded):
    _, g = loaded("acme")
    before = len(flows(g))
    search(db, g)
    assert len(flows(g)) == before
    assert not [n for n in db.list_graphs() if "__sim_" in n]
