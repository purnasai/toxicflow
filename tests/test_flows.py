import pytest
from oracle import toxic_triples

from toxicflow.analyze import broken_tasks, flows, one_hop_findings
from toxicflow.repair import Action, apply_repair, search


SCENARIOS = ["acme", "github_solo", "unlabelled", "analytics", "analytics_structured", "assistant", "support", "support_safe"]


@pytest.mark.parametrize("name", SCENARIOS)
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


def test_acme_has_no_safe_configuration_repair(db, loaded):
    """Coder's output must still reach triage (fix-bug) and standup (standup-notes); untrusted issue text
    reaches coder by delegation. Every single fix fails, and no combination keeps every task."""
    _, g = loaded("acme")
    solutions, rejected = search(db, g)
    assert solutions == []
    assert len(rejected) == 13 and all(t.remaining or t.broken for t in rejected)


def test_repair_that_exists_is_applied_and_verified(db, loaded):
    _, g = loaded("github_solo")
    solutions, _ = search(db, g)
    assert solutions[0].cost == 3
    result = apply_repair(db, g, solutions[0].actions)
    assert result.ok and flows(g, include_unknown=False) == [] and broken_tasks(g) == {}


def test_data_requirement_breaks_store_isolation(db, loaded):
    """Isolating the KB removes the shared-store route but starves standup of coder's notes."""
    _, g = loaded("acme")
    sim = search(db, g)[1]
    iso = next(t for t in sim if t.actions == (Action("isolate", "standup", "memory/team-kb"),))
    assert iso.broken.get("standup-notes") == ["data coder>standup"]


def test_simulation_leaves_base_graph_untouched(db, loaded):
    _, g = loaded("acme")
    before = len(flows(g))
    search(db, g)
    assert len(flows(g)) == before
    assert not [n for n in db.list_graphs() if "__sim_" in n]


def test_private_read_need_not_be_steered(db, loaded):
    """analytics: SQL reads customer data legitimately; it meets injected search results in the analyst.
    Restricting SQL's return to typed fields does not help: typed fields still carry the data."""
    _, g = loaded("analytics")
    assert one_hop_findings(g) == []
    solutions, rejected = search(db, g)
    assert solutions == []
    sql_typed = next(t for t in rejected if t.actions == (Action("quarantine", "analyst", "sql"),))
    assert sql_typed.remaining and not sql_typed.broken


def test_structured_return_still_carries_private_data(loaded):
    """Regression: a structured result with id/number fields is a data channel, not a safe one."""
    _, g = loaded("analytics_structured")
    assert g.ro_query("MATCH (:Agent {id:'sql'})-[:RETURNS_DATA]->(:Agent {id:'analyst'}) RETURN count(*)").result_set[0][0] == 1
    assert g.ro_query("MATCH (:Agent {id:'sql'})-[:REPORTS_TO]->() RETURN count(*)").result_set[0][0] == 0
    assert {f.key for f in flows(g, include_unknown=False)} == {("web", "sql", "analyst"), ("web", "sql", "web")}


def test_no_safe_configuration_is_reported_honestly(db, loaded):
    _, g = loaded("assistant")
    solutions, rejected = search(db, g)
    assert solutions == []
    assert rejected and all(t.broken for t in rejected)


@pytest.mark.parametrize("name", SCENARIOS)
def test_bfs_summary_matches_cypher_flows(loaded, name):
    from toxicflow.analyze import summarize

    _, g = loaded(name)
    assert summarize(g).triples == {f.key for f in flows(g) if f.status == "TOXIC"}
    assert summarize(g, include_unknown=True).triples == {f.key for f in flows(g)}
