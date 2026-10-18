"""Approval re-validates against the graph's current state and never records an unsafe change as applied."""
from toxicflow.service import ToxicFlowService


def calls(svc):
    return svc.g.ro_query("MATCH (:Agent)-[c:CAN_CALL]->() RETURN count(c)").result_set[0][0]


def test_approve_applies_a_still_valid_proposal(db):
    svc = ToxicFlowService("github_solo", db=db, reload=True, graph_name="test_approve_ok")
    try:
        p = svc.propose_repair([{"kind": "revoke", "a": "maintainer", "b": "private_read"}], "test")
        out = svc.approve(p["proposal"])
        assert out["applied"] and out["flows_left"] == 0
        assert svc.g.ro_query("MATCH (r:Remediation) RETURN count(r)").result_set[0][0] == 1
    finally:
        svc.g.delete()


def test_approve_rejects_a_proposal_the_graph_has_outgrown(db):
    """Between proposal and approval a new task starts needing a private tool; applying the revoke would
    now break it. Approval must refuse, change nothing, and record no remediation."""
    svc = ToxicFlowService("github_solo", db=db, reload=True, graph_name="test_approve_stale")
    try:
        p = svc.propose_repair([{"kind": "revoke", "a": "maintainer", "b": "private_read"}], "test")
        svc.g.query("""MATCH (a:Agent {id:'maintainer'}), (t:Tool {id:'github.get_file_contents'})
                       CREATE (k:Task {id:'audit'})-[:ASSIGNED_TO]->(a) CREATE (k)-[:NEEDS]->(t)""")
        before = calls(svc)
        out = svc.approve(p["proposal"])
        assert not out["applied"] and "audit" in out["broken_tasks"]
        assert calls(svc) == before
        assert svc.g.ro_query("MATCH (r:Remediation) RETURN count(r)").result_set[0][0] == 0
        status = svc.g.ro_query("MATCH (p:Proposal {id: $id}) RETURN p.status", {"id": p["proposal"]}).result_set[0][0]
        assert status == "rejected"
        assert not [n for n in db.list_graphs() if n.endswith("__backup") or "__sim_" in n]
    finally:
        svc.g.delete()
