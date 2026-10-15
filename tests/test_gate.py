import uuid

from toxicflow.gate import Gate
from toxicflow.repair import apply_repair, search


def run(g, steps):
    gate = Gate(g, f"t-{uuid.uuid4().hex[:6]}")
    out = []
    for agent, tool in steps:
        d = gate.check(agent, tool)
        gate.record(agent, tool, d)
        out.append(d)
    return out


def test_benign_post_before_private_read_is_allowed(loaded):
    _, g = loaded("acme")
    d = run(g, [("triage", "github.get_issue"), ("triage", "slack.slack_post_message")])
    assert [x.status for x in d] == ["ALLOW", "ALLOW"]


def test_injection_chain_is_blocked_with_path(loaded):
    _, g = loaded("acme")
    d = run(g, [
        ("triage", "github.get_issue"),
        ("coder", "filesystem.read_text_file"),
        ("triage", "slack.slack_post_message"),
        ("researcher", "fetch.fetch"),
    ])
    assert d[1].status == "ALLOW_TAINTED"
    assert d[2].status == "BLOCK" and d[2].path == ["triage", "coder", "triage"]
    assert d[3].status == "BLOCK" and d[3].path[-1] == "researcher"


def test_shared_store_chain_is_blocked(loaded):
    _, g = loaded("acme")
    d = run(g, [
        ("triage", "github.get_issue"),
        ("standup", "memory.read_graph"),
        ("standup", "slack.slack_post_message"),
    ])
    assert d[2].status == "BLOCK"
    assert "memory/team-kb" in d[2].path


def test_order_of_reads_does_not_matter(loaded):
    _, g = loaded("acme")
    d = run(g, [
        ("coder", "filesystem.read_text_file"),
        ("triage", "github.get_issue"),
        ("triage", "slack.slack_post_message"),
    ])
    assert d[2].status == "BLOCK"


def test_blocked_calls_do_not_count_as_reads(loaded):
    _, g = loaded("acme")
    d = run(g, [("triage", "github.get_issue"), ("triage", "filesystem.read_text_file"), ("triage", "slack.slack_post_message")])
    assert d[1].status == "DENY_NOT_MOUNTED"
    assert d[2].status == "ALLOW"


def test_after_repair_the_same_calls_pass(db, loaded):
    _, g = loaded("acme")
    best = search(db, g)[0][0]
    apply_repair(db, g, best.actions)
    d = run(g, [("triage", "github.get_issue"), ("coder", "filesystem.read_text_file"), ("triage", "slack.slack_post_message")])
    assert d[2].status == "ALLOW"


def test_unlabelled_sink_fails_closed(loaded):
    _, g = loaded("unlabelled")
    d = run(g, [
        ("reader", "github.get_issue"),
        ("reader", "filesystem.read_text_file"),
        ("helper", "everything.trigger-long-running-operation"),
    ])
    assert d[2].status == "BLOCK_UNKNOWN"
