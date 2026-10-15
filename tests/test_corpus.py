import json

import pytest

from toxicflow.analyze import summarize
from toxicflow.corpus.model import Resolver, build, parse_frontmatter, split_tools
from toxicflow.corpus.scan import load_model


@pytest.fixture
def project(tmp_path):
    d = tmp_path / "someone__proj"
    d.mkdir()
    (d / "_mcp.json").write_text(json.dumps({"mcpServers": {
        "web": {"command": "uvx", "args": ["mcp-server-fetch"]},
        "chat": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-slack"]},
    }}))
    (d / "researcher.md").write_text("---\nname: researcher\ndescription: finds docs: fast\ntools: mcp__web__fetch\n---\nbody")
    (d / "reader.md").write_text("---\nname: reader\ntools: Read, Grep\n---\n")
    (d / "notifier.md").write_text("---\nname: notifier\ntools: [mcp__chat__slack_post_message]\n---\n")
    (d / "helper.md").write_text("---\nname: helper\ndescription: no tools line\n---\n")
    (d / "gitbot.md").write_text("---\nname: gitbot\ntools: Bash(git:*), Read\n---\n")
    return d


def test_frontmatter_is_lenient():
    assert parse_frontmatter("---\nname: x\ndescription: a: b: c\ntools: Read, Write\n---\n")["tools"] == "Read, Write"
    assert split_tools("Read, Bash(git add:*, git commit:*), mcp__a__b") == ["Read", "Bash(git add:*, git commit:*)", "mcp__a__b"]


def test_resolution(project):
    pm = build(project, "configured", Resolver({}))
    a = pm.agents
    assert pm.servers == {"web": "fetch", "chat": "slack"}
    assert pm.tools["mcp.web.fetch"].caps == ("untrusted_input", "exfil_sink")
    assert pm.tools["mcp.chat.slack_post_message"].source == "curated"
    assert a["reader"]["tools"] == {"builtin.Read", "builtin.Grep"}
    assert a["helper"]["inherits"] and a["helper"]["tools"] == a["main"]["tools"]
    assert "unknown" in pm.tools["builtin.Bash(git:*)"].caps
    assert ("main", "researcher") in pm.delegations


def test_llm_labels_fill_gaps_only():
    r = Resolver({"acme-crm::get_customer": ["private_read"]})
    assert r.mcp_tool("crm", "acme-crm", "get_customer").caps == ("private_read",)
    assert r.mcp_tool("crm", "acme-crm", "other").caps == ("unknown",)
    assert r.mcp_tool("gh", "github", "get_issue").source == "curated"


def test_split_subagents_still_leak_through_the_orchestrator(db, project):
    (project / "helper.md").unlink()  # it inherits every tool, so it would be toxic alone
    pm = build(project, "orchestrator", Resolver({}))
    g = load_model(db, pm, "test_corpus_proj")
    try:
        s = summarize(g)
        assert s.toxic and s.hidden  # no agent holds all three, yet main relays them together
        assert "main" in s.meeting_points
        assert ("researcher", "reader", "notifier") in s.triples
    finally:
        g.delete()


def test_inheriting_subagent_is_toxic_alone(db, project):
    g = load_model(db, build(project, "orchestrator", Resolver({})), "test_corpus_proj2")
    try:
        assert "helper" in summarize(g).toxic_alone
    finally:
        g.delete()
