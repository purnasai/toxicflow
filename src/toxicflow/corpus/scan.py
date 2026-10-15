"""Load every crawled project into its own FalkorDB graph and summarise it.

    uv run python -m toxicflow.corpus.scan            # all projects -> data/corpus/results.jsonl
    uv run python -m toxicflow.corpus.scan --keep 20  # also keep 20 graphs for browsing

Per project and per view of the main thread ("configured" / "orchestrator") we record:
agents, capabilities, how many agents are toxic on their own, whether a toxic flow exists,
whether it is hidden (no single agent toxic), the meeting agents, and the UNKNOWN variant.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter

from falkordb import FalkorDB, Graph

from ..analyze import summarize
from ..graph import connect, rebuild_derived
from ..labels import CAPABILITIES, DATA
from .model import ProjectModel, Resolver, build, load_llm_labels

CORPUS = DATA / "corpus"
RAW = CORPUS / "raw"
RESULTS = CORPUS / "results.jsonl"


def load_model(db: FalkorDB, pm: ProjectModel, graph_name: str) -> Graph:
    if graph_name in db.list_graphs():
        db.select_graph(graph_name).delete()
    g = db.select_graph(graph_name)
    g.query("UNWIND $caps AS c CREATE (:Capability {name: c})", {"caps": CAPABILITIES})
    g.query(
        """
        UNWIND $rows AS r
        CREATE (t:Tool {id: r.id, server: r.server, name: r.name, source: r.source})
        WITH t, r UNWIND r.caps AS cap
        MATCH (c:Capability {name: cap})
        CREATE (t)-[:HAS_CAP]->(c)
        """,
        {"rows": [{"id": t.id, "server": t.server, "name": t.name, "source": t.source, "caps": list(t.caps)} for t in pm.tools.values()]},
    )
    g.query("CREATE INDEX FOR (t:Tool) ON (t.id)")
    g.query(
        "UNWIND $rows AS r CREATE (:Agent {id: r.id, purpose: r.purpose, inherits: r.inherits})",
        {"rows": [{"id": a, "purpose": d["purpose"], "inherits": d["inherits"]} for a, d in pm.agents.items()]},
    )
    g.query("CREATE INDEX FOR (a:Agent) ON (a.id)")
    g.query(
        """
        UNWIND $rows AS r
        MATCH (a:Agent {id: r.agent}), (t:Tool {id: r.tool})
        CREATE (a)-[:CAN_CALL {instance: 'default'}]->(t)
        """,
        {"rows": [{"agent": a, "tool": t} for a, d in pm.agents.items() for t in d["tools"]]},
    )
    g.query(
        """
        UNWIND $rows AS r
        MATCH (p:Agent {id: r.p}), (c:Agent {id: r.c})
        CREATE (p)-[:DELEGATES_TO {returns: 'text'}]->(c)
        """,
        {"rows": [{"p": p, "c": c} for p, c in pm.delegations]},
    )
    rebuild_derived(g)
    return g


def project_stats(pm: ProjectModel, g: Graph) -> dict:
    strict = summarize(g)
    loose = summarize(g, include_unknown=True, max_triples=1)
    subs = [a for a in pm.agents if a != "main"]
    tool_sources = Counter(pm.tools[t].source for d in pm.agents.values() for t in d["tools"])
    caps_of = {a: {c for t in d["tools"] for c in pm.tools[t].caps} for a, d in pm.agents.items()}
    return {
        "toxic": strict.toxic,
        "hidden": strict.hidden,
        "toxic_alone": len(strict.toxic_alone),
        "toxic_alone_subagents": len([a for a in strict.toxic_alone if a != "main"]),
        "flows": len(strict.triples),
        "meeting_points": strict.meeting_points[:10],
        "meeting_main_only": strict.meeting_points == ["main"],
        "unknown_only": (not strict.toxic) and loose.toxic,
        "subagents_with": {c: sum(c in caps_of[a] for a in subs) for c in ("untrusted_input", "private_read", "exfil_sink", "unknown")},
        "tool_sources": dict(tool_sources),
    }


MODES = [("configured", "curated"), ("configured", "llm"), ("orchestrator", "curated"), ("orchestrator", "llm")]


def scan(keep: int = 0, limit: int | None = None) -> None:
    db = connect()
    resolvers = {"curated": Resolver({}), "llm": Resolver(load_llm_labels())}
    repos = [json.loads(line) for line in (CORPUS / "repos.jsonl").read_text().splitlines()]
    repos = [r for r in repos if r["agent_files"]][:limit]
    kept = 0
    with RESULTS.open("w") as out:
        for i, rec in enumerate(repos, 1):
            d = RAW / rec["repo"].replace("/", "__")
            row = {"repo": rec["repo"]}
            for view, labels in MODES:
                pm = build(d, view, resolvers[labels])
                if len(pm.agents) < 2:
                    row["skipped"] = "no parseable subagents"
                    break
                name = f"corpus_{d.name}_{view}_{labels}"[:120] if kept < keep else "corpus_scratch"
                g = load_model(db, pm, name)
                row[f"{view}/{labels}"] = project_stats(pm, g)
                if name == "corpus_scratch":
                    g.delete()
            else:
                subs = {k: a for k, a in pm.agents.items() if k != "main"}
                row.update(
                    subagents=len(subs),
                    inheriting=sum(a["inherits"] for a in subs.values()),
                    mcp_servers=sorted(set(pm.servers.values())),
                    bash_subagents=sum(any(t.startswith("builtin.Bash") for t in a["tools"]) for a in subs.values()),
                )
                if kept < keep:
                    kept += 1
            out.write(json.dumps(row) + "\n")
            if i % 100 == 0:
                print(f"  scanned {i}/{len(repos)}", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", type=int, default=0)
    ap.add_argument("--limit", type=int)
    a = ap.parse_args()
    scan(a.keep, a.limit)


if __name__ == "__main__":
    main()
