"""Aggregate corpus results into data/corpus/summary.json (no repository names).

    uv run python -m toxicflow.corpus.aggregate
"""

from __future__ import annotations

import json
import statistics
from collections import Counter

from ..labels import DATA
from .scan import MODES, RESULTS

SUMMARY = DATA / "corpus" / "summary.json"


def pct(n: int, d: int) -> float:
    return round(100 * n / d, 1) if d else 0.0


def aggregate() -> dict:
    rows = [json.loads(line) for line in RESULTS.read_text().splitlines()]
    ok = [r for r in rows if "skipped" not in r]
    n = len(ok)
    subs = [r["subagents"] for r in ok]
    servers = Counter(s for r in ok for s in r["mcp_servers"])
    out = {
        "projects_scanned": n,
        "projects_skipped": len(rows) - n,
        "subagents": {"total": sum(subs), "median": statistics.median(subs) if subs else 0, "max": max(subs, default=0)},
        "projects_with_inheriting_subagent_pct": pct(sum(r["inheriting"] > 0 for r in ok), n),
        "projects_with_bash_subagent_pct": pct(sum(r["bash_subagents"] > 0 for r in ok), n),
        "projects_with_mcp_pct": pct(sum(bool(r["mcp_servers"]) for r in ok), n),
        "top_mcp_servers": servers.most_common(15),
        "modes": {},
    }
    for view, labels in MODES:
        key = f"{view}/{labels}"
        st = [r[key] for r in ok]
        toxic = [s for s in st if s["toxic"]]
        no_sub_alone = [s for s in st if s["toxic_alone_subagents"] == 0]
        out["modes"][key] = {
            "toxic_pct": pct(len(toxic), n),
            "hidden_pct": pct(sum(s["hidden"] for s in st), n),
            "hidden_share_of_toxic_pct": pct(sum(s["hidden"] for s in st), len(toxic)),
            "unknown_only_pct": pct(sum(s["unknown_only"] for s in st), n),
            "some_subagent_toxic_alone_pct": pct(sum(s["toxic_alone_subagents"] > 0 for s in st), n),
            "no_subagent_toxic_alone_but_toxic_pct": pct(sum(s["toxic"] for s in no_sub_alone), len(no_sub_alone)),
            "projects_with_no_subagent_toxic_alone": len(no_sub_alone),
            "median_flows_when_toxic": statistics.median([s["flows"] for s in toxic]) if toxic else 0,
        }
    SUMMARY.write_text(json.dumps(out, indent=2))
    return out


if __name__ == "__main__":
    print(json.dumps(aggregate(), indent=2))


def counterfactual(labels: str = "curated") -> dict:
    """Compare each project before and after the obvious fix (shell without network),
    orchestrator view, so the main thread's own default tools do not dominate."""
    key = f"orchestrator/{labels}"
    load = lambda p: {r["repo"]: r for r in map(json.loads, p.read_text().splitlines()) if "skipped" not in r}  # noqa: E731
    before = load(RESULTS)
    after = load(RESULTS.with_name("results_bash_local.jsonl"))
    common = sorted(set(before) & set(after))
    b = [before[r][key] for r in common]
    a = [after[r][key] for r in common]
    n = len(common)
    still = [x for x in a if x["toxic"]]
    was = sum(x["toxic"] for x in b)
    return {
        "projects": n,
        "toxic_before_pct": pct(was, n),
        "toxic_after_pct": pct(len(still), n),
        "fixed_by_restricting_shell_pct_of_toxic": pct(sum(x["toxic"] and not y["toxic"] for x, y in zip(b, a)), was),
        "still_toxic_hidden_pct": pct(sum(x["hidden"] for x in still), len(still)),
        "still_toxic_with_single_agent_toxic_pct": pct(sum(x["toxic_alone_subagents"] > 0 for x in still), len(still)),
        "still_toxic_meeting_only_in_main_pct": pct(sum(x["meeting_main_only"] for x in still), len(still)),
        "hidden_after_count": sum(x["hidden"] for x in a),
        "unknown_only_after_pct": pct(sum(x["unknown_only"] for x in a), n),
    }
