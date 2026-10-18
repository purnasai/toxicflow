"""`toxicflow eval`: reproducible ablation over every scenario against hand-derived ground truth
(data/expected.yaml). Writes results/eval.json and results/EVAL.md.

A  per-agent check            agents holding untrusted + private + outbound themselves
B  graph investigation        TOXIC_FLOWS Cypher on FalkorDB (multi-hop over influence edges)
   flat reference             the same semantics in plain Python dicts (toxicflow.reference)
C  graph repair               branch-and-bound on GRAPH.COPY simulations, checked against an
                              exhaustive solver over the full intervention space
D  runtime                    the FalkorDB gate vs. no gate vs. a per-agent gate (blocks an outbound
                              call only if the calling agent itself read untrusted and private data)
"""

from __future__ import annotations

import hashlib
import json
import statistics
import time
import uuid
from pathlib import Path

import yaml

from . import reference as R
from .analyze import flows, one_hop_findings
from .gate import Gate
from .gate_proxy import run_replay
from .graph import connect, load, load_scenario_file
from .labels import DATA, ROOT
from .repair import apply_repair, search

OUT = ROOT / "results"
ALLOWED = {"ALLOW", "ALLOW_TAINTED"}


def _prf(pred: set, truth: set) -> dict:
    tp, fp, fn = len(pred & truth), len(pred - truth), len(truth - pred)
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": round(tp / (tp + fp), 3) if tp + fp else None,
            "recall": round(tp / (tp + fn), 3) if tp + fn else None}


def _ms(fn, n: int = 5) -> float:
    times = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t) * 1000)
    return round(statistics.median(times), 2)


def _per_agent_gate(steps, can_call, caps_of):
    """Non-graph runtime baseline: per-agent memory of what each agent itself has read."""
    seen: dict[str, set[str]] = {}
    out = []
    for agent, tool in steps:
        if tool not in can_call[agent]:
            out.append("DENY_NOT_MOUNTED")
            continue
        caps = caps_of[tool]
        mine = seen.setdefault(agent, set())
        if ("exfil_sink" in caps or "unknown" in caps) and {"untrusted_input", "private_read"} <= mine:
            out.append("BLOCK")
            continue
        out.append("ALLOW")
        mine |= set(caps) & {"untrusted_input", "private_read"}
    return out


def _runtime(db, name: str, sc: dict, cases: list[dict], best_actions) -> dict:
    st = R.from_scenario(sc)
    can_call = {a: set(t) for a, t in st.holds.items()}
    caps_of = {tid: set(t.caps) for tid, t in st.tools.items()}
    policies = {"falkordb_gate": [], "no_gate": [], "per_agent_gate": []}
    detail = []
    for case in cases:
        g = load(db, sc, graph_name=f"eval_rt_{name}_{uuid.uuid4().hex[:6]}")
        try:
            if case.get("repaired"):
                apply_repair(db, g, best_actions)
            gate = Gate(g, f"eval-{uuid.uuid4().hex[:6]}")
            got = []
            for agent, tool, _ in case["steps"]:
                d = gate.check(agent, tool)
                gate.record(agent, tool, d)
                got.append(d.status)
        finally:
            g.delete()
        steps = [(a, t) for a, t, _ in case["steps"]]
        if case.get("repaired"):
            post = apply_repair_flat(st, best_actions)
            can_call_c = {a: set(t) for a, t in post.holds.items()}
        else:
            can_call_c = can_call
        results = {"falkordb_gate": got, "no_gate": ["ALLOW"] * len(steps), "per_agent_gate": _per_agent_gate(steps, can_call_c, caps_of)}
        expected = [e for _, _, e in case["steps"]]
        detail.append({"case": case["name"], "repaired": bool(case.get("repaired")), "expected": expected, **results})
        for pol, res in results.items():
            policies[pol].append((expected, res))
    summary = {}
    for pol, pairs in policies.items():
        c = {"authorized_allowed": 0, "unauthorized_blocked": 0, "unsafe_allowed": 0, "safe_blocked": 0, "exact_status_match": 0, "steps": 0}
        for expected, res in pairs:
            for e, r in zip(expected, res):
                c["steps"] += 1
                c["exact_status_match"] += e == r
                if e in ALLOWED:
                    c["authorized_allowed" if r in ALLOWED else "safe_blocked"] += 1
                else:
                    c["unauthorized_blocked" if r not in ALLOWED else "unsafe_allowed"] += 1
        summary[pol] = c
    return {"policies": summary, "cases": detail}


def apply_repair_flat(st, actions):
    return R.apply(st, [R.Act(a.kind, a.a, a.b) for a in actions])


def evaluate(names: list[str] | None = None) -> dict:
    expected = yaml.safe_load((DATA / "expected.yaml").read_text())["scenarios"]
    names = names or list(expected)
    db = connect()
    t0 = time.perf_counter()
    rows = []
    for name in names:
        exp = expected[name]
        sc = load_scenario_file(name)
        g = load(db, sc, graph_name=f"eval_{name}")
        try:
            truth = {tuple(t) for t in exp["flows"]}
            st = R.from_scenario(sc)
            per_agent = set(one_hop_findings(g))
            a_pred = {(x, x, x) for x in per_agent}
            b_pred = {f.key for f in flows(g, include_unknown=False)}
            unknown = [f.key for f in flows(g) if f.status == "UNKNOWN"]
            ref_pred = R.flows(st)
            old_model = st.copy()  # the pre-fix model: any structured return carries nothing
            old_model.delegations = {k: ("none" if v == "data" else v) for k, v in st.delegations.items()}
            old_pred = R.flows(old_model)
            size = {"nodes": g.ro_query("MATCH (n) RETURN count(n)").result_set[0][0],
                    "edges": g.ro_query("MATCH ()-[e]->() RETURN count(e)").result_set[0][0]}
            lat = {"falkordb_flows_ms": _ms(lambda: flows(g, include_unknown=False)), "flat_reference_ms": _ms(lambda: R.flows(st))}

            t = time.perf_counter()
            sols, rejected = search(db, g)
            search_ms = round((time.perf_counter() - t) * 1000, 1)
            t = time.perf_counter()
            ex_cost, ex_sols, evaluated = R.exact_repairs(st)
            exact_ms = round((time.perf_counter() - t) * 1000, 1)
            g_cost = sols[0].cost if sols else None
            norm = lambda acts: tuple(sorted((a.kind, a.a, a.b) for a in acts))  # noqa: E731
            g_min = sorted({norm(s.actions) for s in sols if s.cost == g_cost}) if sols else []
            e_min = sorted({norm(s) for s in ex_sols})
            repair = {
                "expected_min_cost": exp.get("min_repair_cost"), "graph_search_cost": g_cost, "exact_min_cost": ex_cost,
                "graph_min_solutions": g_min, "exact_min_solutions": e_min,
                "agrees_with_exact": g_cost == ex_cost and g_min == e_min,
                "exact_subsets_evaluated": evaluated, "exact_bounds": "all subsets of the full intervention space, <=5 actions, cost <=8",
                "single_fixes_rejected": len(rejected),
                "single_fixes_breaking_tasks": sum(1 for r in rejected if r.broken),
                "single_fixes_leaving_flows": sum(1 for r in rejected if r.remaining and not r.broken),
                "search_ms": search_ms, "exact_ms": exact_ms,
            }
            if exp.get("single_fix_that_breaks_work"):
                k, a, b = exp["single_fix_that_breaks_work"]
                post = R.apply(st, [R.Act(k, a, b)])
                repair["single_fix_check"] = {"fix": [k, a, b], "flows_left": len(R.flows(post)), "broken_tasks": R.broken_tasks(post)}
            best_actions = sols[0].actions if sols else ()
            if sols:
                after = load(db, sc, graph_name=f"eval_after_{name}")
                trial = apply_repair(db, after, best_actions)
                repair["flows_before"], repair["flows_after"] = len(b_pred), len(trial.remaining)
                repair["tasks_total"], repair["tasks_broken_after"] = len(sc.get("tasks", [])), len(trial.broken)
                repair["applied"] = [a.describe() for a in best_actions]
                after.delete()
            row = {
                "scenario": name, "graph": size, "latency": lat,
                "A_per_agent": {**_prf(a_pred, truth), "findings": sorted(per_agent)},
                "B_graph": {**_prf(b_pred, truth), "unknown_flows": len(unknown)},
                "flat_reference": {**_prf(ref_pred, truth), "identical_to_graph": ref_pred == b_pred},
                "old_model_structured_is_safe": _prf(old_pred, truth),
                "graph_only_detections": len((b_pred & truth) - a_pred),
                "C_repair": repair,
            }
            if exp.get("runtime"):
                row["D_runtime"] = _runtime(db, name, sc, exp["runtime"], best_actions)
            attacks = [a.stem for a in sorted((DATA / "attacks").glob("*.yaml")) if yaml.safe_load(a.read_text()).get("scenario") == name]
            for attack in attacks:  # scripted session through the real MCP gate proxy path
                row.setdefault("D_replay", {})[attack] = {
                    mode: {k: (len(v) if k == "leaked_via" else v) for k, v in run_replay(name, attack, mode, graph_name=f"eval_replay_{name}").items()
                           if k in ("leaked_via", "blocked", "unreachable")}
                    for mode in ("nogate", "gate", "after")
                }
            rows.append(row)
        finally:
            g.delete()
    total = {
        "scenarios": len(rows),
        "expected_flows": sum(r["B_graph"]["tp"] + r["B_graph"]["fn"] for r in rows),
        "A_tp": sum(r["A_per_agent"]["tp"] for r in rows), "A_fp": sum(r["A_per_agent"]["fp"] for r in rows),
        "A_fn": sum(r["A_per_agent"]["fn"] for r in rows),
        "B_tp": sum(r["B_graph"]["tp"] for r in rows), "B_fp": sum(r["B_graph"]["fp"] for r in rows),
        "B_fn": sum(r["B_graph"]["fn"] for r in rows),
        "graph_only_detections": sum(r["graph_only_detections"] for r in rows),
        "flat_reference_identical": all(r["flat_reference"]["identical_to_graph"] for r in rows),
        "repairs_agree_with_exact": sum(r["C_repair"]["agrees_with_exact"] for r in rows),
        "seconds": round(time.perf_counter() - t0, 1),
    }
    rt = {}
    for r in rows:
        for pol, c in r.get("D_runtime", {}).get("policies", {}).items():
            agg = rt.setdefault(pol, {k: 0 for k in c})
            for k, v in c.items():
                agg[k] += v
    total["D_runtime"] = rt
    stable = {k: v for k, v in total.items() if k != "seconds"}
    total["fingerprint"] = hashlib.sha256(json.dumps([stable] + [
        {k: v for k, v in r.items() if k not in ("latency",)} | {"C_repair": {k: v for k, v in r["C_repair"].items() if not k.endswith("_ms")}}
        for r in rows], sort_keys=True, default=str).encode()).hexdigest()[:16]
    return {"total": total, "scenarios": rows}


def markdown(res: dict) -> str:
    t = res["total"]
    lines = ["# ToxicFlow evaluation", "", f"Generated by `toxicflow eval` · fingerprint `{t['fingerprint']}` · {t['seconds']} s", "",
             "## Detection (ground truth: data/expected.yaml)", "",
             "| Scenario | Expected flows | A per-agent TP/FP/FN | B graph TP/FP/FN | Old model (structured = safe) TP/FN | Graph-only | Flat ref = graph | FalkorDB ms | Flat ms |",
             "|---|---|---|---|---|---|---|---|---|"]
    for r in res["scenarios"]:
        a, b = r["A_per_agent"], r["B_graph"]
        o = r["old_model_structured_is_safe"]
        lines.append(f"| {r['scenario']} | {b['tp'] + b['fn']} | {a['tp']}/{a['fp']}/{a['fn']} | {b['tp']}/{b['fp']}/{b['fn']}"
                     f"{' (+' + str(b['unknown_flows']) + ' unknown)' if b['unknown_flows'] else ''} | {o['tp']}/{o['fn']} | {r['graph_only_detections']} | "
                     f"{'yes' if r['flat_reference']['identical_to_graph'] else 'NO'} | {r['latency']['falkordb_flows_ms']} | {r['latency']['flat_reference_ms']} |")
    lines += ["", f"Totals: A {t['A_tp']} TP / {t['A_fp']} FP / {t['A_fn']} FN · B {t['B_tp']} TP / {t['B_fp']} FP / {t['B_fn']} FN · "
              f"graph-only detections {t['graph_only_detections']} of {t['expected_flows']}", "",
              "## Repair (tasks must keep their tools AND receive their declared data)", "",
              "`None` = no configuration change removes every flow and keeps every task; the exact solver checked every subset of up to 5 actions with cost up to 8.", "",
              "| Scenario | Expected min cost | Graph search | Exact solver | Same minimum set | Flows before→after | Tasks broken after | Single fixes rejected (break task / leave flows) |",
              "|---|---|---|---|---|---|---|---|"]
    for r in res["scenarios"]:
        c = r["C_repair"]
        lines.append(f"| {r['scenario']} | {c['expected_min_cost']} | {c['graph_search_cost']} | {c['exact_min_cost']} | {'yes' if c['agrees_with_exact'] else 'NO'} | "
                     f"{c.get('flows_before', '-')}→{c.get('flows_after', '-')} | {c.get('tasks_broken_after', '-')}/{c.get('tasks_total', '-')} | "
                     f"{c['single_fixes_rejected']} ({c['single_fixes_breaking_tasks']} / {c['single_fixes_leaving_flows']}) |")
    lines += ["", "## Scripted attack replays (scripted call sequence; filesystem, git and memory MCP servers run for real, GitHub/Slack/fetch/search from fixtures; a leak counts only if the secret really reached the step's input)", "",
              "| Scenario / attack | No gate: leaks | Gate on: leaks / blocked | Cheapest safe repair applied first (none exists → gate only): leaks / impossible steps |", "|---|---|---|---|"]
    for r in res["scenarios"]:
        for attack, m in r.get("D_replay", {}).items():
            lines.append(f"| {r['scenario']} / {attack} | {m['nogate']['leaked_via']} | {m['gate']['leaked_via']} / {m['gate']['blocked']} | "
                         f"{m['after']['leaked_via']} / {m['after']['unreachable']} |")
    lines += ["", "## Runtime (hand-labelled call sequences)", "", "| Policy | Authorized allowed | Unauthorized blocked | Unsafe allowed | Safe blocked | Exact status match |",
              "|---|---|---|---|---|---|"]
    for pol, c in t["D_runtime"].items():
        lines.append(f"| {pol} | {c['authorized_allowed']} | {c['unauthorized_blocked']} | {c['unsafe_allowed']} | {c['safe_blocked']} | {c['exact_status_match']}/{c['steps']} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    res = evaluate()
    OUT.mkdir(exist_ok=True)
    (OUT / "eval.json").write_text(json.dumps(res, indent=1, default=str))
    (OUT / "EVAL.md").write_text(markdown(res))
    print(markdown(res))
    t = res["total"]
    ok = t["B_fp"] == 0 and t["B_fn"] == 0 and t["flat_reference_identical"] and t["repairs_agree_with_exact"] == t["scenarios"] \
        and t["D_runtime"].get("falkordb_gate", {}).get("unsafe_allowed", 1) == 0
    return 0 if ok else 1
