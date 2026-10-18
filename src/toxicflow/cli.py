"""toxicflow command line.

  toxicflow harvest [server ...]     list tools from the MCP servers in data/servers.yaml
  toxicflow scan <scenario>          per-agent view vs multi-hop toxic flows
  toxicflow repair <scenario>        cheapest repair that keeps every task working
  toxicflow repair <scenario> --apply  apply it, verify, record memory, write patched config
  toxicflow recall <scenario> <agent>  past findings and remediations for an agent
  toxicflow mcp <scenario>           run the MCP server (stdio) over the scenario graph
  toxicflow investigate <scenario>   LLM investigator using the MCP tools; ends with a proposal
  toxicflow approve <scenario> <id>  human approval: apply a proposal, verify, record
  toxicflow gate <scenario> <agent> --session S   runtime gate as an MCP proxy (stdio)
  toxicflow replay <scenario> <attack> [--after-repair] [--no-gate]   scripted session through the gate
  toxicflow ui [--port 8790]         web UI
"""

from __future__ import annotations

import argparse
import sys

import yaml
from rich.console import Console
from rich.table import Table

from .analyze import broken_tasks, flows, one_hop
from .export import export_scenario, mount_diff
from .graph import connect, load, load_scenario_file, open_graph
from .labels import DATA
from .memory import recall, record
from .repair import safe_apply, search

console = Console()
TRIAD = ("untrusted_input", "private_read", "exfil_sink")


def cmd_scan(args) -> int:
    db = connect()
    name = f"toxicflow_{args.scenario}"
    g = open_graph(db, args.scenario, reload=args.reload)
    applied = g.ro_query("MATCH (r:Remediation) RETURN count(r)").result_set[0][0]
    console.print(f"[dim]graph {name}: {applied} applied remediation(s); use --reload to start again from the scenario file[/dim]")

    t = Table(title="Per-agent view (what a one-hop scanner sees)")
    for col in ("agent", *TRIAD, "verdict"):
        t.add_column(col)
    for agent, caps in one_hop(g).items():
        marks = ["yes" if c in caps else "-" for c in TRIAD]
        verdict = "[red]TOXIC[/red]" if all(c in caps for c in TRIAD) else "[green]looks safe[/green]"
        t.add_row(agent, *marks, verdict)
    console.print(t)

    found = flows(g)
    toxic = [f for f in found if f.status == "TOXIC"]
    console.print(f"\n[bold]Multi-hop view:[/bold] {len(toxic)} toxic flows, {len(found) - len(toxic)} unknown")
    for f in found:
        colour = "red" if f.status == "TOXIC" else "yellow"
        console.print(f"[{colour}]{f.status}[/{colour}] ({f.hops} hops) {f.describe()}")
        console.print(f"    in : {' -> '.join(f.path_in)}  via {f.rels_in}")
        console.print(f"    out: {' -> '.join(f.path_out)}  via {f.rels_out}")
        console.print(f"    tools: untrusted={f.sources[:3]} private={f.readers[:3]} sink={f.sinks[:3]}")
        if f.via_unknown:
            console.print(f"    depends on unlabelled tools: {f.via_unknown}")
    return 1 if toxic else 0


def cmd_repair(args) -> int:
    db = connect()
    name = f"toxicflow_{args.scenario}"
    scenario = load_scenario_file(args.scenario)
    g = open_graph(db, args.scenario, reload=args.reload)  # keeps approved repairs; the search only uses copies
    before = flows(g, include_unknown=False)
    if not before:
        console.print("[green]No toxic flows.[/green]")
        return 0
    if broken_tasks(g):
        console.print(f"[red]Scenario is broken before any repair:[/red] {broken_tasks(g)}")
        return 2

    solutions, rejected = search(db, g, max_actions=args.max_actions)
    console.print(f"[bold]{len(before)} toxic flows.[/bold] Single interventions that do not work:")
    for t in rejected:
        why = f"breaks tasks {t.broken}" if t.broken else f"{len(t.remaining)} flows remain"
        console.print(f"  [dim]x[/dim] {t.actions[0].describe()}  ->  {why}")
    if not solutions:
        console.print("[red]No repair within the action limit keeps every task working. Needs a human decision.[/red]")
        return 3

    console.print("\n[bold]Repairs that remove every flow and keep every task:[/bold]")
    for i, s in enumerate(solutions[: args.top], 1):
        console.print(f"  {i}. cost {s.cost}: " + "; ".join(a.describe() for a in s.actions))

    if not args.apply:
        return 0
    chosen = solutions[0]
    applied, result, reason = safe_apply(db, g, chosen.actions)
    g = db.select_graph(name)
    if not applied:
        console.print(f"[red]Not applied: {reason}[/red]")
        return 4
    verified = True
    rid = record(g, before, chosen.actions, verified)
    console.print(f"\nApplied repair 1 to graph {g.name}: verified={verified} (flows left {len(result.remaining)}, broken tasks {result.broken})")
    console.print(f"Recorded as {rid}")

    patched = export_scenario(g, scenario)
    out = DATA / "scenarios" / f"{args.scenario}.patched.yaml"
    out.write_text(patched)
    console.print(f"Patched config: {out}")
    for line in mount_diff(scenario, yaml.safe_load(patched)):
        console.print(("[red]" if line.startswith("-") else "[green]") + line)
    return 0 if verified else 4


def cmd_recall(args) -> int:
    db = connect()
    g = db.select_graph(f"toxicflow_{args.scenario}")
    rows = recall(g, args.agent)
    if not rows:
        console.print(f"Nothing recorded for {args.agent}. (Not the same as 'safe': it may never have been scanned.)")
    for r in rows:
        console.print(r)
    return 0


def cmd_approve(args) -> int:
    from .service import ToxicFlowService

    svc = ToxicFlowService(args.scenario)
    rows = svc.g.ro_query(
        "MATCH (p:Proposal {id: $id}) RETURN p.actions, p.rationale, p.status", {"id": args.proposal}
    ).result_set
    if not rows:
        console.print(f"[red]No proposal {args.proposal}[/red]")
        return 2
    actions, rationale, status = rows[0]
    console.print(f"[bold]{args.proposal}[/bold] ({status})\n  actions: {actions}\n  rationale: {rationale}")
    if not args.yes and console.input("Apply? [y/N] ").strip().lower() != "y":
        console.print("Not applied.")
        return 1
    result = svc.approve(args.proposal)
    console.print(result)
    return 0 if result["verified"] else 4


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="toxicflow")
    sub = p.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("harvest")
    h.add_argument("servers", nargs="*")
    s = sub.add_parser("scan")
    s.add_argument("scenario")
    s.add_argument("--reload", action="store_true", help="discard applied repairs and reload from the scenario file")
    r = sub.add_parser("repair")
    r.add_argument("scenario")
    r.add_argument("--apply", action="store_true")
    r.add_argument("--reload", action="store_true", help="discard applied repairs and reload from the scenario file")
    r.add_argument("--max-actions", type=int, default=4)
    r.add_argument("--top", type=int, default=5)
    m = sub.add_parser("recall")
    m.add_argument("scenario")
    m.add_argument("agent")
    mc = sub.add_parser("mcp")
    mc.add_argument("scenario")
    mc.add_argument("--reload", action="store_true")
    inv = sub.add_parser("investigate")
    inv.add_argument("scenario")
    inv.add_argument("--question")
    inv.add_argument("--reload", action="store_true", help="reload the scenario graph first")
    ap = sub.add_parser("approve")
    ap.add_argument("scenario")
    ap.add_argument("proposal")
    ap.add_argument("-y", "--yes", action="store_true")
    gt = sub.add_parser("gate")
    gt.add_argument("scenario")
    gt.add_argument("agent")
    gt.add_argument("--session", required=True)
    rp = sub.add_parser("replay")
    rp.add_argument("scenario")
    rp.add_argument("attack")
    rp.add_argument("--after-repair", action="store_true")
    rp.add_argument("--no-gate", action="store_true", help="baseline: let every call through")
    sub.add_parser("eval", help="ablation vs ground truth; writes results/eval.json and results/EVAL.md")
    ui = sub.add_parser("ui")
    ui.add_argument("--port", type=int, default=8790)
    args = p.parse_args(argv)

    if args.cmd == "eval":
        from .evaluate import main as eval_main

        return eval_main()
    if args.cmd == "ui":
        from .ui import main as ui_main

        ui_main(args.port)
        return 0

    if args.cmd == "gate":
        from .gate_proxy import serve

        serve(args.scenario, args.agent, args.session)
        return 0
    if args.cmd == "replay":
        from .gate_proxy import replay

        return replay(args.scenario, args.attack, args.after_repair, not args.no_gate)

    if args.cmd == "mcp":
        from .mcp_server import main as mcp_main

        mcp_main(args.scenario, args.reload)
        return 0
    if args.cmd == "investigate":
        from .investigator import run
        from .service import ToxicFlowService

        if args.reload:
            ToxicFlowService(args.scenario, reload=True)
        return run(args.scenario, args.question)

    if args.cmd == "harvest":
        from .harvest import main as harvest_main

        harvest_main(args.servers or None)
        return 0
    return {"scan": cmd_scan, "repair": cmd_repair, "recall": cmd_recall, "approve": cmd_approve}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
