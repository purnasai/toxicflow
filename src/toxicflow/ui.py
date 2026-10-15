"""Small web UI: `toxicflow ui` then open http://localhost:8790.

Every endpoint reads from FalkorDB through the same service code as the CLI and MCP server.
The UI uses its own graphs (ui_<scenario>, ui_<scenario>_after, ui_<scenario>_replay) so it
never disturbs graphs the CLI or MCP server are using.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

from .analyze import Flow, flows
from .gate_proxy import run_replay
from .labels import DATA
from .repair import apply_repair, search
from .service import InvalidArgument, ToxicFlowService

STATIC = Path(__file__).parent / "static"
app = FastAPI(title="ToxicFlow")

GRAPH_VIEW = """
MATCH (a:Agent)
OPTIONAL MATCH (a)-[:CAN_CALL]->(:Tool)-[:HAS_CAP]->(c:Capability)
WITH a, collect(DISTINCT c.name) AS caps
RETURN 'agent' AS kind, a.id AS id, a.purpose AS purpose, caps
UNION
MATCH (s:Store) RETURN 'store' AS kind, s.id AS id, '' AS purpose, [] AS caps
"""

EDGES = "MATCH (x)-[e:INSTRUCTS|REPORTS_TO|WRITES_TO|FEEDS]->(y) RETURN x.id, type(e), y.id"


def _scenarios() -> list[dict]:
    out = []
    for f in sorted((DATA / "scenarios").glob("*.yaml")):
        if f.stem.endswith(".patched"):
            continue
        d = yaml.safe_load(f.read_text())
        attacks = [
            a.stem for a in sorted((DATA / "attacks").glob("*.yaml")) if yaml.safe_load(a.read_text()).get("scenario") == d["name"]
        ]
        out.append({"name": d["name"], "description": d.get("description", ""), "attacks": attacks})
    return out


def _svc(name: str, suffix: str = "") -> ToxicFlowService:
    if name not in {s["name"] for s in _scenarios()}:
        raise HTTPException(404, f"unknown scenario {name}")
    return ToxicFlowService(name, reload=True, graph_name=f"ui_{name}{suffix}")


def _graph(svc: ToxicFlowService) -> dict:
    nodes = [
        {"id": i, "kind": kind, "purpose": purpose, "caps": sorted(c for c in caps if c in ("untrusted_input", "private_read", "exfil_sink"))}
        for kind, i, purpose, caps in svc.g.ro_query(GRAPH_VIEW).result_set
    ]
    edges = [{"source": a, "type": t, "target": b} for a, t, b in svc.g.ro_query(EDGES).result_set]
    # A store only one agent touches carries nothing between agents; hide it to keep the picture readable.
    stores = {n["id"] for n in nodes if n["kind"] == "store"}
    touching = {s: {e["source"] if e["target"] == s else e["target"] for e in edges if s in (e["source"], e["target"])} for s in stores}
    private = {s for s, agents in touching.items() if len(agents) < 2}
    nodes = [n for n in nodes if n["id"] not in private]
    edges = [e for e in edges if e["source"] not in private and e["target"] not in private]
    return {"nodes": nodes, "edges": edges}


def _flow(f: Flow) -> dict:
    return {
        "status": f.status,
        "entry": f.entry,
        "reader": f.reader,
        "meet": f.meet,
        "exit": f.exit,
        "hops": f.hops,
        "routes": {"untrusted": f.path_in, "private": f.path_data, "out": f.path_out},
        "steps": [list(s) for s in f.steps()],
        "tools": {"untrusted": f.sources, "private": f.readers, "sink": f.sinks},
        "via_unknown": f.via_unknown,
    }


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/scenarios")
def scenarios():
    return _scenarios()


@app.get("/api/{name}/scan")
def scan(name: str):
    svc = _svc(name)
    return {
        "graph": _graph(svc),
        "one_hop": svc.one_hop_scan(),
        "flows": [_flow(f) for f in flows(svc.g)],
        "tasks": svc.check_tasks(),
    }


@app.get("/api/{name}/repair")
def repair(name: str):
    svc = _svc(name)
    result = svc.search_repairs(max_actions=4, top=5)
    after = None
    solutions, _ = search(svc.db, svc.g)
    if solutions:
        svc2 = _svc(name, "_after")
        trial = apply_repair(svc2.db, svc2.g, solutions[0].actions)
        after = {
            "graph": _graph(svc2),
            "flows_left": [_flow(f) for f in trial.remaining],
            "broken_tasks": trial.broken,
            "actions": [vars(a) for a in solutions[0].actions],
        }
    return {**result, "after": after}


@app.get("/api/{name}/replay")
def replay(name: str, attack: str, mode: str = "gate"):
    if attack not in next((s["attacks"] for s in _scenarios() if s["name"] == name), []):
        raise HTTPException(404, f"no attack {attack} for {name}")
    try:
        return run_replay(name, attack, mode, graph_name=f"ui_{name}_replay")
    except (ValueError, InvalidArgument) as exc:
        raise HTTPException(400, str(exc)) from exc


def main(port: int = 8790) -> None:
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
