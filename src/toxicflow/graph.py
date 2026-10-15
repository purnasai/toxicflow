"""FalkorDB connection and scenario loading."""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from falkordb import FalkorDB, Graph

from . import queries as Q
from .config import load_env
from .labels import CAPABILITIES, DATA, load_tools


def connect() -> FalkorDB:
    load_env()
    return FalkorDB(host=os.getenv("FALKORDB_HOST", "localhost"), port=int(os.getenv("FALKORDB_PORT", "6390")))


def load_scenario_file(name: str) -> dict:
    return yaml.safe_load((DATA / "scenarios" / f"{name}.yaml").read_text())


def rebuild_derived(g: Graph) -> None:
    for q in (Q.CLEAR_DERIVED, Q.DROP_STORES, Q.REBUILD_DELEGATION, Q.REBUILD_STORE_WRITES, Q.REBUILD_STORE_READS, Q.REBUILD_INFLUENCES):
        g.query(q)


def load(db: FalkorDB, scenario: dict, graph_name: str | None = None) -> Graph:
    """(Re)create the graph for a scenario from harvested tools + labels."""
    tools = load_tools()
    name = graph_name or f"toxicflow_{scenario['name']}"
    if name in db.list_graphs():
        db.select_graph(name).delete()
    g = db.select_graph(name)

    g.query("UNWIND $caps AS c CREATE (:Capability {name: c})", {"caps": CAPABILITIES})
    g.query("CREATE INDEX FOR (t:Tool) ON (t.id)")
    g.query("CREATE INDEX FOR (a:Agent) ON (a.id)")

    servers = sorted({t.server for t in tools.values()})
    g.query("UNWIND $s AS s CREATE (:Server {id: s})", {"s": servers})
    rows = [
        {"id": t.id, "server": t.server, "name": t.name, "description": t.description, "caps": list(t.caps), "why": t.why}
        for t in tools.values()
    ]
    g.query(
        """
        UNWIND $rows AS r
        MATCH (s:Server {id: r.server})
        CREATE (s)-[:EXPOSES]->(t:Tool {id: r.id, server: r.server, name: r.name, description: r.description})
        WITH t, r UNWIND r.caps AS cap
        MATCH (c:Capability {name: cap})
        CREATE (t)-[:HAS_CAP {why: r.why}]->(c)
        """,
        {"rows": rows},
    )

    for agent in scenario["agents"]:
        g.query("CREATE (:Agent {id: $id, purpose: $purpose})", {"id": agent["id"], "purpose": agent["purpose"]})
        for m in agent.get("mounts", []):
            server = m["server"]
            if server not in servers:
                raise ValueError(f"agent {agent['id']}: server {server!r} was not harvested")
            names = m.get("tools") or [t.name for t in tools.values() if t.server == server]
            missing = [n for n in names if f"{server}.{n}" not in tools]
            if missing:
                raise ValueError(f"agent {agent['id']}: {server} has no tools {missing}")
            g.query(
                """
                MATCH (a:Agent {id: $agent})
                UNWIND $ids AS tid
                MATCH (t:Tool {id: tid})
                CREATE (a)-[:CAN_CALL {instance: $instance}]->(t)
                """,
                {"agent": agent["id"], "ids": [f"{server}.{n}" for n in names], "instance": m.get("instance", "default")},
            )
    for agent in scenario["agents"]:
        for d in agent.get("delegates", []):
            g.query(
                """
                MATCH (p:Agent {id: $p}), (c:Agent {id: $c})
                CREATE (p)-[:DELEGATES_TO {returns: $returns}]->(c)
                """,
                {"p": agent["id"], "c": d["to"], "returns": d.get("returns", "text")},
            )

    for task in scenario.get("tasks", []):
        unknown = [t for t in task["needs"] if t not in tools]
        if unknown:
            raise ValueError(f"task {task['id']}: unknown tools {unknown}")
        g.query(
            """
            MATCH (a:Agent {id: $agent})
            CREATE (k:Task {id: $id})-[:ASSIGNED_TO]->(a)
            WITH k UNWIND $needs AS tid
            MATCH (t:Tool {id: tid})
            CREATE (k)-[:NEEDS]->(t)
            """,
            {"id": task["id"], "agent": task["agent"], "needs": task["needs"]},
        )

    rebuild_derived(g)
    return g
