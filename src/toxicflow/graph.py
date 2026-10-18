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
    for q in (Q.CLEAR_DERIVED, Q.DROP_STORES, Q.REBUILD_DELEGATION, Q.REBUILD_DATA_RETURNS, Q.REBUILD_STORE_WRITES,
              Q.REBUILD_STORE_READS, Q.REBUILD_INFLUENCES, Q.REBUILD_CARRIES):
        g.query(q)


TEXT_TYPES = {"string", "text", "markdown"}
DATA_TYPES = {"id", "int", "integer", "number", "float", "date", "url"}
NONE_TYPES = {"enum", "bool", "boolean"}


def channel(delegation: dict) -> str:
    """What a child's result can carry back to its parent: 'text', 'data' or 'none'.

    Free text carries instructions and data. A structured return carries only what its declared field
    types allow; a structured return with no declared fields is treated as free text (unverified claim)."""
    if delegation.get("returns", "text") != "structured":
        return "text"
    fields = delegation.get("fields") or {}
    if not fields:
        return "text"
    types = {str(t).lower() for t in fields.values()}
    unknown = types - TEXT_TYPES - DATA_TYPES - NONE_TYPES
    if unknown:
        raise ValueError(f"unknown field types {sorted(unknown)} in delegation to {delegation['to']}")
    if types & TEXT_TYPES:
        return "text"
    if types & DATA_TYPES:
        return "data"
    return "none"


SCHEMA_VERSION = 2  # 2: typed return channels (RETURNS_DATA) and task data requirements


def is_current(g: Graph) -> bool:
    rows = g.ro_query("MATCH (m:Meta) RETURN m.schema").result_set
    return bool(rows) and rows[0][0] == SCHEMA_VERSION


def open_graph(db: FalkorDB, scenario: str, graph_name: str | None = None, reload: bool = False) -> Graph:
    """The scenario's graph with its current state (approved repairs, sessions), or a fresh load if it is
    missing, if reload is asked for, or if it was built by an older schema (its answers would be wrong)."""
    name = graph_name or f"toxicflow_{scenario}"
    if not reload and name in db.list_graphs():
        g = db.select_graph(name)
        if is_current(g):
            return g
        import sys
        print(f"note: graph {name} was built by an older ToxicFlow schema; reloading from the scenario file", file=sys.stderr)
    return load(db, load_scenario_file(scenario), graph_name=name)


def load(db: FalkorDB, scenario: dict, graph_name: str | None = None) -> Graph:
    """(Re)create the graph for a scenario from harvested tools + labels."""
    tools = load_tools()
    name = graph_name or f"toxicflow_{scenario['name']}"
    if name in db.list_graphs():
        db.select_graph(name).delete()
    g = db.select_graph(name)

    g.query("CREATE (:Meta {schema: $v, scenario: $s})", {"v": SCHEMA_VERSION, "s": scenario["name"]})
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
                CREATE (p)-[:DELEGATES_TO {returns: $returns, channel: $channel}]->(c)
                """,
                {"p": agent["id"], "c": d["to"], "returns": d.get("returns", "text"), "channel": channel(d)},
            )

    for task in scenario.get("tasks", []):
        unknown = [t for t in task["needs"] if t not in tools]
        if unknown:
            raise ValueError(f"task {task['id']}: unknown tools {unknown}")
        g.query(
            """
            MATCH (a:Agent {id: $agent})
            CREATE (k:Task {id: $id, needs_data: $needs_data})-[:ASSIGNED_TO]->(a)
            WITH k UNWIND $needs AS tid
            MATCH (t:Tool {id: tid})
            CREATE (k)-[:NEEDS]->(t)
            """,
            {"id": task["id"], "agent": task["agent"], "needs": task["needs"],
             "needs_data": [f"{a}>{b}" for a, b in task.get("needs_data", [])] or None},
        )

    rebuild_derived(g)
    return g
