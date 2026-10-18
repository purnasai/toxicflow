"""Graph-level `isolate` must be real isolation in the gate proxy: each store instance gets its own
memory-server process and storage file. Runs the real @modelcontextprotocol/server-memory via npx."""
import shutil

import anyio
import pytest

from toxicflow.gate_proxy import Backends, instance_of, seed_sandbox
from toxicflow.repair import Action, apply_repair

pytestmark = pytest.mark.skipif(shutil.which("npx") is None, reason="needs npx for the real memory MCP server")


def test_isolated_instances_do_not_share_storage(db, loaded):
    _, g = loaded("acme")
    apply_repair(db, g, (Action("isolate", "coder", "memory/team-kb"),))
    writer = instance_of(g, "coder", "memory.create_entities")
    reader = instance_of(g, "standup", "memory.read_graph")
    assert writer == "team-kb~coder" and reader == "team-kb"
    seed_sandbox()

    async def run():
        async with Backends("acme") as b:
            await b.start([("memory.create_entities", writer), ("memory.read_graph", reader)])
            secret = "demo_live_4f9a2c-NOT-A-REAL-KEY"
            await b.call("memory.create_entities",
                         {"entities": [{"name": "bug-42", "entityType": "note", "observations": [secret]}]}, writer)
            same, _ = await b.call("memory.read_graph", {}, writer)
            other, _ = await b.call("memory.read_graph", {}, reader)
            return secret, same, other

    secret, same, other = anyio.run(run)
    assert secret in same        # the writer's own instance holds the note
    assert secret not in other   # standup's instance (the old shared one) does not
