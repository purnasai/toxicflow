"""Start each MCP server listed in data/servers.yaml and save the tools it reports.

Output: data/tools/<server_id>.json with the raw tools/list result plus provenance.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import yaml
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
SANDBOX = DATA / "sandbox"
TOOLS_DIR = DATA / "tools"


async def list_tools(spec: dict) -> list[dict]:
    args = [a.replace("{SANDBOX}", str(SANDBOX)) for a in spec.get("args", [])]
    params = StdioServerParameters(
        command=spec["command"],
        args=args,
        env={**os.environ, **spec.get("env", {})},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()
            return [t.model_dump(mode="json", exclude_none=True) for t in result.tools]


async def harvest(only: list[str] | None = None, timeout: float = 120) -> dict[str, str]:
    SANDBOX.mkdir(parents=True, exist_ok=True)
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    specs = yaml.safe_load((DATA / "servers.yaml").read_text())["servers"]
    status: dict[str, str] = {}
    for spec in specs:
        sid = spec["id"]
        if only and sid not in only:
            continue
        try:
            tools = await asyncio.wait_for(list_tools(spec), timeout)
        except Exception as exc:  # one broken server must not stop the rest
            status[sid] = f"FAILED: {type(exc).__name__}: {exc}"[:200]
            continue
        out = {
            "server": sid,
            "source": spec["source"],
            "package": " ".join([spec["command"], *spec.get("args", [])]),
            "harvested_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": tools,
        }
        (TOOLS_DIR / f"{sid}.json").write_text(json.dumps(out, indent=2))
        status[sid] = f"ok ({len(tools)} tools)"
    return status


def main(only: list[str] | None = None) -> None:
    for sid, msg in asyncio.run(harvest(only)).items():
        print(f"{sid:14} {msg}")


if __name__ == "__main__":
    import sys

    main(sys.argv[1:] or None)
