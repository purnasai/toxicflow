"""Attach capability labels to harvested tools using data/labels.yaml."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"

CAPABILITIES = ["untrusted_input", "private_read", "exfil_sink", "store_read", "store_write", "none", "unknown"]


@dataclass(frozen=True)
class Tool:
    server: str
    name: str
    description: str
    caps: tuple[str, ...]
    why: str

    @property
    def id(self) -> str:
        return f"{self.server}.{self.name}"


def load_tools(tools_dir: Path = DATA / "tools", labels_path: Path = DATA / "labels.yaml") -> dict[str, Tool]:
    rules = yaml.safe_load(labels_path.read_text())["servers"]
    out: dict[str, Tool] = {}
    for f in sorted(tools_dir.glob("*.json")):
        harvested = json.loads(f.read_text())
        server = harvested["server"]
        for t in harvested["tools"]:
            caps, why = ("unknown",), "No labelling rule matched; treated as possibly anything."
            for rule in rules.get(server, []):
                if re.search(rule["match"], t["name"]):
                    caps, why = tuple(rule["caps"]), rule["why"]
                    break
            bad = set(caps) - set(CAPABILITIES)
            if bad:
                raise ValueError(f"{server}.{t['name']}: unknown capability {bad}")
            tool = Tool(server, t["name"], (t.get("description") or "")[:500], caps, why)
            out[tool.id] = tool
    return out
