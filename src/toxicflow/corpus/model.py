"""Turn one crawled repository into an agent model the graph loader understands.

Claude Code semantics used here (from its documentation):
- the main thread delegates to subagents (Task tool) and gets their final message back as text;
- a subagent with no `tools:` line inherits every tool the main thread has, MCP tools included;
- subagents do not spawn further subagents;
- all agents in a project work in the same directory, so file tools share one store.

Two views of the main thread:
- "configured": it holds every built-in tool plus every server in .mcp.json (the default);
- "orchestrator": it holds no tools and only relays text, which isolates the question
  "does splitting the work into restricted subagents keep the risky capabilities apart?"
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ..labels import DATA, load_tools

# ---------------------------------------------------------------- built-in tools

BUILTIN_CAPS: dict[str, tuple[str, ...]] = {
    "WebFetch": ("untrusted_input", "exfil_sink"),
    "WebSearch": ("untrusted_input", "exfil_sink"),
    "Read": ("private_read", "store_read"),
    "Grep": ("private_read", "store_read"),
    "Glob": ("private_read", "store_read"),
    "LS": ("private_read", "store_read"),
    "NotebookRead": ("private_read", "store_read"),
    "Write": ("store_write",),
    "Edit": ("store_write",),
    "MultiEdit": ("store_write",),
    "NotebookEdit": ("store_write",),
    # Arbitrary shell: can curl (untrusted in, data out), cat secrets, and write files.
    "Bash": ("untrusted_input", "private_read", "exfil_sink", "store_read", "store_write"),
    "BashOutput": ("none",),
    "KillShell": ("none",),
    "KillBash": ("none",),
    "TodoWrite": ("none",),
    "TodoRead": ("none",),
    "ExitPlanMode": ("none",),
    "Task": ("none",),
    "Agent": ("none",),
    "SlashCommand": ("none",),
    "Skill": ("none",),
    "AskUserQuestion": ("none",),
}
DEFAULT_MAIN_BUILTINS = [
    "Bash", "Glob", "Grep", "LS", "Read", "Edit", "MultiEdit", "Write", "NotebookEdit",
    "WebFetch", "WebSearch", "TodoWrite", "Task",
]
FILE_TOOLS = {"Read", "Grep", "Glob", "LS", "NotebookRead", "Write", "Edit", "MultiEdit", "NotebookEdit", "Bash"}

# Package / URL fragments that identify a harvested server kind in .mcp.json.
KNOWN_SERVERS = {
    "server-github": "github", "github-mcp-server": "github", "api.githubcopilot.com/mcp": "github",
    "server-slack": "slack", "mcp-server-fetch": "fetch", "server-filesystem": "filesystem",
    "mcp-server-git": "git", "server-memory": "memory", "mcp-server-time": "time",
    "server-postgres": "postgres", "mcp-server-sqlite": "sqlite", "server-brave-search": "brave-search",
    "server-puppeteer": "puppeteer", "server-google-maps": "google-maps", "mcp-server-sentry": "sentry",
    "server-everything": "everything", "@playwright/mcp": "playwright",
}


@dataclass
class ToolInfo:
    id: str
    server: str
    name: str
    caps: tuple[str, ...]
    source: str  # builtin | curated | llm | unknown


@dataclass
class ProjectModel:
    name: str
    view: str
    agents: dict[str, dict] = field(default_factory=dict)  # id -> {purpose, tools: set[str], inherits: bool}
    delegations: list[tuple[str, str]] = field(default_factory=list)
    tools: dict[str, ToolInfo] = field(default_factory=dict)
    servers: dict[str, str] = field(default_factory=dict)  # alias -> kind (or alias)
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------- parsing helpers

FRONT = re.compile(r"^---\s*\n(.*?)\n---", re.S)


def parse_frontmatter(text: str) -> dict:
    m = FRONT.match(text.lstrip("﻿"))
    if not m:
        return {}
    block = m.group(1)
    try:
        data = yaml.safe_load(block)
        if isinstance(data, dict):
            return data
    except yaml.YAMLError:
        pass
    # Lenient fallback: descriptions often contain unquoted colons.
    out = {}
    for key in ("name", "tools", "description"):
        mm = re.search(rf"^{key}\s*:\s*(.*)$", block, re.M)
        if mm:
            out[key] = mm.group(1).strip()
    return out


def split_tools(raw) -> list[str] | None:
    if raw is None:
        return None
    items = raw if isinstance(raw, list) else re.split(r",(?![^()]*\))", str(raw))
    out = []
    for t in items:
        t = str(t).strip().strip("'\"[]")
        if t:
            out.append(t)
    return out


def server_kind(alias: str, spec: dict | None) -> str:
    blob = json.dumps(spec or {}).lower()
    for frag, kind in KNOWN_SERVERS.items():
        if frag.lower() in blob:
            return kind
    low = alias.lower()
    for kind in set(KNOWN_SERVERS.values()):
        if low == kind or low.replace("_", "-") == kind:
            return kind
    return alias


# ---------------------------------------------------------------- resolution

# Counterfactual: a shell that can only touch local files (no network). Used to measure what
# remains after the obvious fix "stop giving subagents an unrestricted shell".
BASH_LOCAL_CAPS = ("private_read", "store_read", "store_write")


class Resolver:
    def __init__(self, llm_labels: dict[str, list[str]] | None = None, bash: str = "full"):
        if bash not in ("full", "local"):
            raise ValueError("bash must be 'full' or 'local'")
        self.bash = bash
        self.curated = load_tools()
        self.by_kind: dict[str, list[str]] = {}
        for t in self.curated.values():
            self.by_kind.setdefault(t.server, []).append(t.name)
        self.llm = llm_labels or {}

    def mcp_tool(self, alias: str, kind: str, name: str) -> ToolInfo:
        tid = f"mcp.{alias}.{name}"
        if f"{kind}.{name}" in self.curated:
            return ToolInfo(tid, alias, name, self.curated[f"{kind}.{name}"].caps, "curated")
        key = f"{kind}::{name}"
        if key in self.llm:
            return ToolInfo(tid, alias, name, tuple(self.llm[key]), "llm")
        return ToolInfo(tid, alias, name, ("unknown",), "unknown")

    def server_tools(self, alias: str, kind: str) -> list[ToolInfo]:
        if kind in self.by_kind:
            return [self.mcp_tool(alias, kind, n) for n in self.by_kind[kind]]
        return [self.mcp_tool(alias, kind, "*")]

    def builtin(self, name: str) -> ToolInfo:
        base = name.split("(")[0].strip()
        if base == "Bash" and self.bash == "local":
            return ToolInfo(f"builtin.{name}", "workspace", name, BASH_LOCAL_CAPS, "builtin")
        if base in BUILTIN_CAPS and "(" not in name:
            server = "workspace" if base in FILE_TOOLS else "claude"
            return ToolInfo(f"builtin.{base}", server, base, BUILTIN_CAPS[base], "builtin")
        if base == "Bash":  # restricted shell such as Bash(git:*): we cannot tell what it allows
            return ToolInfo(f"builtin.{name}", "workspace", name, ("unknown", "store_read", "store_write"), "unknown")
        return ToolInfo(f"builtin.{name}", "claude", name, ("unknown",), "unknown")


def load_llm_labels() -> dict[str, list[str]]:
    p = DATA / "corpus" / "llm_labels.json"
    return json.loads(p.read_text()) if p.exists() else {}


def build(repo_dir: Path, view: str = "configured", resolver: Resolver | None = None) -> ProjectModel:
    r = resolver or Resolver(load_llm_labels())
    pm = ProjectModel(repo_dir.name, view)

    mcp_specs: dict = {}
    mcp_file = repo_dir / "_mcp.json"
    if mcp_file.exists():
        try:
            mcp_specs = json.loads(mcp_file.read_text()).get("mcpServers", {}) or {}
        except (json.JSONDecodeError, AttributeError):
            pm.notes.append("unparseable .mcp.json")
    for alias, spec in mcp_specs.items():
        pm.servers[alias] = server_kind(alias, spec if isinstance(spec, dict) else None)

    def add(t: ToolInfo) -> str:
        pm.tools.setdefault(t.id, t)
        return t.id

    def resolve(name: str) -> list[str]:
        if name.startswith("mcp__"):
            parts = name.split("__")
            alias = parts[1] if len(parts) > 1 else "*"
            kind = pm.servers.get(alias) or server_kind(alias, None)
            pm.servers.setdefault(alias, kind)
            if len(parts) < 3 or parts[2] in ("", "*"):
                return [add(t) for t in r.server_tools(alias, kind)]
            return [add(r.mcp_tool(alias, kind, "__".join(parts[2:])))]
        return [add(r.builtin(name))]

    main_tools: set[str] = set()
    for name in DEFAULT_MAIN_BUILTINS:
        main_tools |= set(resolve(name))
    for alias, kind in list(pm.servers.items()):
        for t in r.server_tools(alias, kind):
            main_tools.add(add(t))

    pm.agents["main"] = {
        "purpose": "Claude Code main thread",
        "tools": main_tools if view == "configured" else set(),
        "inherits": False,
    }
    for f in sorted(repo_dir.glob("*.md")):
        fm = parse_frontmatter(f.read_text(errors="replace"))
        if not fm:
            continue
        aid = re.sub(r"[^\w\-.]", "_", str(fm.get("name") or f.stem))[:60]
        if aid == "main" or aid in pm.agents:
            aid = f"{aid}~{f.stem}"
        tools_raw = split_tools(fm.get("tools"))
        if tools_raw is None or any(t in ("*", "all") for t in tools_raw):
            tools, inherits = set(main_tools), True
        else:
            tools, inherits = set(), False
            for t in tools_raw:
                tools |= set(resolve(t))
        pm.agents[aid] = {"purpose": str(fm.get("description", ""))[:200], "tools": tools, "inherits": inherits}
        pm.delegations.append(("main", aid))
    return pm
