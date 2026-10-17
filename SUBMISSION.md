# ToxicFlow — Graph Hacks submission (Track 01: Agents That Act on Connected Data)

Repo: https://github.com/purnasai/toxicflow · License MIT · Built 15–17 Oct 2026 for the hackathon.

## One-line pitch
An agent that finds where untrusted content can steer a multi-agent MCP setup into leaking private data across
agents, picks the least disruptive fix from graph evidence, applies it, and enforces it at runtime.

## Problem
A prompt-injection leak needs three capabilities at once: reading untrusted input, reading private data, and
sending data out. Scanners check one agent at a time. When the three are spread across agents that delegate to
each other or share a store, every agent passes the check and the system still leaks. Finding that needs a
multi-hop traversal over who can influence whom.

## What the agent does (all on FalkorDB)
1. **Scan**: one-hop per-agent view vs. the multi-hop `TOXIC_FLOWS` Cypher query (0..8 hops over `INSTRUCTS`,
   `REPORTS_TO`, `WRITES_TO`/`FEEDS`).
2. **Decide**: hitting-set repair search; every candidate is applied to a `GRAPH.COPY`, the flow query and the
   task-coverage query are re-run, and only repairs with zero flows and zero broken tasks are kept.
3. **Act**: `--apply` writes the repair to the graph, re-verifies it, records `Finding`/`Remediation` memory nodes,
   and exports the patched agent config. An LLM investigator can drive the same tools over MCP and file a
   `Proposal`; a human approves it.
4. **Enforce**: a per-agent MCP gate proxy asks the graph, before every outbound call, whether untrusted and private
   data have met upstream of the caller in this session; if so it blocks and returns the path.

## Verified results (re-run 2026-10-18; code at 7f7fcbe, docs updated after)
| Check | Result |
|---|---|
| Test suite incl. independent pure-Python oracle | **32/32 pass** (`uv run pytest -q`, 5 s) |
| `scan acme` | per-agent view: all 4 agents "look safe"; graph: **8 toxic flows**, 0 unknown |
| `repair acme` | 9 single fixes rejected (each breaks a task); cheapest repairs: **cost 3** |
| `replay acme acme_injection --no-gate` | secret leaves **3 ways** (2× Slack, 1× fetch) |
| `replay … ` (gate on) | **3 calls blocked**, each with its path; nothing leaves |
| `replay … --after-repair` | repair chosen by the graph search and applied first; **4 steps impossible**, nothing leaves |

Real-world corpus (aggregate re-derived from per-project results on 2026-10-18):
- 3,000 public GitHub repos with Claude Code subagents; forks excluded at crawl; 2,963 scanned rows, 2,921
  parsed (42 skipped). 88.3% have a toxic flow; 87.3% have an unrestricted `Bash` subagent; after a
  shell-without-network counterfactual 35.2% (1,027) remain exposed; **4 of 1,027 (0.39%) only through
  cross-agent paths**. 489 still-exposed projects have an inheriting subagent; in 534 of the other 538 one
  explicitly configured subagent holds all three capabilities.
- Duplicate sensitivity: 230 projects are byte-identical copies of another; on the 2,691 distinct ones: 88.0%,
  35.3%, still 4 cross-agent-only projects.
- Honest reading: in today's public setups the risk is mostly inside single agents; the cross-agent case only a
  graph sees is real but rare.

## Reachable vs. exploited
A reported flow means the configuration *permits* the leak path. Exploitation is demonstrated only in the scripted
`acme_injection` replay, against real filesystem/git MCP servers and canned GitHub/Slack/fetch responses. No real
third-party system was attacked; the corpus numbers are reachability only.

## Limits
Hand-written scenario topologies (tool data is real, harvested from 17 MCP servers); no argument-level
permissions, OAuth scopes or message content; the patched config is exported but not deployed into a live client;
corpus sample skewed toward small agent files; LLM labels used for 1,146 unlabelled tool names (validated blind:
precision 0.96 / 0.88 / 0.60 for untrusted / outbound / private).

## Reproduce
```bash
git clone https://github.com/purnasai/toxicflow && cd toxicflow
docker compose up -d && uv sync
uv run pytest -q
uv run toxicflow scan acme
uv run toxicflow repair acme
uv run toxicflow replay acme acme_injection --no-gate
uv run toxicflow replay acme acme_injection
uv run toxicflow replay acme acme_injection --after-repair
uv run toxicflow ui        # http://localhost:8790
```

## 3-minute demo video script
| Time | Screen | Say |
|---|---|---|
| 0:00–0:20 | README diagram / acme graph in UI | "Three agents, each safe alone. Together they leak. ToxicFlow finds that on FalkorDB." |
| 0:20–0:55 | UI **Scan**: per-agent table, then click the `triage → coder → memory → standup` flow | "One-hop: all safe. Multi-hop query: 8 flows. This one has no delegation edge between coder and standup; it goes through shared memory." |
| 0:55–1:35 | UI **Repair** | "The obvious cuts each break a team task. The graph search tests combinations on graph copies: cost 3, quarantine coder's output and isolate its memory. Applied and re-verified." |
| 1:35–2:30 | UI **Runtime gate**: no gate → gate → after repair | "Scripted injection: three leaks. Gate on: all three blocked, with the path that justified each block. After repair: those steps cannot even happen." |
| 2:30–3:00 | Corpus table in README | "On 2,921 real setups: 88% have a flow, mostly single over-powered agents; cross-agent-only leaks are rare (4). We report that honestly." |

## AI assistance disclosure
Built with an AI coding assistant (Claude Code), directed and reviewed by the author, who can explain the graph
model, queries, repair search, gate and labels. Tool labels for 1,146 corpus tool names were produced by an LLM
and validated against 137 hand labels.
