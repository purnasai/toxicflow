# ToxicFlow: Graph Hacks submission (Track 01: Agents That Act on Connected Data)

Repo: https://github.com/purnasai/toxicflow · MIT · built 15–18 Oct 2026 for the hackathon.

## Pitch
An agent that finds where untrusted content can steer a multi-agent MCP setup into leaking private data
**across agents that each look safe on their own**. It picks the cheapest fix that keeps the team's real
work running, a human approves it, and a runtime gate enforces it against live tool calls. FalkorDB holds
the agents, tools, delegations, shared stores, tasks, repair simulations, findings and runtime sessions.
Every decision is a Cypher query over that graph.

## Verified results (all reproducible: `uv run pytest -q` → 61 passed; `uv run toxicflow eval`, fingerprint `189a8479fd10685e` on two runs)

| Question | Evidence |
|---|---|
| Do per-agent checks miss real risks? | Against 14 hand-derived flows in 7 scenarios: per-agent check 2 found, **12 missed**; graph 14 found, 0 false positives, 0 missed. |
| Is the detector right, not just loud? | Ground truth written by hand (`data/expected.yaml`). An independent pure-Python implementation agrees on every scenario. The negative control `support_safe` gives 0 flows. |
| Is the repair really the cheapest? | On all 7 scenarios the graph search's minimum cost **and** full set of minimum repairs equal an exhaustive solver over the whole intervention space (≤5 actions, cost ≤8). |
| Why not one simple permission change? | `acme`: all 13 single fixes fail (9 break a task, 4 leave flows). `support`: revoking the ticket reader's input removes both flows but breaks triage; the chosen repair (same cost, 2 changes) keeps all 4 tasks. |
| Does the gate enforce anything? | 41 hand-labelled calls: the FalkorDB gate allows 36/36 legitimate calls and blocks 5/5 unsafe ones. No gate and a per-agent gate each let **all 5** unsafe calls through. Scripted `acme_injection`: 3 leaks → 0 with gate → 0 after repair (4 steps impossible). |
| Is there an agent? | `toxicflow investigate` = LLM + MCP client over 10 fixed-Cypher MCP tools. Recorded run on `support`: 15 tool calls → proposal → `approve` (applied, re-verified: 0 flows, 0 broken tasks) → rescan 0 flows → `recall` returns the remediation. Files in `results/`. |
| Real world? | 2,921 public Claude Code setups: 88.3% toxic, 87.3% unrestricted `Bash` subagent, 35.2% still exposed after a shell fix. Cross-agent-only: 4 projects. Of 1,898 projects with no over-powered agent, only 4 split the three capabilities across agents, and the graph flags all 4. |

## Honest scope
- **Static analysis is conservative reachability.** A flow means the configuration *permits* the path, not that a leak happened.
- **Runtime taint is per agent and per session, not per value.** Private data sent with no untrusted input is allowed by design: the threat model is injection-driven exfiltration.
- **The graph is not mathematically indispensable.** A dict-based reference computes the same answers faster on these small graphs. FalkorDB is the shared, mutable state that the agent's MCP tools, the `GRAPH.COPY` simulations, approvals, memory, the gate's sessions and the UI all act on.
- **What is real and what is scripted.**
  - Scenarios are synthetic; the tool data is real (harvested from 17 MCP servers).
  - Attack sequences are scripted, not an LLM under attack.
  - GitHub, Slack and fetch responses come from fixtures; filesystem and git servers run for real.
  - The patched config is exported, not deployed to a live client.
- **The model is limited.** Repair cost weights are a stated judgement, not measured business costs. Tasks model tool reachability, not data dependencies. The LLM's prose is checked for names only; decisions come from the queries.

## Reproduce
```bash
git clone https://github.com/purnasai/toxicflow && cd toxicflow
docker compose up -d && uv sync
uv run pytest -q                       # 61 tests
uv run toxicflow eval                  # results/EVAL.md
uv run toxicflow scan acme --reload
uv run toxicflow repair acme
uv run toxicflow replay acme acme_injection --no-gate
uv run toxicflow replay acme acme_injection
uv run toxicflow replay acme acme_injection --after-repair
uv run toxicflow ui                    # http://localhost:8790
# agent (needs OPENAI_API_KEY via .env or TOXICFLOW_ENV_FILE):
uv run toxicflow investigate support --reload && uv run toxicflow approve support <proposal-id> && uv run toxicflow scan support
```

## Demo video script (3:00 maximum)
| Time | Screen | Narration |
|---|---|---|
| 0:00–0:15 | UI, `acme`, headline strip | "Four agents. Reviewed one at a time, all four look safe. FalkorDB's multi-hop query finds 8 toxic flows." |
| 0:15–0:50 | Scan: click "triage + coder meet in coder, out via standup"; hover `coder` | "Injected issue text goes triage → coder; coder writes shared memory; standup reads it and posts to Slack. No delegation edge between coder and standup. Coder is on the route of all 8 flows." |
| 0:50–1:25 | Repair tab, then "Show graph after repair" | "13 single fixes: 9 break a team task, 4 leave flows. The search tests combinations on graph copies. Cost 3: quarantine coder's output, give it its own memory. An exhaustive solver confirms nothing cheaper exists." |
| 1:25–2:00 | Runtime gate: No gate → Gate on (click #5) → After repair | "Scripted injection: three leaks. Gate on: all three blocked, each with the path that justified it. After the repair, those steps can't happen, and legitimate work still passes." |
| 2:00–2:30 | Terminal: `toxicflow investigate support` output, `approve`, `scan support` | "The agent works only through MCP tools over the graph. It compares views, simulates repairs and files a proposal. A human approves; the graph re-verifies; the rescan shows zero flows." |
| 2:30–3:00 | `results/EVAL.md` | "Across 7 scenarios with hand-written ground truth: per-agent checks miss 12 of 14 flows; the graph misses none. A per-agent runtime gate lets every unsafe call through; ours blocks all five. In 2,921 real setups, most risk sits in over-powered single agents, and we say so." |

## Submission checklist
- [x] Public repository: github.com/purnasai/toxicflow (**local commits not yet pushed**)
- [x] README with architecture, graph model, Cypher (`src/toxicflow/queries.py`), setup, limitations, findings
- [x] FalkorDB central: detection, repair simulation (`GRAPH.COPY`), approvals, memory, runtime gate sessions, UI
- [x] Agent with real MCP tool selection (`toxicflow investigate`), with human approval
- [x] Reproducible evaluation (`toxicflow eval`) and 61 tests
- [x] AI-assistance disclosure (below)
- [ ] Demo video (≤3 min, public link): to record
- [ ] Submission form: to fill in

## AI assistance disclosure
Built with an AI coding assistant (Claude Code). The author directed the work, reviewed every change, ran
the tests and evaluation, and can explain the graph model, queries, repair search, gate and labels.
Corpus tool labels for 1,146 tool names were produced by an LLM and validated blind against 137 hand
labels (precision 0.96 / 0.88 / 0.60 for untrusted / outbound / private).
