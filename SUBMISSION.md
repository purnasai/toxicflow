# ToxicFlow: Graph Hacks submission (Track 01: Agents That Act on Connected Data)

Repo: https://github.com/purnasai/toxicflow · MIT · built 15–18 Oct 2026 for the hackathon.

## Pitch
A graph-driven security agent for multi-agent MCP setups:
1. It finds where untrusted content can steer agents into leaking private data **across agents that each look safe on their own**.
2. It searches for a configuration change that closes every such path while every task keeps its tools and the data it needs. When no such change exists, it proves that, checked exhaustively.
3. A runtime gate then blocks the calls that would complete a leak.

FalkorDB holds the agents, tools, delegations, return channels, shared stores, tasks, repair simulations, approvals, findings and gate sessions. Every decision is a Cypher query over it.

This is a proof of concept on synthetic scenarios with real MCP tool definitions, not production security.

## Verified results (`uv run pytest -q` → 79 passed; `uv run toxicflow eval` → fingerprint `bdc87c0637a0425f` on two runs)

| Question | Evidence |
|---|---|
| Do per-agent checks miss real risks? | 16 hand-derived flows in 8 scenarios: per-agent check finds 2 and misses **14**; the graph finds 16, with 0 false positives and 0 missed. |
| Is the model honest about structured returns? | Typed fields still carry data. The regression scenario `analytics_structured` has 2 flows that the old "structured = safe" model missed. |
| Can a configuration change fix it? | Usually **no**, and the graph shows why. With tasks that need their data (`needs_data`), only `github_solo` has a safe repair. For acme, analytics, analytics_structured, assistant and support, an exhaustive solver over the full intervention space (≤5 actions, cost ≤8) confirms none exists. In acme, all 13 single fixes fail: 11 break a task, 2 leave flows. |
| Does the gate enforce anything? | 41 hand-labelled calls: the FalkorDB gate allows 34/34 legitimate calls and blocks 7/7 unsafe ones. No gate and a per-agent gate each let **all 7** through. Scripted `acme_injection` (real filesystem, git and memory servers): 3 leaks with no gate → 0 with the gate. |
| Is store isolation real? | For the memory server, yes: one process and storage file per instance; a note written to the isolated instance is absent from the other (`tests/test_isolation.py`). Typed-return and delegation changes are config recommendations, not enforced by ToxicFlow. |
| Is there an agent? | `toxicflow investigate` = LLM + MCP client over 10 fixed-Cypher tools. Recorded run on `support`: 29 tool calls, 9 repair simulations, concluded no safe repair; its one proposal was rejected by the simulation guardrail. `approve` re-validates against current state and rolls back on failure. |
| Real world? | 2,921 public Claude Code setups: 88.3% toxic, 87.3% have an unrestricted `Bash` subagent, 35.2% still exposed after a shell fix. Of 1,898 projects with no over-powered agent, only 4 split the three capabilities across agents, and the graph flags all 4. |

## What is checked, simulated, enforced or scripted
- **Static detection:** finds configurations that *permit* a leak (conservative reachability). Not proof that a leak happened.
- **Return channels:** typed `id`/`number` fields are data-only, `enum`/`bool` carry nothing. This is an *assumption*: ToxicFlow does not mediate agent-to-agent messages.
- **Simulated repair:** runs on graph copies and is exact on these scenarios. Tasks are modelled as tools plus data paths; task output correctness is **not** verified.
- **Deployed enforcement:**
  - Enforced: per-agent tool lists (revokes), the taint gate on outbound and unlabelled tools, and per-instance memory storage.
  - Not enforced by ToxicFlow: `quarantine` and `cut`, and `isolate` for servers whose launch spec is not instance-aware.
- **Runtime taint:** per agent and per session, not per value. Failed calls don't count as reads. Arguments are stored redacted.
- **Scripted replay:**
  - Fixed call sequences.
  - GitHub, Slack, fetch and search come from fixtures; filesystem, git and memory servers run for real.
  - A leak counts only if the secret really reached the step's input.
- **State handling:**
  - The CLI, agent, `approve` and gate share `toxicflow_<scenario>`.
  - The UI and eval use their own graphs.
  - Replays run on a copy of the active graph.
  - Graphs built by an older schema are rebuilt automatically.

## Reproduce
```bash
git clone https://github.com/purnasai/toxicflow && cd toxicflow
docker compose up -d && uv sync
uv run pytest -q                       # 79 tests
uv run toxicflow eval                  # results/EVAL.md
uv run toxicflow scan acme --reload
uv run toxicflow repair acme
uv run toxicflow replay acme acme_injection --no-gate
uv run toxicflow replay acme acme_injection
uv run toxicflow ui                    # http://localhost:8790
uv run toxicflow investigate support --reload   # needs OPENAI_API_KEY via .env or TOXICFLOW_ENV_FILE
```

## Demo video script (3:00 maximum)
| Time | Screen | Narration |
|---|---|---|
| 0:00–0:15 | UI, `acme`, headline strip | "Four agents. Reviewed one at a time, all four look safe. FalkorDB's multi-hop query finds 8 toxic flows." |
| 0:15–0:50 | Scan: click "triage + coder meet in coder, out via standup"; hover `coder` | "Injected issue text goes triage → coder; coder writes shared memory; standup reads it and posts to Slack. No delegation between coder and standup. Coder sits on all 8 routes." |
| 0:50–1:30 | Repair tab | "Can we fix the config? 13 single fixes: restricting coder to typed fields still lets its data through; isolating the memory starves standup of coder's notes; revoking or cutting breaks a task. An exhaustive search over every combination confirms there is no safe configuration change here." |
| 1:30–2:05 | Runtime gate: No gate → Gate on (click #5) | "So the gate protects instead. Scripted injection with real filesystem and memory servers: three leaks. Gate on: all three blocked, each with the graph path that justified it, while the fix-bug work still runs." |
| 2:05–2:35 | Terminal: `results/investigate_support.txt` | "The agent works only through MCP tools over the graph: 29 calls, 9 simulated repairs, no safe one. Its proposal was rejected by the simulation guardrail, so nothing unsafe is applied." |
| 2:35–3:00 | `results/EVAL.md` | "Across 8 scenarios with hand-written ground truth: per-agent checks miss 14 of 16 flows, the graph misses none, and a per-agent gate lets all 7 unsafe calls through while ours blocks them. We state exactly which defences are enforced and which are recommendations." |

## Submission checklist
- [x] Public repository github.com/purnasai/toxicflow (**local commits not yet pushed**)
- [x] README with architecture, graph model, Cypher (`src/toxicflow/queries.py`), setup, guarantees, limitations, findings
- [x] FalkorDB central: detection, simulations (`GRAPH.COPY`), approvals, memory, gate sessions
- [x] Agent with real MCP tool selection and a simulation guardrail; human approval re-validated
- [x] Reproducible evaluation (`toxicflow eval`) and 79 tests
- [x] AI-assistance disclosure (below)
- [ ] Demo video (≤3 min, public link)
- [ ] Submission form

## AI assistance disclosure
Built with an AI coding assistant (Claude Code). The author directed the work, reviewed every change, ran the
tests and evaluation, and can explain the graph model, queries, repair search, gate and labels. An external
source-level review prompted the correction of the return-channel and task models before submission. Corpus
tool labels for 1,146 tool names were produced by an LLM and validated blind against 137 hand labels
(precision 0.96 / 0.88 / 0.60 for untrusted / outbound / private).
