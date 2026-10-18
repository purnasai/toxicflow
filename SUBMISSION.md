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

## Three-minute recording sequence (verified against the running UI and CLI on 2026-10-18)

Before recording:
- `docker compose up -d && uv run toxicflow ui`, then open http://localhost:8790 and **hard-refresh** (Ctrl+Shift+R).
- Have a terminal with `results/investigate_support.txt` and `results/EVAL.md` open.
- The first Gate-tab load starts the real MCP servers; click it once before recording so it is warm.

| Time | Do this | On screen (verified) | Say |
|---|---|---|---|
| 0:00–0:12 | Scenario `acme`, tab **1 · Scan** | Strip: **4 / 4 look safe** vs **8 toxic flows · 1–4 hops** | "Four agents. Reviewed one at a time, all four look safe. FalkorDB's multi-hop query finds 8 toxic flows." |
| 0:12–0:40 | Click the card **triage + coder meet in coder, out via standup · 3 hops**; hover **coder** | Routes animate `triage → coder`, `coder → memory/team-kb → standup`; hover card: *on the route of 8 of 8 flows* | "The injected issue goes from triage to coder. Coder writes the shared memory; standup reads it and posts to Slack. There is no delegation between coder and standup. Coder is on every route." |
| 0:40–1:15 | Tab **2 · Repair** | Strip: **none is safe**. Table: typed returns → *8 flows remain*; isolating the KB → *breaks standup-notes: data coder>standup*; revokes and cuts → *breaks tasks* | "Can a config change fix it? Restricting coder to typed fields still lets its data through. Isolating the memory starves standup of coder's notes. Revoking or cutting breaks a task. An exhaustive search over every combination confirms there is no safe configuration change, so we don't pretend there is." |
| 1:15–1:50 | Tab **3 · Runtime gate**: **No gate**, then **Gate on**, then click card **#5** | No gate: *Secret left through slack, fetch, slack*. Gate on: *The secret did not leave. 3 blocked*, steps #1–#4 and #7 allowed, #5 #6 #8 **BLOCK**; #5 shows its path | "So the gate protects instead. Filesystem and memory servers run for real. Without the gate the secret leaves three ways. With it, the three exfiltration calls are blocked, each with the graph path behind it, and the five legitimate calls still run." |
| 1:50–2:15 | Scenario `github_solo`, tab **2 · Repair**, click **Show graph after repair** | Strip: **cost 3 → 0 flows · 0 tasks broken**; after repair the node loses its *private* pill | "When a safe change exists, ToxicFlow finds it: one GitHub agent, two single fixes break its job, and revoking the private-read tools removes the flow and keeps the task. `repair --apply` applies it and re-verifies." |
| 2:15–2:38 | Terminal: `results/investigate_support.txt` (scroll to the end) | *29 tool calls via MCP*, *No available repair was found…*, *rejected by simulation* | "The agent works only through MCP tools over the graph: 29 calls, 9 simulated repairs. It tried one proposal; the simulation guardrail rejected it, so nothing unsafe is applied." |
| 2:38–3:00 | `results/EVAL.md` | Detection totals, Repair table, Runtime table | "Across 8 scenarios with hand-written ground truth: per-agent checks miss 14 of 16 flows, the graph misses none. A per-agent gate lets all 7 unsafe calls through; ours blocks all 7 and allows all 34 legitimate ones." |

### Claim → evidence
| Claim | Evidence (run it or open it) |
|---|---|
| Per-agent: all safe; graph: 8 flows | `toxicflow scan acme --reload` → `results/demo/1_scan_acme.txt` |
| No safe configuration repair for acme | `toxicflow repair acme` (13 rejected) → `results/demo/2_repair_acme.txt`; exhaustive check in `results/EVAL.md` (Repair: acme `None`) |
| Gate blocks 3, allows 5 | `toxicflow replay acme acme_injection [--no-gate]` → `results/demo/3_replay_acme_*.txt` |
| github_solo repair applied and verified | `toxicflow repair github_solo --apply`, then `toxicflow scan github_solo` → `results/demo/5_*.txt`, `6_*.txt`; `docs/ui-repair-github_solo.png` |
| Agent and guardrail | `results/investigate_support.txt` |
| Totals (16 flows, 34/7 runtime) | `toxicflow eval` → `results/EVAL.md` (fingerprint `bdc87c0637a0425f`) |
| Memory isolation is real | `uv run pytest -q tests/test_isolation.py` |

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
