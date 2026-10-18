# ToxicFlow

**Graph Hacks (WeMakeDevs × FalkorDB), Track 01: Agents That Act on Connected Data.** (Also entering Track 02; see Memory.)

ToxicFlow finds where a multi-agent MCP setup lets untrusted content steer an agent into reading private data and then carry that data out through a different agent. It then searches for the **least disruptive configuration change** that closes every such path while every task keeps its tools *and the data it needs*. When no such change exists, it says so (checked exhaustively) and a runtime gate blocks the calls that would complete a leak.

**What it is:** a graph-driven security analysis, repair-planning and runtime-gating proof of concept on synthetic scenarios with real MCP tool definitions. It is not production security. See [Guarantees](#guarantees-what-is-checked-simulated-enforced-or-scripted) for exactly what is enforced and what is only modelled.

A risky agent setup needs three things at once: an agent that reads untrusted input, one that reads private data, and one that can send data out. Checking one agent at a time misses this whenever the three are spread across agents that delegate to each other or share a store. FalkorDB follows those connections.

## The demo

```bash
toxicflow scan acme                                   # one-hop view: all safe. graph: 8 toxic flows
toxicflow repair acme                                 # 13 single fixes fail; no safe configuration change exists
toxicflow investigate support --reload                # LLM agent investigates over MCP
toxicflow replay acme acme_injection --no-gate        # baseline: the injected issue leaks the secret 3 ways
toxicflow replay acme acme_injection                  # runtime gate blocks all 3, each with its path
toxicflow replay acme acme_injection --after-repair   # no safe repair exists here, so this is the gate alone
toxicflow repair github_solo --apply                  # a case where a safe repair exists: cost 3, applied and re-verified
toxicflow scan github_solo                            # 0 toxic flows, 1 applied remediation
```

- `scan` shows the per-agent view first: no single agent holds all three capabilities. The multi-hop query then finds 8 flows of 1–4 hops. One goes `triage -> coder -> memory/team-kb -> standup`, with no delegation edge between coder and standup at all.
- `repair` explains why each obvious single fix fails, and why no combination works: restricting coder to typed returns still lets its data reach triage, isolating the KB cuts standup off from coder's notes (`standup-notes` needs them), and revoking or cutting breaks a task. The exhaustive solver confirms that no configuration change is safe here, so the runtime gate is the protection.

## Web UI

`toxicflow ui` opens http://localhost:8790. Every view comes straight from FalkorDB through the same code as the CLI.

| Scan | Repair | Runtime gate |
|---|---|---|
| ![scan](docs/ui-scan.png) | ![repair](docs/ui-repair.png) | ![gate](docs/ui-gate.png) |

- **Scan:** the per-agent table on one side, the graph's flows on the other. Click a flow to light up its untrusted, private and outbound routes.
- **Repair:** every single fix that fails, with the reason, then the cheapest repair. A toggle shows the graph after the repair, with removed edges dashed.
- **Runtime gate:** run the scripted attack with no gate, with the gate on, or after the repair. Click a blocked step to see its path.

## Scenarios

| Scenario | Shape | Result |
|---|---|---|
| `acme` | triage delegates to a coder and a researcher; a standup bot shares memory with the coder | Per-agent check: all safe. Graph: 8 flows. **No safe configuration repair:** coder's output must still reach triage (fix-bug) and standup (standup-notes), and injected issue text reaches coder by delegation. All 13 single fixes fail; the gate blocks the 3 exfiltration attempts. |
| `analytics` | an analyst delegates to a SQL agent and a web-search agent | 2 flows. Restricting SQL to typed fields does not help (the fields still carry customer data); no safe configuration repair. |
| `analytics_structured` | as `analytics`, but the SQL agent already returns a structured result (`customer_id: id, revenue: number`) | **Regression case:** 2 flows. The old model treated any structured return as safe and reported 0. |
| `assistant` | one browser agent that fills forms from local notes | 1 flow. **No configuration change keeps its job working**, so a human decides and the runtime gate protects it meanwhile. |
| `github_solo` | one agent with the full GitHub server (the publicly reported GitHub MCP injection shape) | Per-agent check and graph agree. |
| `unlabelled` | the only outbound path goes through a tool nobody labelled | UNKNOWN, never "safe". At runtime the unlabelled tool is blocked whenever untrusted input could have steered its caller. |
| `support` | a dispatcher **with no risky tools** bridges a ticket reader, a records agent and a Slack notifier; the ticket reader also writes shared notes the notifier reads | Per-agent check: all safe. Graph: 2 flows, one meeting in the tool-less dispatcher and one through the shared store. Revoking the ticket reader's input removes both but breaks triage; typed returns + store isolation still leave a flow (typed fields carry customer data). No safe configuration repair. |
| `support_safe` | the same agents and tools; the ticket reader returns enums only, records returns ids/enums, the notifier keeps its own notes | **Negative control:** 0 flows, and the same calls that leak in `support` are allowed. |

Every scenario's flows, cheapest repair cost and runtime decisions are written down by hand in `data/expected.yaml`, and the tests check against that file rather than against the detector's own output.

## Evaluation: does the graph actually matter?

`uv run toxicflow eval` runs the ablation below over all 8 scenarios and writes `results/eval.json` and `results/EVAL.md`. Two runs give the same result fingerprint (`bdc87c0637a0425f`); only the timings change.

**A. Per-agent check vs. B. graph investigation** (ground truth: 16 hand-derived flows)

| | True positives | False positives | False negatives |
|---|---|---|---|
| A: each agent checked on its own | 2 | 0 | **14** |
| B: multi-hop `TOXIC_FLOWS` on FalkorDB | **16** | 0 | 0 |
| Old model (any structured return = safe) | 14 | 0 | 2 (`analytics_structured`) |

14 of the 16 flows need capabilities joined across agents; the per-agent check finds only the two single-agent cases (`assistant`, `github_solo`). The negative controls (`support_safe`, and `unlabelled` in strict mode) produce no flows.

**C. Repair.** Tasks must keep their tools *and* receive their declared data (`needs_data`). Under that requirement:
- Only `github_solo` has a safe configuration repair (cost 3, revoke the private-read tools). `acme`, `analytics`, `analytics_structured`, `assistant` and `support` have none.
- In each case the graph search agrees with an exhaustive solver over the whole intervention space (every subset of up to 5 actions with cost up to 8, `toxicflow/reference.py`), so "no repair" is checked, not a search gap.
- In `acme`, all 13 single fixes fail: 11 break a task (often by starving it of data, e.g. isolating the KB cuts standup off from coder's notes) and 2 leave flows.

**D. Runtime** (41 hand-labelled calls in 13 sequences, including legitimate workflows):

| Policy | Legitimate calls allowed | Unsafe calls blocked | Unsafe allowed | Legitimate blocked |
|---|---|---|---|---|
| FalkorDB gate | 34/34 | **7/7** | 0 | 0 |
| No gate | 34/34 | 0/7 | 7 | 0 |
| Per-agent gate (blocks if the caller itself read untrusted + private) | 34/34 | 0/7 | **7** | 0 |

All 7 unsafe calls involve another agent's input or data, so a per-agent runtime policy misses every one. Scripted replay of `acme_injection` (filesystem, git and memory servers run for real): 3 leaks with no gate, 0 with the gate (3 blocked). No safe repair exists, so the "after repair" run is the gate alone.

**What this does and does not prove.** The security decision depends on joining relationships across agents; that is the claim. It is *not* that only a graph database can compute it. `toxicflow/reference.py` computes the same flows and repairs over plain Python dicts, agrees on every scenario, and is faster on these small graphs (microseconds vs. 3–80 ms per flow query). FalkorDB earns its place as the shared, mutable system of record:
- The CLI, the MCP tools the agent calls, `approve`, `recall` and the gate proxies all use the scenario's active graph, `toxicflow_<scenario>`.
- Repair simulations run on `GRAPH.COPY`s of it, and approvals are re-validated against it before they are applied.
- The gate's session log lives in it, and several agents' gate proxies share one session through it.
- The web UI and `toxicflow eval` use **their own** disposable graphs (`ui_<scenario>…`, `eval_…`) built from the same code and queries, so they never disturb the active graph. Scripted replays run on a copy of the active graph (`toxicflow_<scenario>__replay`).

Remove FalkorDB and the reference can still answer "is this config toxic?", but there is no live state for the agent to act on or for the gate to enforce.

## Guarantees: what is checked, simulated, enforced or scripted

| Layer | What it means here | Status |
|---|---|---|
| Static possible-flow detection | `TOXIC_FLOWS` finds configurations that **permit** a leak path (conservative reachability over the declared config) | Checked against hand-derived ground truth and two independent implementations; a flow is not proof that a leak happened |
| Return-channel model | free text carries instructions and data; typed `id`/`number` fields carry data only; `enum`/`bool` fields carry neither | **Assumption:** ToxicFlow does not mediate agent-to-agent messages, so declared schemas are not enforced by it |
| Simulated graph repair | interventions applied to `GRAPH.COPY`s, flows and task requirements re-checked | Exact against an exhaustive solver on all scenarios; tasks = tools reachable + declared `needs_data` paths, not proof that task outputs are correct |
| Deployed enforcement | what the gate proxy actually does with live MCP calls | **Enforced:** tool lists per agent (revoked tools are denied), the taint gate on outbound and unlabelled tools, per-instance storage for the memory server (`isolate` is real for memory; `tests/test_isolation.py`). **Not enforced:** `quarantine` (typed returns) and `cut` (delegations) are config recommendations; `isolate` for servers without an instance-aware launch spec (e.g. filesystem) |
| Runtime gate | blocks an outbound or unlabelled call when untrusted and private reads in the session can meet upstream of the caller | Per agent and per session, not per value; failed calls do not count as reads; arguments are stored redacted (name, type, length, hash) |
| Scripted replay | fixed call sequences through the gate; filesystem, git and memory servers run for real; GitHub/Slack/fetch/search are canned | A leak counts only if the secret really reached the step's input; the calls are scripted, not an LLM under attack |
| Actual task correctness | whether tasks still produce correct results after a change | **Not verified**; only modelled through tool reachability and data paths |

## Real-world check: 2,921 public agent setups

We wanted to know how often this actually happens, so we ran ToxicFlow on real projects.

**Data.**
- 3,000 public GitHub repositories that define Claude Code subagents (`.claude/agents/*.md` with a `tools:` line), found through GitHub code search.
- 19,862 agent files and 508 `.mcp.json` files.
- 2,921 projects parsed (42 skipped).
- Each project was loaded into **its own FalkorDB graph**. Reach was computed with `algo.bfs`, which gives the same result as the Cypher flow query on every scenario (tested).
- Raw files are not redistributed; only aggregate numbers are published (`data/corpus/summary.json`).

**How tools were labelled.**
- Built-in tools use a fixed table: `WebFetch` is untrusted input + outbound, `Read` is a private read, and `Bash` is everything.
- MCP tools we harvested use the curated labels.
- The other 1,146 MCP tool names were labelled by an LLM, after a **blind check against our 137 hand-labelled tools**:

  | Capability | Precision | Recall |
  |---|---|---|
  | untrusted input | 0.96 | 0.92 |
  | outbound | 0.88 | 0.98 |
  | private read | 0.60 | 0.86 |

- Store labels were unreliable, so they were not used. 101 low-confidence tools stay `unknown`.
- Every number below was computed with and without the LLM labels. They differ by under one point.

**Results.** The main thread is treated as a pure orchestrator, which asks whether splitting work into subagents keeps risky capabilities apart. As configured, the main thread holds every tool, so 100% of projects are trivially exposed.

| | Result |
|---|---|
| Projects with a toxic flow | **88%** |
| Projects where a subagent has an unrestricted shell (`Bash`) | **87%** |
| After the obvious fix (shell without network), projects still exposed | **35%** |
| …because a subagent has no `tools:` line and inherits everything | 489 projects |
| …with no inheriting subagent (in 534 of these, one explicitly configured subagent holds all three capabilities by itself) | 538 projects |
| Exposed only through cross-agent paths (each agent looks safe alone) | **0.4% of still-exposed (4 projects)** |

**What this means.** In today's public Claude Code setups the risk is mostly **inside single agents**: too many tools, unrestricted shells, and silent tool inheritance. The cross-agent leaks that only a graph can see do occur, but rarely. ToxicFlow reports both kinds, and the same graph lets you test a fix across thousands of setups before recommending it.

**Why "4 of 1,027" is so low** (`data/corpus/graph_only_audit.json`):
- After the shell fix, 1,023 of the 1,027 still-exposed projects have at least one subagent that holds all three capabilities by itself, so they are counted as single-agent exposure. "Cross-agent-only" excludes any project that *also* has an over-powered agent.
- Of the 1,898 projects with no over-powered agent, only 4 spread the three capabilities across different subagents at all. A cross-agent-only leak needs that split, and the graph flags all 4.
- The low share therefore reflects how public setups are built (one agent gets everything, or a capability is missing entirely) and how the metric is defined. It is not the detector missing paths; the detector's path-finding is checked against hand-derived ground truth and an independent implementation above.

**Limits.**
- It is a sample. The search was split by file size, so smaller agent files are over-represented.
- Forks were excluded at crawl time, but non-fork copies were not: 230 projects are byte-identical copies of another project's agent files (126 groups, e.g. one SDK template copied six times). Keeping one per group (2,691 projects) gives 88.0% toxic, 35.3% still exposed after the shell fix, and the same 4 cross-agent-only projects. Headline numbers above use all 2,921.
- Claude Code asks the user before many tool calls, and we do not model that prompt.
- A reported path means a leak *can* happen, not that it did.

Reproduce:
```bash
uv run python -m toxicflow.corpus.crawl --max-repos 3000
uv run python -m toxicflow.corpus.label_llm validate && uv run python -m toxicflow.corpus.label_llm corpus
uv run python -m toxicflow.corpus.scan && uv run python -m toxicflow.corpus.scan --bash local
uv run python -m toxicflow.corpus.aggregate
```

## Data: real MCP servers, not synthetic tools

`toxicflow harvest` starts 17 public MCP servers over stdio and saves the tools each reports via `tools/list`: 137 tools in total. The servers are filesystem, fetch, git, memory, time, github, slack, postgres, sqlite, brave-search, puppeteer, google-maps, sentry, everything, playwright, context7 and sequential-thinking. Credentials are dummies; listing tools never calls an upstream API. Results are in `data/tools/*.json` with their source URLs.

`data/labels.yaml` gives each tool its capabilities, with the reason written down. A tool that matches no rule is `unknown`. Flows that depend on an unknown tool are reported as **UNKNOWN**, never as safe.

The agent setups (`data/scenarios/*.yaml`) are written by hand. They list which servers and tools each agent mounts, who delegates to whom, which store instances are shared, and the tasks that must keep working.

## Graph model

```
(:Server)-[:EXPOSES]->(:Tool)-[:HAS_CAP {why}]->(:Capability)
(:Agent)-[:CAN_CALL {instance}]->(:Tool)
(:Agent)-[:DELEGATES_TO {returns: text|structured}]->(:Agent)
(:Task)-[:ASSIGNED_TO]->(:Agent),  (:Task)-[:NEEDS]->(:Tool)

derived influence edges (rebuilt after every change)
(:Agent)-[:INSTRUCTS]->(:Agent)          parent writes the child's instructions
(:Agent)-[:REPORTS_TO]->(:Agent)         child returns free text (returns = text only)
(:Agent)-[:WRITES_TO]->(:Store)-[:FEEDS]->(:Agent)   shared state via one server instance

memory
(:Remediation)-[:FIXES]->(:Finding)-[:ENTERS_AT|READS_AT|EXITS_AT]->(:Agent)
```

All Cypher is in [`src/toxicflow/queries.py`](src/toxicflow/queries.py), a fixed catalogue. The main query is `TOXIC_FLOWS`:

```cypher
MATCH (a1:Agent)-[:CAN_CALL]->(:Tool)-[:HAS_CAP]->(cu:Capability) WHERE cu.name IN $untrusted
MATCH p1 = (a1)-[:INSTRUCTS|REPORTS_TO|WRITES_TO|FEEDS*0..8]->(a2:Agent)
MATCH (a2)-[:CAN_CALL]->(:Tool)-[:HAS_CAP]->(cr:Capability) WHERE cr.name IN $private
MATCH p2 = (a2)-[:INSTRUCTS|REPORTS_TO|WRITES_TO|FEEDS*0..8]->(a3:Agent)
MATCH (a3)-[:CAN_CALL]->(:Tool)-[:HAS_CAP]->(cs:Capability) WHERE cs.name IN $sink
RETURN ...  -- entry, reader, exit agents + the witness paths
```

## What counts as a toxic flow (and what this does not model)

A flow is toxic when four conditions hold. The agents involved may coincide:
1. untrusted content enters at agent `a1`;
2. private data is read at agent `a2`;
3. both can reach a common agent `m` along influence edges, so one model has both in context;
4. `m` can reach an agent `a3` that holds an outbound tool.

The private read does **not** need to be steered. A legitimate read whose result meets injected text is enough. An earlier version of this project required the injection to reach the reader first. The `analytics` scenario showed that this missed real leaks, and the reference oracle and tests were updated with the fix.

Influence edges and their meaning:
- **`INSTRUCTS`**: a parent writes its child's task, so anything the parent has seen can shape the child.
- **`REPORTS_TO`**: a child returns free text to its parent. A delegation with `returns: structured` has no such edge. This assumes the child returns only schema-constrained values: IDs, counts, enums, booleans. If the schema includes the sensitive fields themselves, quarantine does not help, and that is on the person defining the schema.
- **`WRITES_TO` / `FEEDS`**: agents that mount the same server instance share state through it.

Labels are per tool, conservative, and written by hand with a reason each. Unlabelled tools are `unknown`. Static flows that rely on them are UNKNOWN, and the runtime gate fails closed on them.

Not modelled:
- argument-level permissions, for example a filesystem root that excludes `.env`;
- OAuth scopes;
- per-message content.

A reported path is evidence that the leak *can* happen, not proof that it will.

## How the repair works

Interventions: **quarantine** restricts a child's return to typed fields (ids, numbers, enums, booleans): data still flows back, natural-language instructions do not. **isolate** gives one agent its own instance of a shared store. **revoke** removes every tool with a capability. **cut** removes a delegation.

The cost model: quarantine 1, isolate 2, revoke 3, cut 4. The ranking is a judgement: keep the delegation but restrict what comes back, before splitting state, before removing tools, before removing a working relationship. The numbers are not measured business costs. Tasks are the constraint; cost only ranks safe options.

1. Each remaining flow yields the interventions that would break its path:
   - quarantine a delegation (structured results only);
   - isolate a shared store;
   - revoke a capability;
   - cut a delegation.
2. A hitting-set search tries combinations from cheapest upward. Each try runs on a **`GRAPH.COPY`** of the graph: apply the change, rebuild the influence edges, then re-run `TOXIC_FLOWS` and `TASK_STATUS`.
3. A repair is accepted only if the graph shows no flows left and no task broken.
4. `--apply` writes the change to the real graph, checks it again, and records `Finding` and `Remediation` nodes. It then exports the patched agent config (`data/scenarios/<name>.patched.yaml`).

**Exactness.** The search branches only on interventions that break a remaining flow's witness path, and stops at 4 actions; that is a heuristic restriction. `toxicflow/reference.py` therefore also enumerates the full intervention space. On every scenario both give the same minimum cost and the same set of minimum-cost repairs (`tests/test_expected.py`, `toxicflow eval`). This is checked on these scenarios, not proven in general.

**Task model.** A task "works" if its agent can still reach every needed tool, directly or by delegation, **and** every declared `needs_data` pair is still connected by data-carrying edges. For example, `standup-notes` needs coder's output to reach standup, so isolating the shared KB breaks it. This models whether the data a task needs can arrive; it does not verify that the task's output is correct.

Where the repair is enforced: in the graph (re-checked after apply), by the runtime gate (the gate's allowed tool lists and influence edges come from the repaired graph, so `replay --after-repair` shows the attack steps as impossible), and in the exported config. The patched config has not been deployed to a live Claude Code or MCP client installation; that last step is the user's.

## The agent (MCP)

`toxicflow mcp <scenario>` serves ten tools over MCP:
- `list_agents`, `agent_profile`, `tool_info`
- `one_hop_scan`, `find_toxic_flows`, `check_tasks`
- `simulate_repair`, `search_repairs`
- `propose_repair`, `recall`

Each tool runs fixed, parameterised Cypher. Agent, store and capability names are checked against the graph first, and errors go back to the model so it can correct itself. **No tool accepts Cypher, and no tool applies a change.**

`toxicflow investigate <scenario>` is an LLM agent (OpenAI Responses API) that connects to that server as an MCP client and chooses its own tools:
1. It checks memory with `recall`.
2. It compares the per-agent view with the multi-hop view.
3. It finds and simulates a repair.
4. It files a `Proposal` node.

Only a human applies the proposal, with `toxicflow approve`. The model's final answer is then checked: every `backticked` name must exist in the graph. If any doesn't, the graph's own result is shown instead.

A recorded run on `support` under the current model (`results/investigate_support.txt`):
- The agent made 29 MCP tool calls: `list_agents`, `recall` and `agent_profile` for each agent, `one_hop_scan`, `find_toxic_flows` ×2, `tool_info` ×5, `check_tasks`, `search_repairs` and `simulate_repair` ×9.
- It concluded that no repair removes every flow while keeping every task.
- The one containment proposal it tried was **rejected by the simulation guardrail** in `propose_repair`, and nothing was approved.

`results/agent_run_pre_p0/` keeps the two runs from before the model correction:
- One where the agent proposed and a human approved the old cost-3 repair, which the corrected model no longer considers safe.
- One where a validator bug (task ids not recognised) replaced the model's answer with the graph's own summary. The bug is now fixed.

**Approval is re-validated.** `approve` simulates the proposal against the graph's *current* state first; it only applies a change that still removes every flow and keeps every task. It re-verifies after applying and rolls back if verification fails. A rejected proposal is marked `rejected` and no remediation is recorded (`tests/test_approve.py`).

The security decisions (flows, repair validity, gate verdicts) come from the deterministic queries, never from the model. The name check only verifies that the names the model uses exist; it does not verify its prose.

## Runtime gate

`toxicflow gate <scenario> <agent> --session S` is an MCP proxy for one agent:
- It lists exactly the tools the graph says that agent may call.
- It forwards allowed calls to the real MCP servers: filesystem, git and memory run for real, and the memory server runs **one process and one storage file per store instance**, so `isolate` is real isolation there. GitHub, Slack, fetch and search use canned responses from `data/fixtures/`, because they need credentials.
- If a downstream call fails, the call is marked `failed` and does not count as a read.
- It records every call as a `(:Session)-[:HAS_CALL]->(:Call)` node.

Several agents' proxies share one session through FalkorDB, so the gate sees what happened across agents. That shared state is the Track 02 angle.

Before an outbound call, the gate asks the graph a single question. In this session, did some agent `x` read untrusted input and some agent `y` read private data (in either order), with `x ~> y ~> caller` on the current influence edges?
- If yes, the call is **blocked** and the path is returned.
- Private reads under untrusted influence are allowed but flagged `ALLOW_TAINTED`.
- An unlabelled tool is treated as worst case: possibly untrusted input, private read and outbound at once. Its call is `BLOCK_UNKNOWN` whenever untrusted input in the session could have steered the caller. With no untrusted input upstream it is allowed, because the history gives no reason to block it.

What the gate does and does not track: taint is per agent and per session (which agents read untrusted or private data, and the current influence edges between them), not per value or argument. It is conservative: once untrusted and private reads can meet upstream of a caller, every outbound call from that caller is blocked, whatever the arguments. Private data sent out with no untrusted input in the session is allowed by design (`standup` posting team notes), because the threat model is injection-driven exfiltration, not data-loss prevention.

What is executed and what is simulated: the gate's decisions are computed live from the graph on every call; filesystem, git and memory MCP servers run for real; GitHub, Slack, fetch and search return canned fixtures. The tool-call sequences come from scripts (`data/attacks/`, `data/expected.yaml`), not from an LLM being attacked. Tool arguments are never stored raw: the session log keeps each argument's name, type, length and a short hash.

`toxicflow replay` drives a scripted session (`data/attacks/`) through the same gate. A step marked `uses: n` carries data from step n. After a repair, the graph is asked whether that data can still reach the agent; if it can't, the step is shown as UNREACHABLE.

## Correctness

`tests/oracle.py` is a separate pure-Python implementation of the same flow semantics. The tests check that the Cypher results match it on every scenario. They also cover:
- the one-hop view missing what the multi-hop view finds;
- the shared-store path;
- unlabelled tools giving UNKNOWN;
- minimality and verification of the repair;
- simulation copies leaving the base graph untouched;
- gate behaviour: benign posts allowed, injection chains blocked with paths, shared-store chains blocked, read order not mattering, denied calls not counting, the same calls passing after repair, and unlabelled sinks failing closed (`tests/test_gate.py`).

- every scenario against hand-derived flows, cheapest repair cost and 13 runtime sequences, plus an exhaustive repair check and a single-permission fix that removes the risk but breaks work (`tests/test_expected.py`).

```bash
uv run pytest -q          # 79 tests (test_isolation.py needs npx for the real memory server)
uv run toxicflow eval     # ablation, repair exactness, runtime baselines -> results/EVAL.md
```

## Setup

```bash
docker compose up -d          # FalkorDB on :6390, browser on http://localhost:3390
uv sync
uv run toxicflow harvest      # optional: tool data is committed in data/tools/
uv run toxicflow scan acme --reload   # --reload discards repairs applied earlier to this scenario's graph
uv run toxicflow eval
```

The investigator needs `OPENAI_API_KEY` (optionally `OPENAI_MODEL`), either in `.env` or in a file named by `TOXICFLOW_ENV_FILE`.

Requires Docker, Python 3.12 and [uv](https://docs.astral.sh/uv/). Node.js is needed only for `harvest`.

## Status

Done:
- harvest of 17 real MCP servers (137 labelled tools), graph loading, one-hop vs multi-hop scan, UNKNOWN handling;
- repair search on graph copies; apply, verify, memory nodes, patched config;
- MCP server over the query catalogue; LLM investigator with human approval;
- runtime gate proxy and scripted replay;
- web UI;
- eight scenarios, including a negative control and a structured-return regression case, with hand-derived ground truth;
- `toxicflow eval`: per-agent vs. graph detection, exact repair check, runtime baselines;
- real-world check on 2,921 public agent setups, including a counterfactual fix and an explanation of the graph-only share;
- 79 tests, including a separate reference oracle, an exhaustive repair solver, approval re-validation and real store isolation.

Next:
- demo video;
- blog post.

## AI assistance disclosure

This project was built with an AI coding assistant (Claude Code). The author reviewed, tested and can explain every part: graph model, queries, search and labels.

## License

MIT
