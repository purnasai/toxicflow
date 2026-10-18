"""The fixed Cypher catalogue. Nothing else in the project sends Cypher to FalkorDB,
and the LLM never writes Cypher: it can only pick one of these and pass parameters.

Graph model
-----------
(:Capability {name})
(:Server {id, source})-[:EXPOSES]->(:Tool {id, server, name, description})
(:Tool)-[:HAS_CAP {why}]->(:Capability)
(:Agent {id, purpose})-[:CAN_CALL {instance}]->(:Tool)
(:Agent)-[:DELEGATES_TO {returns: 'text'|'structured', channel: 'text'|'data'|'none'}]->(:Agent)
(:Task {id, needs_data})-[:ASSIGNED_TO]->(:Agent), (:Task)-[:NEEDS]->(:Tool)

`channel` is what the child's result can carry back, derived from the declared return fields:
  text  free text (or a structured return with a string field, or with no declared fields): instructions + data
  data  only ids / numbers / enums / booleans: data, but no natural-language instructions
  none  only enums / booleans: neither
ToxicFlow does not enforce these schemas; 'data' and 'none' are assumptions about the deployment.

Derived edges (rebuilt by REBUILD_* after every change):
(:Agent)-[:INSTRUCTS]->(:Agent)     parent writes the child's instructions (carries instructions + data)
(:Agent)-[:REPORTS_TO]->(:Agent)    child returns free text (channel 'text'; instructions + data)
(:Agent)-[:RETURNS_DATA]->(:Agent)  child returns typed fields (channel 'data'; data only)
(:Agent)-[:WRITES_TO]->(:Store)-[:FEEDS]->(:Agent)  shared state through one server instance (instructions + data)

Untrusted content steers an agent only along instruction-carrying edges; private data travels along
every data-carrying edge. A toxic flow needs the two to meet in one agent that can get data to a sink.
"""

INFLUENCE = "INSTRUCTS|REPORTS_TO|WRITES_TO|FEEDS"          # can carry instructions (and data)
DATAFLOW = "INSTRUCTS|REPORTS_TO|RETURNS_DATA|WRITES_TO|FEEDS"  # can carry data
MAX_HOPS = 8

# ---------------------------------------------------------------- derived edges

CLEAR_DERIVED = """
MATCH ()-[e:INSTRUCTS|REPORTS_TO|RETURNS_DATA|WRITES_TO|FEEDS|INFLUENCES|CARRIES]->() DELETE e
"""

DROP_STORES = "MATCH (s:Store) DELETE s"

REBUILD_DELEGATION = """
MATCH (p:Agent)-[d:DELEGATES_TO]->(c:Agent)
MERGE (p)-[:INSTRUCTS]->(c)
WITH p, c, d WHERE d.channel = 'text'
MERGE (c)-[:REPORTS_TO]->(p)
"""

REBUILD_DATA_RETURNS = """
MATCH (p:Agent)-[d:DELEGATES_TO {channel: 'data'}]->(c:Agent)
MERGE (c)-[:RETURNS_DATA]->(p)
"""

REBUILD_STORE_WRITES = """
MATCH (a:Agent)-[c:CAN_CALL]->(t:Tool)-[:HAS_CAP]->(:Capability {name: 'store_write'})
MERGE (s:Store {id: t.server + '/' + c.instance})
MERGE (a)-[:WRITES_TO]->(s)
"""

REBUILD_STORE_READS = """
MATCH (a:Agent)-[c:CAN_CALL]->(t:Tool)-[:HAS_CAP]->(:Capability {name: 'store_read'})
MERGE (s:Store {id: t.server + '/' + c.instance})
MERGE (s)-[:FEEDS]->(a)
"""

# One untyped copy of every influence edge, so algo.bfs can follow all of them at once.
REBUILD_INFLUENCES = """
MATCH (x)-[:INSTRUCTS|REPORTS_TO|WRITES_TO|FEEDS]->(y)
MERGE (x)-[:INFLUENCES]->(y)
"""

REBUILD_CARRIES = """
MATCH (x)-[:INSTRUCTS|REPORTS_TO|RETURNS_DATA|WRITES_TO|FEEDS]->(y)
MERGE (x)-[:CARRIES]->(y)
"""

# ---------------------------------------------------------------- analysis

# Every agent's reach over influence edges via FalkorDB's BFS (stores are traversed, only
# agents are returned). Agents with no outgoing edges yield no row; callers add self-reach.
REACH = """
MATCH (x:Agent)
CALL algo.bfs(x, $depth, $rel) YIELD nodes
RETURN x.id, [n IN nodes WHERE n:Agent | n.id]
"""

# Baseline a per-agent scanner would give: capabilities each agent holds directly.
AGENT_CAPS = """
MATCH (a:Agent)
OPTIONAL MATCH (a)-[:CAN_CALL]->(t:Tool)-[:HAS_CAP]->(c:Capability)
RETURN a.id AS agent, collect(DISTINCT c.name) AS caps
ORDER BY agent
"""

# Toxic flow: untrusted content enters at a1, private data is read at a2, both reach a
# meeting agent m (the model holding both in context), and m can reach a3, which can send
# data out. The private read does not need to be steered: a legitimate read whose result
# meets injected instructions is enough. Any of a1, a2, m, a3 may coincide.
# $untrusted / $private / $sink are lists so the same query also finds flows that
# rely on unlabelled tools (pass ['x', 'unknown']).
TOXIC_FLOWS = f"""
MATCH (a1:Agent)-[:CAN_CALL]->(:Tool)-[:HAS_CAP]->(c1:Capability)
WHERE c1.name IN $untrusted
WITH DISTINCT a1
MATCH (a1)-[:{INFLUENCE}*0..{MAX_HOPS}]->(m:Agent)
WITH DISTINCT a1, m
MATCH (a2:Agent)-[:{DATAFLOW}*0..{MAX_HOPS}]->(m)
WITH DISTINCT a1, m, a2
WHERE size([(a2)-[:CAN_CALL]->(:Tool)-[:HAS_CAP]->(c:Capability) WHERE c.name IN $private | 1]) > 0
MATCH (m)-[:{DATAFLOW}*0..{MAX_HOPS}]->(a3:Agent)
WITH DISTINCT a1, m, a2, a3
WHERE size([(a3)-[:CAN_CALL]->(:Tool)-[:HAS_CAP]->(c:Capability) WHERE c.name IN $sink | 1]) > 0
RETURN a1.id AS entry, a2.id AS reader, a3.id AS exit, collect(m.id) AS meets
ORDER BY entry, reader, exit
"""

# Shortest path between two agents (the witness shown to people and used for repair):
# WITNESS over instruction-carrying edges (untrusted route), WITNESS_DATA over data-carrying edges.
WITNESS = f"""
MATCH p = (a:Agent {{id: $src}})-[:{INFLUENCE}*0..{MAX_HOPS}]->(b:Agent {{id: $dst}})
RETURN [n IN nodes(p) | n.id], [e IN relationships(p) | type(e)]
ORDER BY length(p)
LIMIT 1
"""

WITNESS_DATA = f"""
MATCH p = (a:Agent {{id: $src}})-[:{DATAFLOW}*0..{MAX_HOPS}]->(b:Agent {{id: $dst}})
RETURN [n IN nodes(p) | n.id], [e IN relationships(p) | type(e)]
ORDER BY length(p)
LIMIT 1
"""

# Output-level task requirements: data produced by one agent must still reach another.
TASK_DATA = f"""
MATCH (k:Task) WHERE k.needs_data IS NOT NULL
UNWIND k.needs_data AS pair
WITH k, pair, split(pair, '>') AS ends
OPTIONAL MATCH p = (:Agent {{id: ends[0]}})-[:{DATAFLOW}*0..{MAX_HOPS}]->(:Agent {{id: ends[1]}})
WITH k, pair, count(p) > 0 AS ok
WHERE NOT ok
RETURN k.id, collect('data ' + pair)
"""

# Tools an agent holds for a set of capabilities.
TOOLS_WITH_CAPS = """
MATCH (:Agent {id: $agent})-[:CAN_CALL]->(t:Tool)-[:HAS_CAP]->(c:Capability)
WHERE c.name IN $caps
RETURN collect(DISTINCT t.id)
"""

# A task works if its assigned agent can reach each needed tool itself or by delegating.
TASK_STATUS = """
MATCH (k:Task)-[:ASSIGNED_TO]->(a:Agent), (k)-[:NEEDS]->(t:Tool)
OPTIONAL MATCH p = (a)-[:INSTRUCTS*0..4]->(x:Agent)-[:CAN_CALL]->(t)
WITH k, t, count(p) > 0 AS ok
RETURN k.id AS task, collect(CASE WHEN ok THEN null ELSE t.id END) AS missing
ORDER BY task
"""

TOOL_INFO = """
MATCH (t:Tool {id: $tool})-[h:HAS_CAP]->(c:Capability)
RETURN t.id AS tool, t.description AS description, collect(c.name) AS caps, head(collect(h.why)) AS why
"""

AGENT_INFO = """
MATCH (a:Agent {id: $agent})
OPTIONAL MATCH (a)-[c:CAN_CALL]->(t:Tool)
RETURN a.id AS agent, a.purpose AS purpose, collect(t.id) AS tools
"""

# ---------------------------------------------------------------- interventions

REVOKE_CAP = """
MATCH (a:Agent {id: $agent})-[c:CAN_CALL]->(t:Tool)-[:HAS_CAP]->(:Capability {name: $cap})
DELETE c
RETURN count(c) AS removed
"""

# Restrict the child's result to typed fields (ids, numbers, enums, booleans): data still flows
# back, natural-language instructions do not. Needs schema enforcement outside ToxicFlow.
QUARANTINE = """
MATCH (p:Agent {id: $parent})-[d:DELEGATES_TO]->(c:Agent {id: $child})
SET d.returns = 'structured', d.channel = 'data'
RETURN count(d) AS changed
"""

CUT_DELEGATION = """
MATCH (p:Agent {id: $parent})-[d:DELEGATES_TO]->(c:Agent {id: $child})
DELETE d
RETURN count(d) AS removed
"""

ISOLATE_STORE = """
MATCH (a:Agent {id: $agent})-[c:CAN_CALL]->(t:Tool)
WHERE t.server + '/' + c.instance = $store
SET c.instance = c.instance + '~' + $agent
RETURN count(c) AS changed
"""
