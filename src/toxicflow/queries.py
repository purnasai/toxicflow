"""The fixed Cypher catalogue. Nothing else in the project sends Cypher to FalkorDB,
and the LLM never writes Cypher: it can only pick one of these and pass parameters.

Graph model
-----------
(:Capability {name})
(:Server {id, source})-[:EXPOSES]->(:Tool {id, server, name, description})
(:Tool)-[:HAS_CAP {why}]->(:Capability)
(:Agent {id, purpose})-[:CAN_CALL {instance}]->(:Tool)
(:Agent)-[:DELEGATES_TO {returns: 'text'|'structured'}]->(:Agent)
(:Task {id})-[:ASSIGNED_TO]->(:Agent), (:Task)-[:NEEDS]->(:Tool)

Derived influence edges (rebuilt by REBUILD_* after every change):
(:Agent)-[:INSTRUCTS]->(:Agent)   parent writes the child's instructions
(:Agent)-[:REPORTS_TO]->(:Agent)  child returns free text to the parent (returns='text' only)
(:Agent)-[:WRITES_TO]->(:Store)-[:FEEDS]->(:Agent)  shared state through one server instance

Content an agent has seen can reach every agent downstream of it on influence edges.
A toxic flow needs untrusted content and private data to meet in one agent that can reach a sink.
"""

INFLUENCE = "INSTRUCTS|REPORTS_TO|WRITES_TO|FEEDS"
MAX_HOPS = 8

# ---------------------------------------------------------------- derived edges

CLEAR_DERIVED = """
MATCH ()-[e:INSTRUCTS|REPORTS_TO|WRITES_TO|FEEDS]->() DELETE e
"""

DROP_STORES = "MATCH (s:Store) DELETE s"

REBUILD_DELEGATION = """
MATCH (p:Agent)-[d:DELEGATES_TO]->(c:Agent)
MERGE (p)-[:INSTRUCTS]->(c)
WITH p, c, d WHERE d.returns = 'text'
MERGE (c)-[:REPORTS_TO]->(p)
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

# ---------------------------------------------------------------- analysis

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
MATCH (a2:Agent)-[:{INFLUENCE}*0..{MAX_HOPS}]->(m)
WITH DISTINCT a1, m, a2
WHERE size([(a2)-[:CAN_CALL]->(:Tool)-[:HAS_CAP]->(c:Capability) WHERE c.name IN $private | 1]) > 0
MATCH (m)-[:{INFLUENCE}*0..{MAX_HOPS}]->(a3:Agent)
WITH DISTINCT a1, m, a2, a3
WHERE size([(a3)-[:CAN_CALL]->(:Tool)-[:HAS_CAP]->(c:Capability) WHERE c.name IN $sink | 1]) > 0
RETURN a1.id AS entry, a2.id AS reader, a3.id AS exit, collect(m.id) AS meets
ORDER BY entry, reader, exit
"""

# Shortest influence path between two agents (the witness shown to people and used for repair).
WITNESS = f"""
MATCH p = (a:Agent {{id: $src}})-[:{INFLUENCE}*0..{MAX_HOPS}]->(b:Agent {{id: $dst}})
RETURN [n IN nodes(p) | n.id], [e IN relationships(p) | type(e)]
ORDER BY length(p)
LIMIT 1
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

QUARANTINE = """
MATCH (p:Agent {id: $parent})-[d:DELEGATES_TO]->(c:Agent {id: $child})
SET d.returns = 'structured'
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
