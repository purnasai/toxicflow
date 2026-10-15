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

# Toxic flow: untrusted content enters at a1, steers a2 into reading private data,
# and that data reaches a3, which can send it out. a1, a2, a3 may coincide.
# $untrusted / $private / $sink are lists so the same query also finds flows that
# rely on unlabelled tools (pass ['x', 'unknown']).
TOXIC_FLOWS = f"""
MATCH (a1:Agent)-[:CAN_CALL]->(u:Tool)-[:HAS_CAP]->(cu:Capability)
WHERE cu.name IN $untrusted
MATCH p1 = (a1)-[:{INFLUENCE}*0..{MAX_HOPS}]->(a2:Agent)
MATCH (a2)-[:CAN_CALL]->(r:Tool)-[:HAS_CAP]->(cr:Capability)
WHERE cr.name IN $private
MATCH p2 = (a2)-[:{INFLUENCE}*0..{MAX_HOPS}]->(a3:Agent)
MATCH (a3)-[:CAN_CALL]->(s:Tool)-[:HAS_CAP]->(cs:Capability)
WHERE cs.name IN $sink
WITH a1, a2, a3, u, r, s, p1, p2, length(p1) + length(p2) AS hops
ORDER BY hops
WITH a1, a2, a3,
     collect(DISTINCT u.id) AS sources,
     collect(DISTINCT r.id) AS readers,
     collect(DISTINCT s.id) AS sinks,
     head(collect([n IN nodes(p1) | n.id])) AS path_in,
     head(collect([n IN nodes(p2) | n.id])) AS path_out,
     head(collect([e IN relationships(p1) | type(e)])) AS rels_in,
     head(collect([e IN relationships(p2) | type(e)])) AS rels_out,
     min(hops) AS hops
RETURN a1.id AS entry, a2.id AS reader, a3.id AS exit,
       sources, readers, sinks, path_in, path_out, rels_in, rels_out, hops
ORDER BY hops, entry, reader, exit
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
