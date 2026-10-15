"""Read-only analysis over a loaded graph."""

from __future__ import annotations

from dataclasses import dataclass, field

from falkordb import Graph

from . import queries as Q

STRICT = {"untrusted": ["untrusted_input"], "private": ["private_read"], "sink": ["exfil_sink"]}
LOOSE = {k: v + ["unknown"] for k, v in STRICT.items()}


@dataclass
class Flow:
    entry: str
    reader: str
    exit: str
    meet: str
    sources: list[str]
    readers: list[str]
    sinks: list[str]
    path_in: list[str]
    path_data: list[str]
    path_out: list[str]
    rels_in: list[str]
    rels_data: list[str]
    rels_out: list[str]
    hops: int
    status: str = "TOXIC"  # TOXIC, or UNKNOWN when it depends on unlabelled tools
    via_unknown: list[str] = field(default_factory=list)

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.entry, self.reader, self.exit)

    def steps(self) -> list[tuple[str, str, str]]:
        """(from, relationship, to) for every hop on the witness path."""
        out = []
        for nodes, rels in ((self.path_in, self.rels_in), (self.path_data, self.rels_data), (self.path_out, self.rels_out)):
            out += [(nodes[i], rels[i], nodes[i + 1]) for i in range(len(rels))]
        return out

    def route(self) -> str:
        return f"untrusted {' -> '.join(self.path_in)} | private {' -> '.join(self.path_data)} | out {' -> '.join(self.path_out)}"

    def describe(self) -> str:
        return (
            f"{self.entry} reads untrusted input, {self.reader} reads private data, both reach {self.meet}, "
            f"{self.exit} sends it out  [{self.route()}]"
        )


def one_hop(g: Graph) -> dict[str, list[str]]:
    """What a per-agent scanner sees: each agent's own capabilities."""
    return {agent: sorted(c for c in caps if c) for agent, caps in g.ro_query(Q.AGENT_CAPS).result_set}


def one_hop_findings(g: Graph) -> list[str]:
    need = {"untrusted_input", "private_read", "exfil_sink"}
    return [a for a, caps in one_hop(g).items() if need <= set(caps)]


def _rows(g: Graph, params: dict) -> list[Flow]:
    witness_cache: dict[tuple[str, str], tuple[list[str], list[str]]] = {}

    def witness(src: str, dst: str) -> tuple[list[str], list[str]]:
        if (src, dst) not in witness_cache:
            nodes, rels = g.ro_query(Q.WITNESS, {"src": src, "dst": dst}).result_set[0]
            witness_cache[(src, dst)] = (nodes, rels)
        return witness_cache[(src, dst)]

    def tools(agent: str, caps: list[str]) -> list[str]:
        return sorted(g.ro_query(Q.TOOLS_WITH_CAPS, {"agent": agent, "caps": caps}).result_set[0][0])

    out = []
    for entry, reader, exit_, meets in g.ro_query(Q.TOXIC_FLOWS, params).result_set:
        def total(m: str) -> int:
            return sum(len(witness(a, b)[1]) for a, b in ((entry, m), (reader, m), (m, exit_)))

        m = min(sorted(set(meets)), key=total)
        (pin, rin), (pdata, rdata), (pout, rout) = witness(entry, m), witness(reader, m), witness(m, exit_)
        out.append(
            Flow(
                entry, reader, exit_, m,
                tools(entry, params["untrusted"]), tools(reader, params["private"]), tools(exit_, params["sink"]),
                pin, pdata, pout, rin, rdata, rout, total(m),
            )
        )
    return sorted(out, key=lambda f: (f.hops, f.key))


def flows(g: Graph, include_unknown: bool = True) -> list[Flow]:
    strict = _rows(g, STRICT)
    if not include_unknown:
        return strict
    seen = {f.key for f in strict}
    unknown_tools = set(unknown_tool_ids(g))
    extra = []
    for f in _rows(g, LOOSE):
        if f.key in seen:
            continue
        f.status = "UNKNOWN"
        f.via_unknown = sorted(unknown_tools & set(f.sources + f.readers + f.sinks))
        extra.append(f)
    return strict + extra


def unknown_tool_ids(g: Graph) -> list[str]:
    q = "MATCH (a:Agent)-[:CAN_CALL]->(t:Tool)-[:HAS_CAP]->(:Capability {name: 'unknown'}) RETURN DISTINCT t.id"
    return [r[0] for r in g.ro_query(q).result_set]


def broken_tasks(g: Graph) -> dict[str, list[str]]:
    return {task: missing for task, missing in g.ro_query(Q.TASK_STATUS).result_set if missing}
