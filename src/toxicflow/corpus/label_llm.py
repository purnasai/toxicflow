"""LLM labels for MCP tools nobody has curated, plus a check of how far to trust them.

    uv run python -m toxicflow.corpus.label_llm validate   # label the 137 curated tools blind, compare
    uv run python -m toxicflow.corpus.label_llm corpus     # label unknown tools seen in the corpus

The model sees only the server name and tool name, the same information a corpus file gives.
Labels with low confidence are not stored, so those tools stay `unknown`.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict

from openai import OpenAI

from ..config import load_env, openai_model
from ..labels import DATA, load_tools

OUT = DATA / "corpus" / "llm_labels.json"
VALIDATION = DATA / "corpus" / "label_validation.json"
CAPS = ["untrusted_input", "private_read", "exfil_sink", "store_read", "store_write"]

PROMPT = """You label tools exposed by MCP servers for a data-flow security analysis.
For each tool, given only its server name and tool name, return the capabilities it has:
- untrusted_input: returns content a third party can author (web pages, search results, issues, emails, chat messages, tickets, documents others edit)
- private_read: returns data that should not leave the organisation (files, databases, internal docs, messages, customer records, secrets, repos)
- exfil_sink: can send data outside the trust boundary (posts, emails, creates issues/comments/pages, HTTP requests, search queries to external APIs, uploads)
- store_read / store_write: reads / writes a store other agents may share (memory, notes, files, databases)
A tool can have several capabilities or none (pure computation, time, local reasoning).
Set confidence to low when the name does not tell you enough. Never guess wildly."""

SCHEMA = {
    "type": "object",
    "properties": {
        "labels": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "key": {"type": "string"},
                    "caps": {"type": "array", "items": {"type": "string", "enum": CAPS}},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                },
                "required": ["key", "caps", "confidence"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["labels"],
    "additionalProperties": False,
}


def label(keys: list[str], batch: int = 60) -> dict[str, dict]:
    load_env()
    client = OpenAI()
    out: dict[str, dict] = {}
    for i in range(0, len(keys), batch):
        chunk = keys[i : i + batch]
        listing = "\n".join(f"- key: {k}   (server: {k.split('::')[0]}, tool: {k.split('::')[1]})" for k in chunk)
        resp = client.responses.create(
            model=openai_model(),
            instructions=PROMPT,
            input=f"Label these tools. Return one entry per key, keys copied exactly.\n{listing}",
            text={"format": {"type": "json_schema", "name": "labels", "schema": SCHEMA, "strict": True}},
        )
        for item in json.loads(resp.output_text)["labels"]:
            if item["key"] in chunk:
                out[item["key"]] = {"caps": sorted(set(item["caps"])), "confidence": item["confidence"]}
        print(f"  labelled {min(i + batch, len(keys))}/{len(keys)}", flush=True)
    return out


def validate() -> dict:
    curated = load_tools()
    gold = {f"{t.server}::{t.name}": {c for c in t.caps if c in CAPS} for t in curated.values() if "unknown" not in t.caps}
    pred_raw = label(sorted(gold))
    report = {"tools": len(gold), "per_capability": {}, "confidence": defaultdict(int)}
    for conf in ("high", "medium", "low"):
        report["confidence"][conf] = sum(p["confidence"] == conf for p in pred_raw.values())
    kept = {k: set(v["caps"]) for k, v in pred_raw.items() if v["confidence"] != "low"}
    for cap in CAPS:
        tp = sum(cap in kept[k] and cap in gold[k] for k in kept)
        fp = sum(cap in kept[k] and cap not in gold[k] for k in kept)
        fn = sum(cap not in kept[k] and cap in gold[k] for k in kept)
        report["per_capability"][cap] = {
            "precision": round(tp / (tp + fp), 3) if tp + fp else None,
            "recall": round(tp / (tp + fn), 3) if tp + fn else None,
            "tp": tp, "fp": fp, "fn": fn,
        }
    report["exact_match"] = round(sum(kept[k] == gold[k] for k in kept) / len(kept), 3) if kept else None
    report["kept_after_dropping_low"] = len(kept)
    report["disagreements"] = [
        {"key": k, "llm": sorted(kept[k]), "curated": sorted(gold[k])} for k in sorted(kept) if kept[k] != gold[k]
    ]
    report["confidence"] = dict(report["confidence"])
    VALIDATION.write_text(json.dumps(report, indent=2))
    return report


def corpus_unknowns() -> list[str]:
    from .model import Resolver, build

    r = Resolver({})
    keys = set()
    for d in sorted((DATA / "corpus" / "raw").iterdir()):
        pm = build(d, "configured", r)
        for t in pm.tools.values():
            if t.source == "unknown" and t.id.startswith("mcp.") and t.name != "*":
                keys.add(f"{pm.servers.get(t.server, t.server)}::{t.name}")
    return sorted(keys)


def label_corpus() -> None:
    existing = json.loads(OUT.read_text()) if OUT.exists() else {}
    keys = [k for k in corpus_unknowns() if k not in existing]
    print(f"{len(keys)} new tools to label", flush=True)
    raw = label(keys)
    # Store labels were unreliable in validation (precision ~0.4), so only the three flow
    # capabilities are taken from the model.
    triad = ("untrusted_input", "private_read", "exfil_sink")
    existing.update({k: [c for c in v["caps"] if c in triad] or ["none"] for k, v in raw.items() if v["confidence"] != "low"})
    OUT.write_text(json.dumps(existing, indent=1, sort_keys=True))
    print(f"stored {len(existing)} labels; {sum(v['confidence'] == 'low' for v in raw.values())} left unknown (low confidence)")


if __name__ == "__main__":
    {"validate": lambda: print(json.dumps({k: v for k, v in validate().items() if k != 'disagreements'}, indent=1)),
     "corpus": label_corpus}[sys.argv[1]]()
