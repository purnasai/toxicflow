"""Collect real, public Claude Code agent setups from GitHub.

A setup is one repository: its subagent files (.claude/agents/**/*.md) and its project MCP
config (.mcp.json). Search goes through `gh api` (GitHub code search, 10 requests/minute,
1,000 results per query, so the query is split by file size). Files are then downloaded from
raw.githubusercontent.com. Everything lands in data/corpus/raw/ (git-ignored: we analyse
other people's files but do not redistribute them) and data/corpus/repos.jsonl.

    uv run python -m toxicflow.corpus.crawl --max-repos 3000
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..labels import DATA

CORPUS = DATA / "corpus"
RAW = CORPUS / "raw"
HITS = CORPUS / "search_hits.jsonl"
REPOS = CORPUS / "repos.jsonl"
QUERY = 'path:.claude/agents "tools:"'
SEARCH_PAUSE = 6.5  # code search allows 10 requests per minute


def gh(path: str, **params) -> dict | list:
    args = ["gh", "api", "-X", "GET", path]
    for k, v in params.items():
        args += ["-f", f"{k}={v}"]
    for attempt in range(6):
        p = subprocess.run(args, capture_output=True, text=True)
        if p.returncode == 0:
            return json.loads(p.stdout)
        err = p.stderr + p.stdout
        if "rate limit" in err.lower() or "secondary" in err.lower() or "403" in err:
            time.sleep(30 * (attempt + 1))
            continue
        if "404" in err or "Not Found" in err:
            return {}
        time.sleep(3)
    raise RuntimeError(f"gh api failed: {path} {params}: {err[:300]}")


def search_count(q: str) -> int:
    time.sleep(SEARCH_PAUSE)
    return gh("search/code", q=q, per_page=1).get("total_count", 0)


def partitions(lo: int = 0, hi: int = 60000):
    """Split by file size until each query has at most 1,000 results; yield each as found."""
    todo = [(lo, hi)]
    while todo:
        a, b = todo.pop(0)
        q = f"{QUERY} size:{a}..{b}"
        n = search_count(q)
        print(f"  size {a}..{b}: {n}", flush=True)
        if n <= 1000 or b - a <= 20:
            if n:
                yield q
        else:
            mid = (a + b) // 2
            todo = [(a, mid), (mid + 1, b)] + todo


def collect_hits(max_repos: int) -> set[str]:
    seen_paths = set()
    repos: set[str] = set()
    if HITS.exists():
        for line in HITS.read_text().splitlines():
            h = json.loads(line)
            seen_paths.add((h["repo"], h["path"]))
            repos.add(h["repo"])
    if len(repos) >= max_repos:
        return repos
    with HITS.open("a") as f:
        for q in partitions():
            for page in range(1, 11):
                time.sleep(SEARCH_PAUSE)
                items = gh("search/code", q=q, per_page=100, page=page).get("items", [])
                for it in items:
                    repo = it["repository"]
                    if repo.get("fork"):
                        continue
                    key = (repo["full_name"], it["path"])
                    if key in seen_paths:
                        continue
                    seen_paths.add(key)
                    repos.add(repo["full_name"])
                    f.write(json.dumps({"repo": repo["full_name"], "path": it["path"]}) + "\n")
                print(f"  {q.split('size:')[1]} p{page}: {len(items)} items, {len(repos)} repos", flush=True)
                if len(items) < 100 or len(repos) >= max_repos:
                    break
            if len(repos) >= max_repos:
                break
    return repos


def raw_get(repo: str, path: str) -> str | None:
    url = f"https://raw.githubusercontent.com/{repo}/HEAD/{path}"
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=20) as r:
                return r.read(400_000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            time.sleep(2 * (attempt + 1))
        except Exception:
            time.sleep(2 * (attempt + 1))
    return None


def list_agent_files(repo: str) -> list[str]:
    """All .md files under .claude/agents (one level of subfolders), via the contents API."""
    out = []
    top = gh(f"repos/{repo}/contents/.claude/agents")
    for entry in top if isinstance(top, list) else []:
        if entry["type"] == "file" and entry["name"].endswith(".md"):
            out.append(entry["path"])
        elif entry["type"] == "dir":
            sub = gh(f"repos/{repo}/contents/{entry['path']}")
            out += [e["path"] for e in (sub if isinstance(sub, list) else []) if e["type"] == "file" and e["name"].endswith(".md")]
    return out


def fetch_repo(repo: str) -> dict:
    d = RAW / repo.replace("/", "__")
    d.mkdir(parents=True, exist_ok=True)
    files = list_agent_files(repo)
    saved = []
    for path in files[:80]:
        text = raw_get(repo, path)
        if text is not None:
            (d / Path(path).name).write_text(text)
            saved.append(path)
    mcp = raw_get(repo, ".mcp.json")
    if mcp is not None:
        (d / "_mcp.json").write_text(mcp)
    return {"repo": repo, "agent_files": saved, "has_mcp_json": mcp is not None, "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-repos", type=int, default=3000)
    ap.add_argument("--workers", type=int, default=12)
    args = ap.parse_args()
    CORPUS.mkdir(parents=True, exist_ok=True)

    repos = sorted(collect_hits(args.max_repos))[: args.max_repos]
    done = set()
    if REPOS.exists():
        done = {json.loads(line)["repo"] for line in REPOS.read_text().splitlines()}
    todo = [r for r in repos if r not in done]
    print(f"{len(repos)} repos found, {len(todo)} to fetch", flush=True)
    with REPOS.open("a") as f, ThreadPoolExecutor(args.workers) as pool:
        for i, rec in enumerate(pool.map(fetch_repo, todo), 1):
            f.write(json.dumps(rec) + "\n")
            f.flush()
            if i % 100 == 0:
                print(f"  fetched {i}/{len(todo)}", flush=True)


if __name__ == "__main__":
    main()
