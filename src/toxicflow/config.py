"""Environment loading. Values already set in the process environment win; then the
project .env; then the file named by TOXICFLOW_ENV_FILE (used for the OpenAI key)."""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_loaded = False


def _read_env(path: Path) -> dict[str, str]:
    out = {}
    if not path.is_file():
        return out
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def load_env() -> None:
    global _loaded
    if _loaded:
        return
    local = _read_env(ROOT / ".env")
    extra_path = os.environ.get("TOXICFLOW_ENV_FILE") or local.get("TOXICFLOW_ENV_FILE")
    extra = _read_env(Path(extra_path).expanduser()) if extra_path else {}
    for source in (local, extra):
        for k, v in source.items():
            if v and not os.environ.get(k):
                os.environ[k] = v
    _loaded = True


def openai_model() -> str:
    load_env()
    return os.environ.get("TOXICFLOW_MODEL") or os.environ.get("OPENAI_MODEL") or "gpt-5-mini"
