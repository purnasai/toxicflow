import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from toxicflow.graph import connect, load, load_scenario_file  # noqa: E402


@pytest.fixture
def db():
    return connect()


@pytest.fixture
def loaded(db):
    """Load a scenario into a test-only graph; deleted afterwards."""
    made = []

    def _load(name: str):
        sc = load_scenario_file(name)
        g = load(db, sc, graph_name=f"test_{name}")
        made.append(g)
        return sc, g

    yield _load
    for g in made:
        g.delete()
