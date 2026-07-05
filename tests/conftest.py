"""Shared pytest fixtures.

Provides a Neo4j-backed builder that:
  * uses the central connection config (src.config, env-driven),
  * skips the test when Neo4j is unreachable (local dev without a database),
  * seeds the committed sample dataset when the database is empty, so graph
    tests have data to assert on when run against a fresh service container
    (e.g. the Neo4j service in CI).
"""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.graph.builder import IAMGraphBuilder  # noqa: E402

DATASET_PATH = REPO_ROOT / "data" / "iam_dataset.json"


@pytest.fixture
def neo4j_builder():
    """Yield a connected IAMGraphBuilder, seeding sample data if empty.

    Skips (rather than fails) when no Neo4j is reachable, so the suite stays
    green on machines without a database while still exercising these tests
    against the CI service container.
    """
    builder = IAMGraphBuilder.from_env()
    try:
        stats = builder.get_graph_stats()
    except Exception as exc:
        builder.close()
        pytest.skip(f"Neo4j is not reachable: {exc}")

    if stats.get("total_nodes", 0) == 0:
        if not DATASET_PATH.exists():
            builder.close()
            pytest.skip(f"Sample dataset not found at {DATASET_PATH}")
        builder.load_data(str(DATASET_PATH))

    try:
        yield builder
    finally:
        builder.close()
