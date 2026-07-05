"""Tests for the central Neo4j configuration module."""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.config import (
    DEFAULT_PASSWORD,
    DEFAULT_URI,
    DEFAULT_USER,
    Neo4jConfig,
    get_config,
)
from src.graph.builder import IAMGraphBuilder

ENV_VARS = ("NEO4J_URI", "NEO4J_USER", "NEO4J_PASSWORD")


def test_defaults_when_env_unset(monkeypatch):
    for var in ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    cfg = get_config()
    assert cfg.uri == DEFAULT_URI == "bolt://localhost:7687"
    assert cfg.user == DEFAULT_USER == "neo4j"
    assert cfg.password == DEFAULT_PASSWORD == "changeme"
    assert cfg.auth == ("neo4j", "changeme")


def test_env_overrides(monkeypatch):
    monkeypatch.setenv("NEO4J_URI", "bolt://db.internal:7687")
    monkeypatch.setenv("NEO4J_USER", "alice")
    monkeypatch.setenv("NEO4J_PASSWORD", "s3cret-pass")
    cfg = get_config()
    assert cfg.uri == "bolt://db.internal:7687"
    assert cfg.user == "alice"
    assert cfg.password == "s3cret-pass"
    assert cfg.auth == ("alice", "s3cret-pass")


def test_config_is_immutable():
    cfg = Neo4jConfig()
    import dataclasses

    try:
        cfg.uri = "bolt://elsewhere:7687"  # type: ignore[misc]
    except dataclasses.FrozenInstanceError:
        return
    raise AssertionError("Neo4jConfig should be frozen/immutable")


def test_builder_from_config_uses_config_without_connecting():
    # Driver construction is lazy (no network I/O until a session runs), so
    # this verifies wiring without needing a live database.
    cfg = Neo4jConfig(uri="bolt://localhost:7687", user="neo4j", password="pw")
    builder = IAMGraphBuilder.from_config(cfg)
    try:
        assert builder.driver is not None
    finally:
        builder.close()
