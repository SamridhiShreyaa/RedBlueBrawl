"""Central Neo4j connection configuration — the single source of truth.

Connection settings used to be duplicated across ~7 files as inline
``os.getenv("NEO4J_URI", "bolt://localhost:7687")`` calls. This module reads
them from the environment once, with the same defaults, and exposes them via a
small immutable dataclass plus a ``get_driver()`` helper.

Environment variables (see ``.env.example``):
    NEO4J_URI       default ``bolt://localhost:7687``
    NEO4J_USER      default ``neo4j``
    NEO4J_PASSWORD  default ``changeme``

If ``python-dotenv`` is installed, a local ``.env`` file is loaded on import so
local development can keep credentials out of the shell. In CI or production the
real environment variables take precedence.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional, Tuple

# Load a local .env if present. Real environment variables still win because
# python-dotenv does not override already-set variables by default.
try:  # pragma: no cover - trivial import guard
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover - dotenv is optional
    pass


DEFAULT_URI = "bolt://localhost:7687"
DEFAULT_USER = "neo4j"
DEFAULT_PASSWORD = "changeme"


@dataclass(frozen=True)
class Neo4jConfig:
    """Immutable Neo4j connection settings."""

    uri: str = DEFAULT_URI
    user: str = DEFAULT_USER
    password: str = DEFAULT_PASSWORD

    @classmethod
    def from_env(cls) -> "Neo4jConfig":
        """Build config from environment variables, falling back to defaults."""
        return cls(
            uri=os.getenv("NEO4J_URI", DEFAULT_URI),
            user=os.getenv("NEO4J_USER", DEFAULT_USER),
            password=os.getenv("NEO4J_PASSWORD", DEFAULT_PASSWORD),
        )

    @property
    def auth(self) -> Tuple[str, str]:
        """``(user, password)`` tuple in the shape the neo4j driver expects."""
        return (self.user, self.password)


def get_config() -> Neo4jConfig:
    """Return the active Neo4j configuration read from the environment."""
    return Neo4jConfig.from_env()


def get_driver(config: Optional[Neo4jConfig] = None):
    """Create a Neo4j driver from ``config`` (or the environment if omitted)."""
    from neo4j import GraphDatabase

    cfg = config or get_config()
    return GraphDatabase.driver(cfg.uri, auth=cfg.auth)


# ---- risk scorer selection -----------------------------------------------
# Which risk scorer the generic pipeline uses. "signature" is the default and
# preserves current behaviour on the synthetic Neo4j dataset (which carries no
# trust-edge structure). "reachability" opts into the structural scorer and
# requires trust-edge data on the graph. This flips to "reachability" as the
# recommended default once real IAM ingestion with trust-policy data lands
# (Feature 9) -- a config change, not a re-architecture.
DEFAULT_RISK_SCORER_METHOD = "signature"
VALID_RISK_SCORER_METHODS = ("signature", "reachability")


def get_risk_scorer_method() -> str:
    """Active risk-scorer method from ``RISK_SCORER_METHOD`` (default 'signature')."""
    method = os.getenv("RISK_SCORER_METHOD", DEFAULT_RISK_SCORER_METHOD).strip().lower()
    if method not in VALID_RISK_SCORER_METHODS:
        raise ValueError(
            f"RISK_SCORER_METHOD must be one of {VALID_RISK_SCORER_METHODS}, "
            f"got {method!r}"
        )
    return method
