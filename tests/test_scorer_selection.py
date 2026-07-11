"""Tests for configurable risk-scorer selection (make_risk_scorer + config)."""

import sys
from pathlib import Path

import networkx as nx
import pytest

repo_root = str(Path(__file__).parent.parent)
sys.path.insert(0, repo_root)

from src.config import get_risk_scorer_method
from src.causal.risk_scorer import (
    ReachabilityRiskScorer,
    SignatureCounterfactualScorer,
    make_risk_scorer,
)

ENV_VAR = "RISK_SCORER_METHOD"


def _no_trust_graph() -> nx.DiGraph:
    """A graph with no trust-edge metadata (like the synthetic Neo4j dataset)."""
    G = nx.DiGraph()
    G.add_node("u", label="User", username="u")
    G.add_node("r", label="Role", name="r")
    G.add_node("p", label="Permission", action="s3:GetObject", is_sensitive=False)
    G.add_edge("u", "r", relation="HAS_ROLE")
    G.add_edge("r", "p", relation="GRANTS")
    return G


def _trust_graph() -> nx.DiGraph:
    """A graph carrying trust-edge metadata (an assume-path to a sensitive target)."""
    G = _no_trust_graph()
    G.add_node("r2", label="Role", name="r2")
    G.add_node("p_enable", label="Permission", action="iam:SwapRoleCredentials",
               is_sensitive=True)
    G.add_node("p_target", label="Permission", action="iam:CreateUser",
               is_sensitive=True)
    G.add_edge("r", "p_enable", relation="GRANTS")
    G.add_edge("r2", "p_target", relation="GRANTS")
    G.graph["trust_edges"] = [{"src": "r", "dst": "r2", "enabling_perm": "p_enable"}]
    return G


# -- explicit method argument ---------------------------------------------

def test_explicit_signature_returns_signature_scorer():
    scorer = make_risk_scorer(_no_trust_graph(), method="signature")
    assert isinstance(scorer, SignatureCounterfactualScorer)


def test_explicit_reachability_with_trust_returns_reachability_scorer():
    scorer = make_risk_scorer(_trust_graph(), method="reachability")
    assert isinstance(scorer, ReachabilityRiskScorer)


def test_reachability_without_trust_edges_raises_loudly():
    with pytest.raises(ValueError, match="trust-edge data"):
        make_risk_scorer(_no_trust_graph(), method="reachability")


def test_unknown_method_raises():
    with pytest.raises(ValueError, match="Unknown risk scorer method"):
        make_risk_scorer(_no_trust_graph(), method="bogus")


# -- default / env-driven selection ---------------------------------------

def test_default_is_signature_when_env_unset(monkeypatch):
    monkeypatch.delenv(ENV_VAR, raising=False)
    scorer = make_risk_scorer(_no_trust_graph())
    assert isinstance(scorer, SignatureCounterfactualScorer)


def test_env_var_selects_reachability(monkeypatch):
    monkeypatch.setenv(ENV_VAR, "reachability")
    assert get_risk_scorer_method() == "reachability"
    scorer = make_risk_scorer(_trust_graph())
    assert isinstance(scorer, ReachabilityRiskScorer)


def test_env_reachability_without_trust_still_fails_loudly(monkeypatch):
    monkeypatch.setenv(ENV_VAR, "reachability")
    with pytest.raises(ValueError, match="trust-edge data"):
        make_risk_scorer(_no_trust_graph())


def test_env_default_stays_signature_even_with_trust_data(monkeypatch):
    # Until Feature 9 flips the default, an unset env stays "signature"
    # regardless of whether the graph could support reachability.
    monkeypatch.delenv(ENV_VAR, raising=False)
    scorer = make_risk_scorer(_trust_graph())
    assert isinstance(scorer, SignatureCounterfactualScorer)


def test_invalid_env_value_raises(monkeypatch):
    monkeypatch.setenv(ENV_VAR, "nonsense")
    with pytest.raises(ValueError, match="RISK_SCORER_METHOD must be one of"):
        get_risk_scorer_method()
