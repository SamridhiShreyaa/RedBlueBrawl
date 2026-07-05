"""Counterfactual correctness tests for the attack-path risk scorer."""

import sys
from pathlib import Path

import networkx as nx

repo_root = str(Path(__file__).parent.parent)
sys.path.insert(0, repo_root)

from src.causal.risk_scorer import (
    CounterfactualRiskScorer,
    RiskLevel,
    count_attack_paths,
    enumerate_route_edges,
)


def build_known_graph() -> nx.DiGraph:
    """A tiny graph with one clear escalation route and benign padding.

    u1 -> r_pivot -(sts:AssumeRole)-> can pivot to r_admin -> iam:CreateUser
    u2 -> r_benign -> s3:GetObject (no escalation)

    Critical grants: r_pivot->sts (enables the pivot) and r_admin->iam:CreateUser
    (the escalation payload). Benign grants: the s3:GetObject perms.
    """
    G = nx.DiGraph()

    G.add_node("u1", label="User", username="u1")
    G.add_node("u2", label="User", username="u2")

    G.add_node("r_pivot", label="Role", name="r_pivot")
    G.add_node("r_admin", label="Role", name="r_admin")
    G.add_node("r_benign", label="Role", name="r_benign")

    G.add_node("p_sts", label="Permission", action="sts:AssumeRole", is_sensitive=True)
    G.add_node("p_admin", label="Permission", action="iam:CreateUser", is_sensitive=True)
    G.add_node("p_s3a", label="Permission", action="s3:GetObject", is_sensitive=False)
    G.add_node("p_s3b", label="Permission", action="s3:GetObject", is_sensitive=False)

    G.add_edge("u1", "r_pivot", relation="HAS_ROLE")
    G.add_edge("r_pivot", "p_sts", relation="GRANTS")

    G.add_edge("r_admin", "p_admin", relation="GRANTS")
    G.add_edge("r_admin", "p_s3a", relation="GRANTS")  # benign perm on admin role

    G.add_edge("u2", "r_benign", relation="HAS_ROLE")
    G.add_edge("r_benign", "p_s3b", relation="GRANTS")

    return G


CRITICAL_EDGES = [("r_pivot", "p_sts"), ("r_admin", "p_admin")]
BENIGN_EDGES = [("r_benign", "p_s3b"), ("r_admin", "p_s3a")]


def test_graph_has_reachable_routes():
    G = build_known_graph()
    assert count_attack_paths(G) > 0


def test_removing_critical_edge_drops_route_count():
    G = build_known_graph()
    base = count_attack_paths(G)
    for edge in CRITICAL_EDGES:
        G2 = G.copy()
        G2.remove_edge(*edge)
        after = count_attack_paths(G2)
        assert after < base, f"removing critical {edge} should drop routes ({after} !< {base})"


def test_removing_benign_edge_does_not_change_route_count():
    G = build_known_graph()
    base = count_attack_paths(G)
    for edge in BENIGN_EDGES:
        G2 = G.copy()
        G2.remove_edge(*edge)
        after = count_attack_paths(G2)
        assert after == base, f"removing benign {edge} should not change routes ({after} != {base})"


def test_edge_credit_equals_recomputed_counterfactual():
    """The fast participation count must equal actual recomputation for every edge."""
    G = build_known_graph()
    edge_credit, base = enumerate_route_edges(G)
    for u, v in list(G.edges()):
        G2 = G.copy()
        G2.remove_edge(u, v)
        recomputed = base - count_attack_paths(G2)
        assert edge_credit.get((u, v), 0) == recomputed, (
            f"edge {(u, v)}: credit {edge_credit.get((u, v), 0)} != recomputed {recomputed}"
        )


def test_scorer_ranks_critical_above_benign():
    G = build_known_graph()
    scorer = CounterfactualRiskScorer(G)

    sts = scorer.score_permission_risk("p_sts")
    admin = scorer.score_permission_risk("p_admin")
    s3a = scorer.score_permission_risk("p_s3a")
    s3b = scorer.score_permission_risk("p_s3b")

    # Critical escalation perms break routes; benign perms break none.
    assert sts.routes_broken > 0
    assert admin.routes_broken > 0
    assert s3a.routes_broken == 0
    assert s3b.routes_broken == 0

    assert sts.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
    assert admin.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
    assert s3a.risk_level == RiskLevel.LOW
    assert s3b.risk_level == RiskLevel.LOW

    assert sts.risk_score > s3a.risk_score
    assert admin.risk_score > s3b.risk_score


def test_counterfactual_for_grant_matches_edge_removal():
    G = build_known_graph()
    scorer = CounterfactualRiskScorer(G)

    base = count_attack_paths(G)
    for role, perm in CRITICAL_EDGES + BENIGN_EDGES:
        G2 = G.copy()
        G2.remove_edge(role, perm)
        expected = base - count_attack_paths(G2)
        assert scorer.routes_broken_by_removing_grant(role, perm) == expected


def test_report_has_expected_shape():
    G = build_known_graph()
    report = CounterfactualRiskScorer(G).generate_risk_report()
    assert report["total_permissions"] == 4
    assert "permissions_by_risk_level" in report
    assert "total_attack_routes" in report
    assert report["total_attack_routes"] > 0
    assert isinstance(report["recommendations"], list)
