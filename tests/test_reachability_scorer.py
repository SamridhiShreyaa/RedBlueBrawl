"""Reachability-scorer correctness and novel-technique generalization tests."""

import sys
from pathlib import Path

import networkx as nx

repo_root = str(Path(__file__).parent.parent)
sys.path.insert(0, repo_root)

from src.causal.risk_scorer import (
    ASSUME_ACTIONS,
    PRIVESC_ACTIONS,
    ReachabilityRiskScorer,
    RiskLevel,
    SignatureCounterfactualScorer,
    count_reachability_paths,
    enumerate_reachability_routes,
)
from eval.tenant_gen import NOVEL_ASSUME_ACTION, generate_tenant


# --------------------------------------------------------------------------
# small known graph: sensitive target reachable ONLY via a specific assume edge
# --------------------------------------------------------------------------

def build_known_graph() -> nx.DiGraph:
    G = nx.DiGraph()

    G.add_node("u1", label="User", username="u1")
    G.add_node("u2", label="User", username="u2")

    G.add_node("r_entry", label="Role", name="r_entry")
    G.add_node("r_admin", label="Role", name="r_admin")
    G.add_node("r_benign", label="Role", name="r_benign")

    # The enabler uses a NOVEL action (absent from every signature list) to
    # prove catching is structural. It sits on the entry role.
    G.add_node("p_enable", label="Permission", action=NOVEL_ASSUME_ACTION, is_sensitive=True)
    G.add_node("p_admin", label="Permission", action="iam:CreateUser", is_sensitive=True)
    G.add_node("p_admin_benign", label="Permission", action="s3:GetObject", is_sensitive=False)
    G.add_node("p_benign", label="Permission", action="s3:GetObject", is_sensitive=False)

    G.add_edge("u1", "r_entry", relation="HAS_ROLE")
    G.add_edge("r_entry", "p_enable", relation="GRANTS")
    G.add_edge("r_admin", "p_admin", relation="GRANTS")
    G.add_edge("r_admin", "p_admin_benign", relation="GRANTS")
    G.add_edge("u2", "r_benign", relation="HAS_ROLE")
    G.add_edge("r_benign", "p_benign", relation="GRANTS")

    # r_entry can assume r_admin, enabled by the (novel) p_enable grant.
    # r_admin is NOT held by any user directly -> only reachable via this edge.
    G.graph["trust_edges"] = [
        {"src": "r_entry", "dst": "r_admin", "enabling_perm": "p_enable"},
    ]
    return G


ASSUME_EDGE_ENABLER = ("r_entry", "p_enable")
TERMINAL_TARGET = ("r_admin", "p_admin")
BENIGN_EDGES = [("r_benign", "p_benign"), ("r_admin", "p_admin_benign")]


def test_target_reachable_only_through_assume_edge():
    G = build_known_graph()
    assert count_reachability_paths(G) > 0

    # Removing the enabling grant severs the only assume edge to the target.
    G2 = G.copy()
    G2.remove_edge(*ASSUME_EDGE_ENABLER)
    assert count_reachability_paths(G2) < count_reachability_paths(G)
    assert count_reachability_paths(G2) == 0


def test_removing_terminal_target_drops_routes():
    G = build_known_graph()
    base = count_reachability_paths(G)
    G2 = G.copy()
    G2.remove_edge(*TERMINAL_TARGET)
    assert count_reachability_paths(G2) < base


def test_removing_benign_edge_does_not_change_routes():
    G = build_known_graph()
    base = count_reachability_paths(G)
    for edge in BENIGN_EDGES:
        G2 = G.copy()
        G2.remove_edge(*edge)
        assert count_reachability_paths(G2) == base


def test_edge_credit_equals_recomputed_counterfactual():
    G = build_known_graph()
    edge_credit, base = enumerate_reachability_routes(G)
    for u, v in list(G.edges()):
        G2 = G.copy()
        G2.remove_edge(u, v)
        recomputed = base - count_reachability_paths(G2)
        assert edge_credit.get((u, v), 0) == recomputed


def test_scorer_flags_enabler_and_target_not_benign():
    scorer = ReachabilityRiskScorer(build_known_graph())

    enabler = scorer.score_permission_risk("p_enable")
    target = scorer.score_permission_risk("p_admin")
    benign1 = scorer.score_permission_risk("p_admin_benign")
    benign2 = scorer.score_permission_risk("p_benign")

    assert enabler.routes_broken > 0
    assert target.routes_broken > 0
    assert benign1.routes_broken == 0
    assert benign2.routes_broken == 0

    assert enabler.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
    assert target.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
    assert benign1.risk_level == RiskLevel.LOW
    assert benign2.risk_level == RiskLevel.LOW


def test_no_trust_edges_means_no_routes():
    """Without trust structure there is nothing to reach -> no routes."""
    G = build_known_graph()
    G.graph["trust_edges"] = []
    assert count_reachability_paths(G) == 0
    scorer = ReachabilityRiskScorer(G)
    assert all(s.routes_broken == 0 for s in scorer.score_all_permissions())


# --------------------------------------------------------------------------
# generalization: novel technique caught by structure, not name-matching
# --------------------------------------------------------------------------

def _recall(scorer_cls, tenant) -> float:
    gt = tenant.risky_permissions()
    if not gt:
        return 0.0
    flagged = {
        s.permission_id for s in scorer_cls(tenant.graph).score_all_permissions()
        if s.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
    }
    return len(flagged & gt) / len(gt)


def test_novel_action_is_absent_from_signature_lists():
    # Precondition for the whole test to be meaningful.
    assert NOVEL_ASSUME_ACTION not in ASSUME_ACTIONS
    assert NOVEL_ASSUME_ACTION not in PRIVESC_ACTIONS


def test_signature_scorer_is_blind_to_novel_technique():
    tenant = generate_tenant(seed=1, chain_length=3, density="low",
                             n_chains=3, novel_technique=True)
    # The signature scorer catches almost none of the novel chain.
    assert _recall(SignatureCounterfactualScorer, tenant) < 0.3


def test_reachability_scorer_catches_novel_technique_via_structure():
    tenant = generate_tenant(seed=1, chain_length=3, density="low",
                             n_chains=3, novel_technique=True)

    # Reachability catches the escalation despite the unlisted action name.
    assert _recall(ReachabilityRiskScorer, tenant) > 0.7

    # Prove it is the trust STRUCTURE doing the work, not any name: strip the
    # trust edges and the same scorer catches nothing (and so would signature).
    stripped = tenant.graph.copy()
    stripped.graph["trust_edges"] = []
    flagged = {
        s.permission_id for s in ReachabilityRiskScorer(stripped).score_all_permissions()
        if s.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
    }
    assert len(flagged & tenant.risky_permissions()) == 0


def test_reachability_generalizes_original_and_novel_equally():
    """Same structure, different action name -> same recall."""
    original = generate_tenant(seed=2, chain_length=3, density="low",
                               n_chains=3, novel_technique=False)
    novel = generate_tenant(seed=2, chain_length=3, density="low",
                            n_chains=3, novel_technique=True)
    assert _recall(ReachabilityRiskScorer, original) == _recall(ReachabilityRiskScorer, novel)
