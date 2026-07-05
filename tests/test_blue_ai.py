"""
Test suite for Blue AI and Causal Risk Scorer modules.

Run with: pytest tests/test_blue_ai.py
"""

import sys
from pathlib import Path

import networkx as nx
import pytest

# Add repo to path
repo_root = str(Path(__file__).parent.parent)
sys.path.insert(0, repo_root)

from src.adversarial.red_agent import RedAgent
from src.adversarial.blue_agent import BlueAgent
from src.causal.risk_scorer import CausalRiskScorer


def create_test_graph():
    """Create a test IAM graph that will trigger attack paths."""
    G = nx.DiGraph()

    # Create test nodes with escalation structure
    users = ["user_low_1", "user_low_2"]

    # Create user nodes (low privilege)
    for u in users:
        G.add_node(u, label="User", username=u)

    # Create role nodes
    G.add_node("role_junior", label="Role", name="role_junior", is_overpermissive=False)
    G.add_node("role_with_assume_role", label="Role", name="role_with_assume_role", is_overpermissive=False)
    G.add_node("role_admin_target", label="Role", name="role_admin_target", is_overpermissive=True)

    # Create permission nodes with sensitive flags
    G.add_node("perm_s3_read", label="Permission", action="s3:GetObject", is_sensitive=False)
    G.add_node("perm_s3_write", label="Permission", action="s3:PutObject", is_sensitive=False)
    G.add_node("perm_s3_delete", label="Permission", action="s3:DeleteObject", is_sensitive=True)
    G.add_node("perm_sts_AssumeRole", label="Permission", action="sts:AssumeRole", is_sensitive=True)
    G.add_node("perm_iam_CreateUser", label="Permission", action="iam:CreateUser", is_sensitive=True)
    G.add_node("perm_iam_PassRole", label="Permission", action="iam:PassRole", is_sensitive=True)
    G.add_node("perm_iam_AttachPolicy", label="Permission", action="iam:AttachRolePolicy", is_sensitive=True)
    G.add_node("perm_ec2_Terminate", label="Permission", action="ec2:TerminateInstances", is_sensitive=True)
    G.add_node("perm_ec2_Start", label="Permission", action="ec2:StartInstances", is_sensitive=False)
    G.add_node("perm_kms_Decrypt", label="Permission", action="kms:Decrypt", is_sensitive=True)

    # Build escalation path:
    # user_low_1 -> role_junior -> s3:read/write
    G.add_edge("user_low_1", "role_junior", relation="HAS_ROLE")
    G.add_edge("role_junior", "perm_s3_read", relation="GRANTS")
    G.add_edge("role_junior", "perm_s3_write", relation="GRANTS")

    # user_low_2 -> role_with_assume_role -> {s3_read, sts:AssumeRole}
    # This is the pivot role for escalation
    G.add_edge("user_low_2", "role_with_assume_role", relation="HAS_ROLE")
    G.add_edge("role_with_assume_role", "perm_s3_read", relation="GRANTS")
    G.add_edge("role_with_assume_role", "perm_sts_AssumeRole", relation="GRANTS")

    # Target admin role with 7 sensitive permissions (>= 5 for high priv detection)
    G.add_edge("role_admin_target", "perm_iam_CreateUser", relation="GRANTS")
    G.add_edge("role_admin_target", "perm_iam_PassRole", relation="GRANTS")
    G.add_edge("role_admin_target", "perm_iam_AttachPolicy", relation="GRANTS")
    G.add_edge("role_admin_target", "perm_ec2_Terminate", relation="GRANTS")
    G.add_edge("role_admin_target", "perm_kms_Decrypt", relation="GRANTS")
    G.add_edge("role_admin_target", "perm_s3_delete", relation="GRANTS")
    G.add_edge("role_admin_target", "perm_s3_read", relation="GRANTS")

    return G


@pytest.fixture
def G():
    return create_test_graph()


@pytest.fixture
def attack_paths(G):
    red = RedAgent(G)
    return red.find_escalation_paths(max_paths=5)


@pytest.fixture
def blue_defense(G, attack_paths):
    """Blue agent with a generated strategy already applied to the graph."""
    blue = BlueAgent(G)
    strategy = blue.generate_defenses(attack_paths)
    hardened_graph, applied_count = blue.apply_defenses(strategy)
    return blue, strategy, hardened_graph, applied_count


def test_graph_queries(G):
    """Test basic graph query functions."""
    from src.graph.queries import (
        get_users, get_roles, get_permissions,
        get_user_roles, get_role_permissions, get_user_permissions,
    )

    users = get_users(G)
    roles = get_roles(G)
    perms = get_permissions(G)

    user_low_1_roles = get_user_roles(G, "user_low_1")
    junior_perms = get_role_permissions(G, "role_junior")
    user_low_1_perms = get_user_permissions(G, "user_low_1")

    assert len(users) == 2, f"Should have 2 users, got {len(users)}"
    assert len(roles) == 3, f"Should have 3 roles, got {len(roles)}"
    assert len(perms) >= 9, f"Should have at least 9 permissions, got {len(perms)}"
    assert user_low_1_roles == ["role_junior"]
    assert set(junior_perms) == {"perm_s3_read", "perm_s3_write"}
    assert set(user_low_1_perms) == set(junior_perms)


def test_red_agent(attack_paths):
    """Test Red AI attack discovery."""
    assert len(attack_paths) > 0, "Should find at least one attack path"
    assert hasattr(attack_paths[0], "risk_score"), "Attack should have risk_score"


def test_blue_agent(blue_defense):
    """Test Blue AI defense generation."""
    _, strategy, _, _ = blue_defense
    assert len(strategy.actions) > 0, "Should generate at least one defense"


def test_apply_defenses(blue_defense):
    """Test applying defenses to the graph."""
    blue, _, hardened_graph, _ = blue_defense

    original_edges = blue.original_graph.number_of_edges()
    hardened_edges = hardened_graph.number_of_edges()

    assert hardened_edges <= original_edges, "Hardened graph should have fewer edges"


def test_compute_metrics(blue_defense):
    """Test metrics computation."""
    blue, _, _, _ = blue_defense
    metrics = blue.compute_metrics()

    assert "edges_removed" in metrics
    assert "risky_exposures_reduced" in metrics


def test_causal_risk_scorer(G):
    """Test Causal Risk Scorer."""
    scorer = CausalRiskScorer(G)
    all_scores = scorer.score_all_permissions()

    assert len(all_scores) > 0, "Should score at least one permission"


def test_risk_report(G):
    """Test risk report generation."""
    scorer = CausalRiskScorer(G)
    report = scorer.generate_risk_report()

    assert "total_permissions" in report
    assert "permissions_by_risk_level" in report


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
