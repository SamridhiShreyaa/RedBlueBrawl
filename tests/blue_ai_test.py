"""
Test suite for Blue AI and Causal Risk Scorer modules.

Run this to verify that all Person C components work correctly.
"""

import sys
import tempfile
from pathlib import Path

import networkx as nx

# Add repo to path
repo_root = str(Path(__file__).parent.parent)
sys.path.insert(0, repo_root)

from src.adversarial.red_agent import RedAgent, AttackPath
from src.adversarial.blue_agent import BlueAgent, DefenseActionType
from src.causal.risk_scorer import CausalRiskScorer, RiskLevel
from src.graph.queries import (
    get_users, get_roles, get_permissions, 
    get_user_roles, get_role_permissions, get_user_permissions
)


def create_test_graph():
    """Create a test IAM graph that will trigger attack paths."""
    G = nx.DiGraph()
    
    # Create test nodes with escalation structure
    users = ["user_low_1", "user_low_2"]
    roles = ["role_junior", "role_with_assume_role", "role_admin_target"]
    
    # Create 10 permissions (so we have roles with 5+ permissions)
    perms = [
        "perm_s3_read", 
        "perm_s3_write",
        "perm_s3_delete",
        "perm_sts_AssumeRole",  # Key permission for escalation
        "perm_iam_CreateUser",
        "perm_iam_PassRole",
        "perm_iam_AttachPolicy",
        "perm_ec2_Terminate",
        "perm_ec2_Start",
        "perm_kms_Decrypt",
    ]
    
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


def test_graph_queries():
    """Test basic graph query functions."""
    print("\n" + "=" * 70)
    print("TEST 1: Graph Query Functions")
    print("=" * 70)
    
    G = create_test_graph()
    
    # Test user/role/perm queries
    users = get_users(G)
    roles = get_roles(G)
    perms = get_permissions(G)
    
    print(f"✓ Users: {len(users)} - {users}")
    print(f"✓ Roles: {len(roles)} - {roles}")
    print(f"✓ Permissions: {len(perms)}")
    
    # Test relationship queries
    user_low_1_roles = get_user_roles(G, "user_low_1")
    print(f"✓ user_low_1 roles: {user_low_1_roles}")
    
    junior_perms = get_role_permissions(G, "role_junior")
    print(f"✓ role_junior permissions: {junior_perms}")
    
    user_low_1_perms = get_user_permissions(G, "user_low_1")
    print(f"✓ user_low_1 effective permissions: {user_low_1_perms}")
    
    assert len(users) == 2, f"Should have 2 users, got {len(users)}"
    assert len(roles) == 3, f"Should have 3 roles, got {len(roles)}"
    assert len(perms) >= 9, f"Should have at least 9 permissions, got {len(perms)}"
    
    print("\n✅ All graph query tests passed!")
    return G


def test_red_agent(G):
    """Test Red AI attack discovery."""
    print("\n" + "=" * 70)
    print("TEST 2: Red AI - Attack Path Discovery")
    print("=" * 70)
    
    red = RedAgent(G)
    attack_paths = red.find_escalation_paths(max_paths=5)
    
    print(f"✓ Found {len(attack_paths)} attack path(s)")
    
    for i, attack in enumerate(attack_paths[:2], 1):
        print(f"\n  Attack {i}:")
        print(f"    - Type: {attack.attack_type}")
        print(f"    - Risk Score: {attack.risk_score}")
        print(f"    - Path: {' → '.join(attack.nodes)}")
        print(f"    - Description: {attack.description}")
    
    assert len(attack_paths) > 0, "Should find at least one attack path"
    assert hasattr(attack_paths[0], 'risk_score'), "Attack should have risk_score"
    
    print("\n✅ Red AI attack discovery tests passed!")
    return attack_paths


def test_blue_agent(G, attack_paths):
    """Test Blue AI defense generation."""
    print("\n" + "=" * 70)
    print("TEST 3: Blue AI - Defense Strategy Generation")
    print("=" * 70)
    
    blue = BlueAgent(G)
    strategy = blue.generate_defenses(attack_paths)
    
    print(f"✓ Generated {len(strategy.actions)} defensive actions")
    print(f"✓ Estimated risk reduction: {strategy.total_risk_reduction}")
    print(f"✓ Roles targeted for splitting: {strategy.permissive_roles_targeted}")
    print(f"✓ Permissions to remove: {strategy.perms_removed}")
    
    # Show first few actions
    for i, action in enumerate(strategy.actions[:3], 1):
        print(f"\n  Action {i}:")
        print(f"    - Type: {action.action_type.value}")
        print(f"    - Target: {action.target_id}")
        print(f"    - Risk Reduction: {action.risk_reduction}")
        print(f"    - Justification: {action.justification}")
    
    assert len(strategy.actions) > 0, "Should generate at least one defense"
    
    print("\n✅ Blue AI defense generation tests passed!")
    return blue, strategy


def test_apply_defenses(blue_agent, strategy):
    """Test applying defenses to the graph."""
    print("\n" + "=" * 70)
    print("TEST 4: Blue AI - Apply Defenses")
    print("=" * 70)
    
    hardened_graph, applied_count = blue_agent.apply_defenses(strategy)
    
    print(f"✓ Applied {applied_count} defensive actions")
    print(f"✓ Original edges: {blue_agent.original_graph.number_of_edges()}")
    print(f"✓ Hardened edges: {hardened_graph.number_of_edges()}")
    
    original_edges = blue_agent.original_graph.number_of_edges()
    hardened_edges = hardened_graph.number_of_edges()
    
    print(f"✓ Edges removed: {original_edges - hardened_edges}")
    
    assert hardened_edges <= original_edges, "Hardened graph should have fewer edges"
    
    print("\n✅ Apply defenses tests passed!")
    return hardened_graph


def test_compute_metrics(blue_agent):
    """Test metrics computation."""
    print("\n" + "=" * 70)
    print("TEST 5: Blue AI - Security Metrics")
    print("=" * 70)
    
    metrics = blue_agent.compute_metrics()
    
    print(f"✓ Original edges: {metrics['original_edges']}")
    print(f"✓ Current edges: {metrics['current_edges']}")
    print(f"✓ Edges removed: {metrics['edges_removed']}")
    print(f"✓ Original risky exposures: {metrics['original_risky_permission_exposures']}")
    print(f"✓ Current risky exposures: {metrics['current_risky_permission_exposures']}")
    print(f"✓ Risky exposures reduced: {metrics['risky_exposures_reduced']}")
    print(f"✓ Original avg perms/role: {metrics['original_avg_perms_per_role']}")
    print(f"✓ Current avg perms/role: {metrics['current_avg_perms_per_role']}")
    print(f"✓ Least privilege improvement: {metrics['least_privilege_improvement']}%")
    
    assert "edges_removed" in metrics
    assert "risky_exposures_reduced" in metrics
    
    print("\n✅ Metrics computation tests passed!")


def test_causal_risk_scorer(G):
    """Test Causal Risk Scorer."""
    print("\n" + "=" * 70)
    print("TEST 6: Causal Risk Scorer - Permission Risk Analysis")
    print("=" * 70)
    
    scorer = CausalRiskScorer(G)
    all_scores = scorer.score_all_permissions()
    
    print(f"✓ Scored {len(all_scores)} permissions")
    
    # Show top riskiest
    print("\nTop 3 Riskiest Permissions:")
    for i, score in enumerate(all_scores[:3], 1):
        print(f"  {i}. {score.action}")
        print(f"     - Risk Level: {score.risk_level.value}")
        print(f"     - Risk Score: {score.risk_score}/10")
        print(f"     - Exposure: {score.exposure_count} users")
        print(f"     - Causal Strength: {score.causal_strength}")
        print(f"     - Reason: {score.justification}")
    
    assert len(all_scores) > 0, "Should score at least one permission"
    
    print("\n✅ Permission risk scoring tests passed!")


def test_risk_report(G):
    """Test risk report generation."""
    print("\n" + "=" * 70)
    print("TEST 7: Causal Risk Scorer - Report Generation")
    print("=" * 70)
    
    scorer = CausalRiskScorer(G)
    report = scorer.generate_risk_report()
    
    print(f"✓ Total permissions: {report['total_permissions']}")
    print(f"✓ Risk distribution:")
    for level, perms in report["permissions_by_risk_level"].items():
        print(f"  - {level}: {len(perms)}")
    
    print(f"\n✓ Top 5 riskiest:")
    for item in report["top_10_riskiest"][:5]:
        print(f"  - {item['action']}: {item['risk_level']} ({item['risk_score']}/10)")
    
    print(f"\n✓ Causal attribution:")
    for perm, pct in report["causal_attribution"].items():
        print(f"  - {perm}: {pct}%")
    
    print(f"\n✓ Recommendations:")
    for rec in report["recommendations"]:
        print(f"  - {rec}")
    
    assert "total_permissions" in report
    assert "permissions_by_risk_level" in report
    
    print("\n✅ Risk report generation tests passed!")


def main():
    """Run all tests."""
    print("\n" + "=" * 70)
    print("🧪 BLUE AI + CAUSAL RISK SCORER TEST SUITE")
    print("=" * 70)
    
    try:
        # Run tests in sequence
        G = test_graph_queries()
        attack_paths = test_red_agent(G)
        blue, strategy = test_blue_agent(G, attack_paths)
        hardened_graph = test_apply_defenses(blue, strategy)
        test_compute_metrics(blue)
        test_causal_risk_scorer(G)
        test_risk_report(G)
        
        print("\n" + "=" * 70)
        print("✅ ALL TESTS PASSED!")
        print("=" * 70)
        print("\nYour Blue AI and Causal Risk Scorer modules are working correctly.")
        print("Ready to integrate with the full pipeline!")
        
        return 0
        
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        return 1
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
