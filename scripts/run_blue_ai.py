"""
Blue AI + Causal Risk Analysis Integration Script

This script demonstrates how:
1. Red AI finds attack paths
2. Blue AI generates defensive strategies
3. Causal Risk Scorer attributes risk to specific permissions
"""

import os
import sys
import json

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.adversarial.red_agent import RedAgent
from src.adversarial.blue_agent import BlueAgent
from src.causal.risk_scorer import make_risk_scorer


def run_blue_ai_pipeline(graph, attack_paths, output_file="defenses.json"):
    """
    Run the complete Blue AI + Causal pipeline.
    
    Args:
        graph: NetworkX IAM graph
        attack_paths: List of AttackPath from RedAgent
        output_file: Where to save results
        
    Returns:
        Dictionary with all results
    """
    print("\n" + "=" * 70)
    print("🔵 BLUE AI DEFENSE ENGINE STARTING")
    print("=" * 70)

    # ===== STEP 1: ANALYZE ATTACK PATHS AND GENERATE DEFENSES =====
    print("\n[1] Analyzing attack paths and generating defensive strategy...")
    blue = BlueAgent(graph)
    strategy = blue.generate_defenses(attack_paths)

    print(f"    ✓ Generated {len(strategy.actions)} defensive actions")
    print(f"    ✓ Targeting {strategy.permissive_roles_targeted} roles for splitting")
    print(f"    ✓ Removing {strategy.perms_removed} high-risk permissions")
    print(f"    ✓ Total estimated risk reduction: {strategy.total_risk_reduction:.1f}")

    # ===== STEP 2: APPLY DEFENSES TO GRAPH =====
    print("\n[2] Applying defenses to IAM graph...")
    hardened_graph, applied = blue.apply_defenses(strategy)
    print(f"    ✓ Applied {applied} defensive actions successfully")

    # ===== STEP 3: COMPUTE BEFORE/AFTER METRICS =====
    print("\n[3] Computing security metrics...")
    metrics = blue.compute_metrics()
    
    print(f"    Original Graph:  {metrics['original_edges']} edges")
    print(f"    Hardened Graph:  {metrics['current_edges']} edges")
    print(f"    Edges Removed:   {metrics['edges_removed']}")
    print(f"    Risky Exposures: {metrics['original_risky_permission_exposures']} → "
          f"{metrics['current_risky_permission_exposures']} "
          f"(-{metrics['risky_exposures_reduced']})")
    print(f"    Avg Perms/Role:  {metrics['original_avg_perms_per_role']} → "
          f"{metrics['current_avg_perms_per_role']}")
    print(f"    Least Privilege: +{metrics['least_privilege_improvement']}%")

    # ===== STEP 4: RUN CAUSAL RISK ANALYSIS (ORIGINAL GRAPH) =====
    print("\n[4] Running Causal Risk Analysis on ORIGINAL graph...")
    original_scorer = make_risk_scorer(graph)
    original_risk_report = original_scorer.generate_risk_report()
    
    print(f"    Original Risk Profile:")
    for level, perms in original_risk_report["permissions_by_risk_level"].items():
        print(f"      {level}: {len(perms)} permissions")

    # ===== STEP 5: RUN CAUSAL RISK ANALYSIS (HARDENED GRAPH) =====
    print("\n[5] Running Causal Risk Analysis on HARDENED graph...")
    hardened_scorer = make_risk_scorer(hardened_graph)
    hardened_risk_report = hardened_scorer.generate_risk_report()
    
    print(f"    Hardened Risk Profile:")
    for level, perms in hardened_risk_report["permissions_by_risk_level"].items():
        print(f"      {level}: {len(perms)} permissions")

    # ===== STEP 6: TOP RISKIEST PERMISSIONS =====
    print("\n[6] Top 5 Riskiest Permissions (Causal Attribution):")
    for i, item in enumerate(original_risk_report["top_10_riskiest"][:5], 1):
        print(f"    {i}. {item['action']}")
        print(f"       Risk: {item['risk_level']} ({item['risk_score']}/10)")
        print(f"       Exposed to: {item['exposure_count']} users")
        print(f"       Reason: {item['justification']}")

    # ===== STEP 7: RECOMMENDATIONS =====
    print("\n[7] Recommendations:")
    for i, rec in enumerate(hardened_risk_report["recommendations"], 1):
        print(f"    {i}. {rec}")

    # ===== COMPILE RESULTS =====
    results = {
        "summary": {
            "attack_paths_found": len(attack_paths),
            "defensive_actions": len(strategy.actions),
            "actions_applied": applied,
            "total_risk_reduction": strategy.total_risk_reduction,
        },
        "metrics": metrics,
        "original_risk_analysis": {
            "total_permissions": original_risk_report["total_permissions"],
            "risk_distribution": original_risk_report["permissions_by_risk_level"],
            "top_10_riskiest": original_risk_report["top_10_riskiest"],
            "causal_attribution": original_risk_report["causal_attribution"],
        },
        "hardened_risk_analysis": {
            "total_permissions": hardened_risk_report["total_permissions"],
            "risk_distribution": hardened_risk_report["permissions_by_risk_level"],
            "top_10_riskiest": hardened_risk_report["top_10_riskiest"],
            "causal_attribution": hardened_risk_report["causal_attribution"],
        },
        "defense_actions_detail": [
            {
                "type": a.action_type.value,
                "target": a.target_id,
                "justification": a.justification,
                "risk_reduction": a.risk_reduction,
            }
            for a in strategy.actions
        ],
    }

    # ===== SAVE RESULTS =====
    print(f"\n[8] Saving results to {output_file}...")
    with open(output_file, "w") as f:
        # Convert non-serializable types before JSON dumping
        serializable_results = {
            k: v if not isinstance(v, dict) else {
                kk: vv if isinstance(vv, (list, dict, str, int, float, bool, type(None)))
                else str(vv)
                for kk, vv in v.items()
            }
            for k, v in results.items()
        }
        json.dump(serializable_results, f, indent=2)

    print(f"    ✓ Results saved!")

    print("\n" + "=" * 70)
    print("✅ BLUE AI PIPELINE COMPLETED")
    print("=" * 70)

    return results


if __name__ == "__main__":
    # This would be called by the main orchestration script
    print("Blue AI module ready. Import run_blue_ai_pipeline() to execute.")
