"""
Complete Red vs Blue AI Orchestration Script

This integrates:
1. Graph building (Person A)
2. Red AI attack simulation (Person B)
3. Blue AI defense + Causal Risk Analysis (Person C)
"""

import os
import sys
import json

try:
    from src.graph.builder import IAMGraphBuilder
    from src.adversarial.red_agent import RedAgent
    from src.adversarial.blue_agent import BlueAgent
    from src.causal.risk_scorer import CausalRiskScorer

except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure you've installed all dependencies: pip install -r requirements.txt")
    sys.exit(1)


def orchestrate_full_pipeline():
    """
    Execute the complete Red vs Blue AI simulation pipeline.
    """
    
    print("\n" + "=" * 80)
    print("🔴 🔵 RED vs BLUE AI - Self-Healing IAM System")
    print("=" * 80)
    
    builder = None
    
    try:
        # ===== PHASE 1: LOAD IAM GRAPH =====
        print("\n[PHASE 1] Loading IAM Graph...")
        print("-" * 80)
        
        builder = IAMGraphBuilder(
            uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            user=os.getenv("NEO4J_USER", "neo4j"),
            password=os.getenv("NEO4J_PASSWORD", "changeme"),
        )
        
        graph = builder.get_networkx_graph()
        stats = builder.get_graph_stats()
        
        print(f"✓ Graph loaded successfully")
        print(f"  - Nodes: {stats['total_nodes']}")
        print(f"  - Edges: {stats['total_edges']}")
        
        # ===== PHASE 2: RED AI - FIND ATTACKS =====
        print("\n[PHASE 2] Red AI - Finding Privilege Escalation Paths...")
        print("-" * 80)
        
        red = RedAgent(graph)
        attack_paths = red.find_escalation_paths(max_paths=10)
        
        print(f"✓ Red AI found {len(attack_paths)} attack path(s)")
        
        if attack_paths:
            print("\nTop attack paths:")
            for i, attack in enumerate(attack_paths[:3], 1):
                print(f"\n  [{i}] Risk Score: {attack.risk_score}")
                print(f"      Type: {attack.attack_type}")
                print(f"      Path: {' → '.join(attack.nodes)}")
                print(f"      Description: {attack.description}")
        
        # ===== PHASE 3: BLUE AI - GENERATE DEFENSES =====
        print("\n[PHASE 3] Blue AI - Generating Defensive Strategy...")
        print("-" * 80)
        
        blue = BlueAgent(graph)
        strategy = blue.generate_defenses(attack_paths)
        
        print(f"✓ Blue AI generated {len(strategy.actions)} defensive actions")
        print(f"  - Roles to split: {strategy.permissive_roles_targeted}")
        print(f"  - Permissions to remove: {strategy.perms_removed}")
        print(f"  - Estimated risk reduction: {strategy.total_risk_reduction:.1f}")
        
        # ===== PHASE 4: APPLY DEFENSES =====
        print("\n[PHASE 4] Applying Defenses...")
        print("-" * 80)
        
        hardened_graph, applied_count = blue.apply_defenses(strategy)
        
        print(f"✓ Applied {applied_count} defensive actions")
        
        # ===== PHASE 5: COMPUTE METRICS =====
        print("\n[PHASE 5] Computing Before/After Security Metrics...")
        print("-" * 80)
        
        metrics = blue.compute_metrics()
        
        print(f"Original Graph:")
        print(f"  - Edges: {metrics['original_edges']}")
        print(f"  - Risky exposures: {metrics['original_risky_permission_exposures']}")
        print(f"  - Avg perms/role: {metrics['original_avg_perms_per_role']}")
        
        print(f"\nHardened Graph:")
        print(f"  - Edges: {metrics['current_edges']}")
        print(f"  - Risky exposures: {metrics['current_risky_permission_exposures']}")
        print(f"  - Avg perms/role: {metrics['current_avg_perms_per_role']}")
        
        print(f"\nImprovement:")
        print(f"  - Edges removed: {metrics['edges_removed']}")
        print(f"  - Risky exposures reduced: {metrics['risky_exposures_reduced']}")
        print(f"  - Least privilege improvement: +{metrics['least_privilege_improvement']}%")
        
        # ===== PHASE 6: CAUSAL RISK ANALYSIS (ORIGINAL) =====
        print("\n[PHASE 6] Causal Risk Analysis - ORIGINAL Graph...")
        print("-" * 80)
        
        original_scorer = CausalRiskScorer(graph)
        original_risk = original_scorer.generate_risk_report()
        
        print(f"Risk Distribution:")
        for level, perms in original_risk["permissions_by_risk_level"].items():
            print(f"  - {level}: {len(perms)} permissions")
        
        print(f"\nTop 3 Riskiest Permissions:")
        for item in original_risk["top_10_riskiest"][:3]:
            print(f"  - {item['action']}: {item['risk_level']} ({item['risk_score']}/10)")
        
        # ===== PHASE 7: CAUSAL RISK ANALYSIS (HARDENED) =====
        print("\n[PHASE 7] Causal Risk Analysis - HARDENED Graph...")
        print("-" * 80)
        
        hardened_scorer = CausalRiskScorer(hardened_graph)
        hardened_risk = hardened_scorer.generate_risk_report()
        
        print(f"Risk Distribution:")
        for level, perms in hardened_risk["permissions_by_risk_level"].items():
            print(f"  - {level}: {len(perms)} permissions")
        
        print(f"\nTop 3 Riskiest Permissions:")
        for item in hardened_risk["top_10_riskiest"][:3]:
            print(f"  - {item['action']}: {item['risk_level']} ({item['risk_score']}/10)")
        
        # ===== PHASE 8: SAVE RESULTS =====
        print("\n[PHASE 8] Saving Results...")
        print("-" * 80)
        
        results = {
            "summary": {
                "total_nodes": stats['total_nodes'],
                "total_edges": stats['total_edges'],
                "attack_paths_discovered": len(attack_paths),
                "defensive_actions_generated": len(strategy.actions),
                "defensive_actions_applied": applied_count,
            },
            "red_ai_findings": {
                "attack_count": len(attack_paths),
                "attacks": [
                    {
                        "risk_score": a.risk_score,
                        "type": a.attack_type,
                        "path_length": len(a.nodes),
                        "permissions_used": len(a.permissions_used),
                    }
                    for a in attack_paths[:5]
                ],
            },
            "blue_ai_actions": {
                "total_actions": len(strategy.actions),
                "roles_split": strategy.permissive_roles_targeted,
                "permissions_removed": strategy.perms_removed,
                "estimated_risk_reduction": strategy.total_risk_reduction,
            },
            "metrics": {
                "original_edges": metrics['original_edges'],
                "hardened_edges": metrics['current_edges'],
                "edges_removed": metrics['edges_removed'],
                "original_risky_exposures": metrics['original_risky_permission_exposures'],
                "hardened_risky_exposures": metrics['current_risky_permission_exposures'],
                "least_privilege_improvement_pct": metrics['least_privilege_improvement'],
            },
            "risk_analysis": {
                "original_risk_distribution": original_risk["permissions_by_risk_level"],
                "hardened_risk_distribution": hardened_risk["permissions_by_risk_level"],
                "top_riskiest_permissions": original_risk["top_10_riskiest"][:5],
            },
        }
        
        # Save JSON results
        with open("results.json", "w") as f:
            json.dump(results, f, indent=2)
        
        print(f"✓ Results saved to results.json")
        
        # Save defense report
        defense_report = blue.get_defense_report()
        with open("defense_report.txt", "w") as f:
            f.write(defense_report)
        
        print(f"✓ Defense report saved to defense_report.txt")
        
        # ===== FINAL SUMMARY =====
        print("\n" + "=" * 80)
        print("✅ SIMULATION COMPLETED SUCCESSFULLY")
        print("=" * 80)
        
        print(f"""
EXECUTIVE SUMMARY:
─────────────────────────────────────────────────────────────
🔴 Red AI discovered {len(attack_paths)} privilege escalation paths
🔵 Blue AI generated {len(strategy.actions)} defensive actions (applied {applied_count})

SECURITY IMPROVEMENT:
─────────────────────────────────────────────────────────────
  → Edges reduced: {metrics['edges_removed']} ({metrics['original_edges']} → {metrics['current_edges']})
  → Risky exposures reduced: {metrics['risky_exposures_reduced']} 
  → Least privilege improved: +{metrics['least_privilege_improvement']}%

CAUSAL RISK ATTRIBUTION:
─────────────────────────────────────────────────────────────
  → Original critical permissions: {len(original_risk['permissions_by_risk_level'].get('CRITICAL', []))}
  → Hardened critical permissions: {len(hardened_risk['permissions_by_risk_level'].get('CRITICAL', []))}

OUTPUTS:
─────────────────────────────────────────────────────────────
  ✓ results.json - Full metrics and analysis
  ✓ defense_report.txt - Detailed defense actions
""")
        
        return results
        
    except Exception as e:
        print(f"\n❌ Pipeline failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    finally:
        if builder:
            builder.close()


if __name__ == "__main__":
    results = orchestrate_full_pipeline()
