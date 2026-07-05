import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.adversarial.red_agent import RedAgent

try:
    from src.graph.builder import IAMGraphBuilder

    builder = IAMGraphBuilder.from_env()

    graph = builder.get_networkx_graph()
    red = RedAgent(graph)
    attack_paths = red.find_escalation_paths(max_paths=5)

    print(f"Found {len(attack_paths)} attack path(s)")
    for i, attack in enumerate(attack_paths, start=1):
        print(f"\n[{i}] Score={attack.risk_score} Type={attack.attack_type}")
        print("Path:", " -> ".join(attack.nodes))
        print("Description:", attack.description)
except Exception as exc:
    print(f"Red AI run failed: {exc}")
    sys.exit(1)
finally:
    if "builder" in locals():
        builder.close()
