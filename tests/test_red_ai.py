import os
import sys

import networkx as nx

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.adversarial.red_agent import RedAgent


def build_demo_graph() -> nx.DiGraph:
    graph = nx.DiGraph()

    graph.add_node("user_insider", label="User", username="j.smith.dev")
    graph.add_node("role_escalation_pivot", label="Role", name="DevOps_Operator_Pivot")
    graph.add_node("perm_sts", label="Permission", action="sts:AssumeRole", is_sensitive=True)
    graph.add_node("role_admin_sink", label="Role", name="Engineering_Admin_Sink")

    graph.add_node("user_ops", label="User", username="ops.user")
    graph.add_node("role_ops", label="Role", name="Operations")
    graph.add_node("perm_kms", label="Permission", action="kms:Decrypt", is_sensitive=True)
    graph.add_node("role_finance_admin", label="Role", name="Finance_Admin")

    graph.add_edge("user_insider", "role_escalation_pivot")
    graph.add_edge("role_escalation_pivot", "perm_sts")

    graph.add_edge("user_ops", "role_ops")
    graph.add_edge("role_ops", "perm_kms")

    # Admin-like roles have many outgoing permissions.
    for i in range(6):
        perm_id = f"perm_admin_{i}"
        graph.add_node(perm_id, label="Permission", action=f"admin:Action{i}")
        graph.add_edge("role_admin_sink", perm_id)
        graph.add_edge("role_finance_admin", perm_id)

    return graph


def main() -> None:
    graph = build_demo_graph()
    agent = RedAgent(graph)
    paths = agent.find_escalation_paths(max_paths=10)

    assert len(paths) >= 2, f"Expected at least 2 attack paths, found {len(paths)}"

    sts_paths = [p for p in paths if "perm_sts" in p.permissions_used]
    assert sts_paths, "Expected at least one sts:AssumeRole-based path"

    for idx, path in enumerate(paths, start=1):
        assert path.description, f"Path {idx} has empty description"
        assert isinstance(path.risk_score, float), f"Path {idx} risk score is not float"

    print("Red AI test passed")
    print(f"Paths found: {len(paths)}")


if __name__ == "__main__":
    main()
