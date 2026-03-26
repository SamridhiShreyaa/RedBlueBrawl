import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from src.graph.builder import IAMGraphBuilder

    builder = IAMGraphBuilder(
        uri=os.getenv("NEO4J_URI", "neo4j://127.0.0.1:7687"),
        user=os.getenv("NEO4J_USER", "neo4j"),
        password=os.getenv("NEO4J_PASSWORD", "changeme"),
    )
    dataset_path = os.getenv("IAM_DATASET_PATH", "data/iam_dataset.json")
    builder.clear_all()
    builder.load_data(dataset_path)
    metadata = builder.get_loaded_dataset_metadata()
    stats = builder.get_graph_stats()
    if metadata:
        print(
            "Loaded dataset metadata: "
            f"dataset_id={metadata.get('dataset_id')} "
            f"users={metadata.get('user_count')} "
            f"roles={metadata.get('role_count')} "
            f"permissions={metadata.get('permission_count')}"
        )
    print(
        "Graph totals: "
        f"nodes={stats['total_nodes']} "
        f"edges={stats['total_edges']}"
    )
except Exception as exc:
    print(f"Graph load failed: {exc}")
    sys.exit(1)
finally:
    if "builder" in locals():
        builder.close()
