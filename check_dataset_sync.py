import json
import os
import sys

from src.graph.builder import IAMGraphBuilder


def read_local_metadata(path: str):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    meta = data.get("metadata", {})
    return {
        "dataset_id": meta.get("dataset_id", "unknown"),
        "user_count": meta.get("user_count", len(data.get("users", []))),
        "role_count": meta.get("role_count", len(data.get("roles", []))),
        "permission_count": meta.get("permission_count", len(data.get("permissions", []))),
    }


def main():
    dataset_path = os.getenv("IAM_DATASET_PATH", "data/iam_dataset.json")

    local = read_local_metadata(dataset_path)

    builder = None
    try:
        builder = IAMGraphBuilder(
            uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            user=os.getenv("NEO4J_USER", "neo4j"),
            password=os.getenv("NEO4J_PASSWORD", "changeme"),
        )
        remote = builder.get_loaded_dataset_metadata()
    except Exception as exc:
        print(f"Dataset check failed while connecting to Neo4j: {exc}")
        sys.exit(1)
    finally:
        if builder is not None:
            builder.close()

    print("Local dataset metadata:")
    print(f"  dataset_id: {local['dataset_id']}")
    print(f"  counts: users={local['user_count']} roles={local['role_count']} permissions={local['permission_count']}")

    if remote is None:
        print("Neo4j dataset metadata: not found (load graph first with run_graph.py)")
        sys.exit(2)

    print("Neo4j loaded dataset metadata:")
    print(f"  dataset_id: {remote.get('dataset_id')}")
    print(
        "  counts: "
        f"users={remote.get('user_count')} roles={remote.get('role_count')} permissions={remote.get('permission_count')}"
    )
    print(f"  loaded_at: {remote.get('loaded_at')}")
    print(f"  source_path: {remote.get('source_path')}")

    same_id = str(local["dataset_id"]) == str(remote.get("dataset_id"))
    same_counts = (
        int(local["user_count"]) == int(remote.get("user_count", -1))
        and int(local["role_count"]) == int(remote.get("role_count", -1))
        and int(local["permission_count"]) == int(remote.get("permission_count", -1))
    )

    if same_id and same_counts:
        print("MATCH: local dataset matches what is loaded in Neo4j.")
    else:
        print("MISMATCH: local dataset is different from what is loaded in Neo4j.")
        sys.exit(3)


if __name__ == "__main__":
    main()
