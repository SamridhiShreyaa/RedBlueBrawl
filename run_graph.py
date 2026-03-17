from src.graph.builder import IAMGraphBuilder

builder = IAMGraphBuilder(
    uri="bolt://localhost:7687",
    user="neo4j",
    password="changeme"
)

builder.load_data("data/iam_dataset.json")
builder.close()