import sys
import os

# FIX IMPORT PATH
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.graph.builder import IAMGraphBuilder

builder = IAMGraphBuilder("bolt://localhost:7687", "neo4j", "changeme")

G = builder.get_networkx_graph()

print("Nodes:", len(G.nodes()))
print("Edges:", len(G.edges()))

builder.close()