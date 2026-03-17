import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.graph.builder import IAMGraphBuilder
from src.graph.queries import *

builder = IAMGraphBuilder("bolt://localhost:7687", "neo4j", "changeme")

G = builder.get_networkx_graph()

print("Users:", len(get_users(G)))
print("Roles:", len(get_roles(G)))
print("Permissions:", len(get_permissions(G)))

print("Low privilege users:", len(get_low_privilege_users(G)))
print("High risk roles:", len(get_high_privilege_roles(G)))

builder.close()