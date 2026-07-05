import os
import sys

import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.graph.builder import IAMGraphBuilder


@pytest.fixture
def graph():
    builder = IAMGraphBuilder("bolt://localhost:7687", "neo4j", "changeme")
    try:
        G = builder.get_networkx_graph()
    except Exception as e:
        pytest.skip(f"Neo4j is not reachable at bolt://localhost:7687: {e}")
    finally:
        builder.close()
    return G


def test_graph_has_nodes_and_edges(graph):
    assert graph.number_of_nodes() > 0
    assert graph.number_of_edges() > 0
