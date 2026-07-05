import os
import sys

import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.graph.builder import IAMGraphBuilder
from src.graph.queries import (
    get_users,
    get_roles,
    get_permissions,
    get_low_privilege_users,
    get_high_privilege_roles,
)


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


def test_query_helpers_return_expected_shapes(graph):
    users = get_users(graph)
    roles = get_roles(graph)
    perms = get_permissions(graph)

    assert isinstance(users, list)
    assert isinstance(roles, list)
    assert isinstance(perms, list)
    assert isinstance(get_low_privilege_users(graph), list)
    assert isinstance(get_high_privilege_roles(graph), list)
