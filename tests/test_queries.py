"""Neo4j-backed graph query helper tests.

Uses the shared ``neo4j_builder`` fixture (see conftest.py): skips when Neo4j
is unreachable, runs against the CI service container when present.
"""

from src.graph.queries import (
    get_users,
    get_roles,
    get_permissions,
    get_low_privilege_users,
    get_high_privilege_roles,
)


def test_query_helpers_return_expected_shapes(neo4j_builder):
    graph = neo4j_builder.get_networkx_graph()

    users = get_users(graph)
    roles = get_roles(graph)
    perms = get_permissions(graph)

    assert isinstance(users, list)
    assert isinstance(roles, list)
    assert isinstance(perms, list)
    assert isinstance(get_low_privilege_users(graph), list)
    assert isinstance(get_high_privilege_roles(graph), list)

    # With the seeded sample dataset these must be non-empty.
    assert len(users) > 0
    assert len(roles) > 0
    assert len(perms) > 0
