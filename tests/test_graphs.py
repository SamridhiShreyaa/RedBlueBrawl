"""Neo4j-backed graph builder tests.

Uses the shared ``neo4j_builder`` fixture (see conftest.py): skips when Neo4j
is unreachable, runs against the CI service container when present.
"""


def test_graph_has_nodes_and_edges(neo4j_builder):
    G = neo4j_builder.get_networkx_graph()
    assert G.number_of_nodes() > 0
    assert G.number_of_edges() > 0
