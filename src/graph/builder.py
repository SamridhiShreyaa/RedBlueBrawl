import json
from neo4j import GraphDatabase


class IAMGraphBuilder:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def load_data(self, path):
        with open(path) as f:
            data = json.load(f)

        with self.driver.session() as session:
            self._create_nodes(session, data)
            self._create_relationships(session, data)

        print("Graph loaded successfully!")

    def _create_nodes(self, session, data):

        # Users
        for u in data["users"]:
            session.run(
                "MERGE (u:User {id: $id, username: $username})",
                id=u["id"], username=u["username"]
            )

        # Roles
        for r in data["roles"]:
            session.run(
                "MERGE (r:Role {id: $id, name: $name})",
                id=r["id"], name=r["name"]
            )

        # Permissions
        for p in data["permissions"]:
            session.run(
                "MERGE (p:Permission {id: $id, action: $action})",
                id=p["id"], action=p["action"]
            )

    def _create_relationships(self, session, data):

        # User -> Role
        for u in data["users"]:
            for role_id in u["roles"]:
                session.run("""
                    MATCH (u:User {id: $uid})
                    MATCH (r:Role {id: $rid})
                    MERGE (u)-[:HAS_ROLE]->(r)
                """, uid=u["id"], rid=role_id)

        # Role -> Permission
        for r in data["roles"]:
            for perm_id in r["permissions"]:
                session.run("""
                    MATCH (r:Role {id: $rid})
                    MATCH (p:Permission {id: $pid})
                    MERGE (r)-[:GRANTS]->(p)
                """, rid=r["id"], pid=perm_id)

    def get_networkx_graph(self):
        import networkx as nx

        G = nx.DiGraph()

    # open fresh session
        with self.driver.session() as session:
         records = session.run(
            "MATCH (a)-[r]->(b) RETURN a.id AS src, b.id AS tgt"
        ).data()   

    # process OUTSIDE session
         for record in records:
                 G.add_edge(record["src"], record["tgt"])

        return G