import json
from neo4j import GraphDatabase


class IAMGraphBuilder:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def clear_all(self):
        """Delete all nodes and relationships from the database."""
        with self.driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")
        print("Database cleared!")

    def load_data(self, path):
        with open(path) as f:
            data = json.load(f)

        with self.driver.session() as session:
            self._create_nodes(session, data)
            self._create_relationships(session, data)
            self._upsert_dataset_metadata(session, data, path)

        print("Graph loaded successfully!")

    def get_loaded_dataset_metadata(self):
        with self.driver.session() as session:
            record = session.run(
                """
                MATCH (d:DatasetInfo {id: 'active'})
                RETURN d.dataset_id AS dataset_id,
                       d.user_count AS user_count,
                       d.role_count AS role_count,
                       d.permission_count AS permission_count,
                       d.source_path AS source_path,
                       d.loaded_at AS loaded_at
                """
            ).single()
            if record is None:
                return None
            return dict(record)

    def get_graph_stats(self):
        with self.driver.session() as session:
            node_count = session.run("MATCH (n) RETURN count(n) AS c").single()["c"]
            edge_count = session.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]
            return {
                "total_nodes": int(node_count),
                "total_edges": int(edge_count),
            }

    def _create_nodes(self, session, data):

        # Users
        for u in data["users"]:
            session.run(
                "MERGE (u:User {id: $id}) SET u.username = $username",
                id=u["id"], username=u["username"]
            )

        # Roles
        for r in data["roles"]:
            session.run(
                "MERGE (r:Role {id: $id}) "
                "SET r.name = $name, "
                "r.is_overpermissive = $is_overpermissive",
                id=r["id"],
                name=r["name"],
                is_overpermissive=r.get("is_overpermissive", False),
            )

        # Permissions
        for p in data["permissions"]:
            session.run(
                "MERGE (p:Permission {id: $id}) "
                "SET p.action = $action, "
                "p.is_sensitive = $is_sensitive",
                id=p["id"],
                action=p["action"],
                is_sensitive=p.get("is_sensitive", False),
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

    def _upsert_dataset_metadata(self, session, data, source_path):
        metadata = data.get("metadata", {})
        dataset_id = metadata.get("dataset_id", "unknown")
        user_count = metadata.get("user_count", len(data.get("users", [])))
        role_count = metadata.get("role_count", len(data.get("roles", [])))
        permission_count = metadata.get("permission_count", len(data.get("permissions", [])))

        session.run(
            """
            MERGE (d:DatasetInfo {id: 'active'})
            SET d.dataset_id = $dataset_id,
                d.user_count = $user_count,
                d.role_count = $role_count,
                d.permission_count = $permission_count,
                d.source_path = $source_path,
                d.loaded_at = datetime()
            """,
            dataset_id=dataset_id,
            user_count=user_count,
            role_count=role_count,
            permission_count=permission_count,
            source_path=source_path,
        )

    def get_networkx_graph(self):
        import networkx as nx

        G = nx.DiGraph()

        with self.driver.session() as session:
            node_records = session.run("""
                MATCH (n)
                RETURN n.id AS id, labels(n)[0] AS label, properties(n) AS props
            """).data()

            edge_records = session.run("""
                MATCH (a)-[r]->(b)
                RETURN a.id AS src, b.id AS tgt, type(r) AS rel
            """).data()

        for record in node_records:
            attrs = dict(record["props"])
            attrs["label"] = record["label"]
            G.add_node(record["id"], **attrs)

        for record in edge_records:
            G.add_edge(record["src"], record["tgt"], relation=record["rel"])

        return G