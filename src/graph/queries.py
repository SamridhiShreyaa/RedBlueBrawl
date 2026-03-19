import networkx as nx


# -------------------------------
# BASIC NODE FETCHING
# -------------------------------

def get_users(G: nx.DiGraph):
    return [n for n, d in G.nodes(data=True) if d.get("label") == "User"]


def get_roles(G: nx.DiGraph):
    return [n for n, d in G.nodes(data=True) if d.get("label") == "Role"]


def get_permissions(G: nx.DiGraph):
    return [n for n, d in G.nodes(data=True) if d.get("label") == "Permission"]


# -------------------------------
# RELATIONSHIP QUERIES
# -------------------------------

def get_user_roles(G: nx.DiGraph, user_id: str):
    if not G.has_node(user_id):
        return []
    return [
        node_id
        for node_id in G.successors(user_id)
        if G.nodes[node_id].get("label") == "Role"
    ]


def get_role_permissions(G: nx.DiGraph, role_id: str):
    if not G.has_node(role_id):
        return []
    return list(G.successors(role_id))


def get_user_permissions(G: nx.DiGraph, user_id: str):
    permissions = set()
    roles = get_user_roles(G, user_id)

    for role in roles:
        perms = get_role_permissions(G, role)
        permissions.update(perms)

    return list(permissions)


# -------------------------------
# ANALYSIS HELPERS (IMPORTANT)
# -------------------------------

def get_low_privilege_users(G: nx.DiGraph, max_roles=2):
    """Users with few roles (likely attack entry points)"""
    low_priv = []

    for user in get_users(G):
        roles = get_user_roles(G, user)
        if len(roles) <= max_roles:
            low_priv.append(user)

    return low_priv


def get_high_privilege_roles(G: nx.DiGraph, min_permissions=5):
    """Roles with too many permissions (risky roles)"""
    risky_roles = []

    for role in get_roles(G):
        perms = get_role_permissions(G, role)
        if len(perms) >= min_permissions:
            risky_roles.append(role)

    return risky_roles


# -------------------------------
# GRAPH STATS (FOR DEBUG/UI)
# -------------------------------

def get_graph_summary(G: nx.DiGraph):
    return {
        "users": len(get_users(G)),
        "roles": len(get_roles(G)),
        "permissions": len(get_permissions(G)),
        "edges": G.number_of_edges()
    }