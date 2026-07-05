"""Deterministic synthetic-tenant generation with planted privesc chains.

Given a fixed seed and difficulty knobs, :func:`generate_tenant` produces an
IAM graph in which a handful of named AWS privilege-escalation chains are
buried among benign distractor roles/users. The exact planted paths and the
edges whose removal breaks them are recorded as ground truth on the returned
:class:`~eval.tenant.Tenant`.

Difficulty axes:
    * ``chain_length`` (2..5): number of role hops from entry user to admin.
    * ``density`` ("low"/"medium"/"high"): how many benign distractor roles
      and users surround the planted chains.

Design choices that make grading unambiguous:
    * Every permission grant is its own node (id ``"<role>::<action>"``), so a
      permission node is risky iff it sits on a planted chain -- no aliasing
      between a chain's ``iam:PassRole`` and a distractor's.
    * Privilege-escalation *technique* actions appear ONLY on planted chains.
      Distractor roles may hold destructive-but-not-escalating sensitive
      actions (``s3:DeleteObject`` etc.) to create realistic false-positive
      pressure: "sensitive" is not the same as "exploitable escalation".
"""

from __future__ import annotations

import random
from typing import Dict, List, Tuple

import networkx as nx

from eval.tenant import PlantedChain, Tenant

Edge = Tuple[str, str]

# Named AWS privilege-escalation techniques. These appear ONLY on planted
# chains, cycled per hop so a length-4 chain reads as a real escalation story
# (e.g. CreatePolicyVersion -> AttachRolePolicy -> PassRole -> admin).
TECHNIQUE_ACTIONS: List[str] = [
    "iam:CreatePolicyVersion",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:PassRole",
    "iam:CreateAccessKey",
    "iam:UpdateAssumeRolePolicy",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy",
]

# Admin sink: >=5 permissions so RedAgent flags it as a high-privilege target.
ADMIN_ACTIONS: List[str] = [
    "iam:*",
    "sts:AssumeRole",
    "iam:CreateUser",
    "iam:AttachRolePolicy",
    "iam:PassRole",
    "iam:PutRolePolicy",
]

# Genuinely harmless actions used to pad distractor roles.
BENIGN_ACTIONS: List[str] = [
    "s3:GetObject",
    "s3:PutObject",
    "logs:CreateLogStream",
    "cloudwatch:PutMetricData",
    "ec2:DescribeInstances",
    "dynamodb:GetItem",
    "sqs:SendMessage",
    "sns:Publish",
]

# Sensitive but NOT privilege-escalating. A method that flags "anything
# sensitive" will trip over these and lose precision -- which is the point.
DISTRACTOR_SENSITIVE_ACTIONS: List[str] = [
    "s3:DeleteObject",
    "kms:Decrypt",
    "ec2:TerminateInstances",
]

ASSUME_ACTION = "sts:AssumeRole"

DENSITY_PRESETS: Dict[str, Dict[str, int]] = {
    "low": {"distractor_roles": 8, "distractor_users": 15},
    "medium": {"distractor_roles": 25, "distractor_users": 50},
    "high": {"distractor_roles": 60, "distractor_users": 120},
}


def _perm_id(role_id: str, action: str, suffix: str = "") -> str:
    return f"{role_id}::{action}{suffix}"


def _add_permission(graph: nx.DiGraph, role_id: str, action: str,
                    is_sensitive: bool, suffix: str = "") -> str:
    """Create a per-grant permission node and the GRANTS edge from ``role_id``."""
    perm_id = _perm_id(role_id, action, suffix)
    graph.add_node(perm_id, label="Permission", action=action,
                   is_sensitive=is_sensitive)
    graph.add_edge(role_id, perm_id, relation="GRANTS")
    return perm_id


def _plant_chain(graph: nx.DiGraph, chain_index: int, chain_length: int,
                 rng: random.Random) -> PlantedChain:
    """Bury one escalation chain of ``chain_length`` role hops into ``graph``."""
    cid = f"c{chain_index}"
    entry_user = f"u_{cid}_entry"
    graph.add_node(entry_user, label="User", username=entry_user)

    nodes: List[str] = [entry_user]
    edges: List[Edge] = []
    breaking_edges: List[Edge] = []
    risky_perms: List[str] = []
    roles: List[str] = []
    techniques: List[str] = []

    # chain_length counts roles: (chain_length - 1) pivot hops + 1 admin sink.
    n_pivots = max(1, chain_length - 1)

    prev_hop_role = None
    for hop in range(n_pivots):
        role_id = f"r_{cid}_h{hop}"
        graph.add_node(role_id, label="Role", name=role_id, is_overpermissive=True)
        roles.append(role_id)
        nodes.append(role_id)

        # Entry user holds only the first hop; deeper hops are reached by
        # assuming, so they stay "buried" (no direct user ownership).
        if hop == 0:
            graph.add_edge(entry_user, role_id, relation="HAS_ROLE")
            edges.append((entry_user, role_id))
            breaking_edges.append((entry_user, role_id))

        # The escalation technique for this hop.
        action = TECHNIQUE_ACTIONS[hop % len(TECHNIQUE_ACTIONS)]
        techniques.append(action)
        tech_perm = _add_permission(graph, role_id, action, is_sensitive=True)
        risky_perms.append(tech_perm)
        edges.append((role_id, tech_perm))
        breaking_edges.append((role_id, tech_perm))

        # An assume grant so the next hop is reachable (and so the project's
        # RedAgent assume-role inference has something to follow).
        assume_perm = _add_permission(graph, role_id, ASSUME_ACTION,
                                      is_sensitive=True, suffix="__assume")
        risky_perms.append(assume_perm)
        edges.append((role_id, assume_perm))
        breaking_edges.append((role_id, assume_perm))

        prev_hop_role = role_id

    # Admin sink at the end of the chain.
    admin_role = f"r_{cid}_admin"
    graph.add_node(admin_role, label="Role", name=admin_role, is_overpermissive=True)
    roles.append(admin_role)
    nodes.append(admin_role)
    for action in ADMIN_ACTIONS:
        admin_perm = _add_permission(graph, admin_role, action, is_sensitive=True)
        risky_perms.append(admin_perm)
        # Admin's own grants participate in the chain (not collateral if cut)
        # but do NOT gate reachability, so they are not breaking edges.
        edges.append((admin_role, admin_perm))

    # Bury the entry user a little: optionally give them one benign role too,
    # keeping them at <=2 roles so they still read as a low-privilege user.
    return PlantedChain(
        chain_id=cid,
        technique_actions=techniques,
        nodes=nodes,
        edges=edges,
        breaking_edges=breaking_edges,
        risky_perms=risky_perms,
        roles=roles,
    )


def _add_distractors(graph: nx.DiGraph, n_roles: int, n_users: int,
                     rng: random.Random) -> List[str]:
    """Populate the tenant with benign roles/users. Returns distractor role ids."""
    distractor_roles: List[str] = []
    for i in range(n_roles):
        role_id = f"r_d{i}"
        graph.add_node(role_id, label="Role", name=role_id, is_overpermissive=False)
        distractor_roles.append(role_id)

        n_perms = rng.randint(2, 6)
        for _ in range(n_perms):
            # Mostly benign, occasionally a sensitive-but-not-escalating action.
            if rng.random() < 0.25:
                action = rng.choice(DISTRACTOR_SENSITIVE_ACTIONS)
                sensitive = True
            else:
                action = rng.choice(BENIGN_ACTIONS)
                sensitive = False
            _add_permission(graph, role_id, action, is_sensitive=sensitive,
                            suffix=f"__{rng.randrange(1_000_000)}")

    for i in range(n_users):
        user_id = f"u_d{i}"
        graph.add_node(user_id, label="User", username=user_id)
        if distractor_roles:
            k = rng.randint(1, min(3, len(distractor_roles)))
            for role_id in rng.sample(distractor_roles, k):
                graph.add_edge(user_id, role_id, relation="HAS_ROLE")

    return distractor_roles


def generate_tenant(seed: int, chain_length: int = 3, density: str = "low",
                    n_chains: int = 3) -> Tenant:
    """Deterministically build a tenant with ``n_chains`` planted escalations.

    Args:
        seed: RNG seed; identical (seed, params) always yield an identical graph.
        chain_length: Number of role hops per chain (2..5 recommended).
        density: One of ``"low"``, ``"medium"``, ``"high"`` (distractor volume).
        n_chains: How many independent escalation chains to plant.

    Returns:
        A :class:`~eval.tenant.Tenant` carrying the graph and ground truth.
    """
    if density not in DENSITY_PRESETS:
        raise ValueError(
            f"density must be one of {sorted(DENSITY_PRESETS)}, got {density!r}"
        )
    if chain_length < 2:
        raise ValueError("chain_length must be >= 2")

    rng = random.Random(seed)
    graph = nx.DiGraph()

    chains: List[PlantedChain] = []
    for ci in range(n_chains):
        chains.append(_plant_chain(graph, ci, chain_length, rng))

    preset = DENSITY_PRESETS[density]
    distractor_roles = _add_distractors(
        graph, preset["distractor_roles"], preset["distractor_users"], rng
    )

    # Sprinkle each chain's entry user into the benign population so the
    # escalation entry points are not trivially isolated.
    for chain in chains:
        entry_user = chain.nodes[0]
        if distractor_roles:
            role_id = rng.choice(distractor_roles)
            if not graph.has_edge(entry_user, role_id):
                graph.add_edge(entry_user, role_id, relation="HAS_ROLE")

    tenant_id = f"seed{seed}_len{chain_length}_{density}_n{n_chains}"
    return Tenant(tenant_id=tenant_id, graph=graph, chains=chains)
