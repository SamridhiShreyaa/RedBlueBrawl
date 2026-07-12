"""Data structures describing a synthetic tenant and its ground truth.

A :class:`Tenant` bundles a NetworkX IAM graph (same schema the rest of the
project uses: ``User -[HAS_ROLE]-> Role -[GRANTS]-> Permission`` with
``label`` / ``action`` / ``is_sensitive`` node attributes) together with the
list of :class:`PlantedChain` objects we deliberately buried in it.

Everything a scorer needs to grade a method lives on the tenant, so metrics
never have to re-derive "what was risky" from heuristics — it is recorded at
generation time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Set, Tuple

import networkx as nx

Edge = Tuple[str, str]


@dataclass
class PlantedChain:
    """A single deliberately-planted privilege-escalation path.

    Attributes:
        chain_id: Stable identifier within the tenant.
        technique_actions: Ordered AWS actions that make up the escalation
            (e.g. ``["iam:CreatePolicyVersion", "iam:AttachRolePolicy"]``).
        nodes: Ordered node ids along the escalation (user, roles, admin).
        edges: Every edge planted for this chain, including the admin role's
            own permission grants. Used for collateral accounting.
        breaking_edges: The subset of edges whose removal severs the
            escalation *route* (entry + assume/technique hops). Removing any
            one of them breaks the chain.
        risky_perms: Permission node ids that lie on the chain. These are the
            ground-truth positives for risky-permission detection.
        roles: Role node ids on the chain (used to detect node-removal breaks).
    """

    chain_id: str
    technique_actions: List[str]
    nodes: List[str]
    edges: List[Edge]
    breaking_edges: List[Edge]
    risky_perms: List[str]
    roles: List[str]

    def is_broken_by(self, removed_edges: Set[Edge], removed_nodes: Set[str]) -> bool:
        """Return True if this planted route no longer holds.

        The route is broken when any breaking edge was cut, or any role/user
        node on the chain was deleted outright.
        """
        if any(edge in removed_edges for edge in self.breaking_edges):
            return True
        if any(node in removed_nodes for node in self.nodes):
            return True
        return False


@dataclass
class Tenant:
    """A synthetic IAM graph plus the ground truth planted inside it."""

    tenant_id: str
    graph: nx.DiGraph
    chains: List[PlantedChain] = field(default_factory=list)
    # Ground truth for role mining: (role_a, role_b) pairs deliberately planted
    # to be near-duplicates (same permission set +/- 1-2 grants). Empty unless
    # the tenant was generated with ``n_duplicate_pairs > 0``.
    duplicate_role_pairs: List[Edge] = field(default_factory=list)

    # --- ground-truth views -------------------------------------------------

    def planted_duplicate_pairs(self) -> Set[Edge]:
        """Planted near-duplicate role pairs as a set of normalized tuples."""
        return {tuple(sorted(pair)) for pair in self.duplicate_role_pairs}

    def chain_roles(self) -> Set[str]:
        """Every role that belongs to a planted escalation chain.

        The role-mining benchmark scores over *non-chain* roles: planted
        escalation chains create structurally-identical roles across chains
        (a separate experiment), which would otherwise pollute duplicate-pair
        ground truth.
        """
        roles: Set[str] = set()
        for chain in self.chains:
            roles.update(chain.roles)
        return roles

    def all_permissions(self) -> Set[str]:
        return {
            n for n, d in self.graph.nodes(data=True)
            if d.get("label") == "Permission"
        }

    def risky_permissions(self) -> Set[str]:
        """Permission nodes on any planted chain (ground-truth positives)."""
        risky: Set[str] = set()
        for chain in self.chains:
            risky.update(chain.risky_perms)
        return risky

    def benign_permissions(self) -> Set[str]:
        return self.all_permissions() - self.risky_permissions()

    def participating_edges(self) -> Set[Edge]:
        """Every edge that belongs to a planted chain.

        Removing one of these during remediation is legitimate; removing any
        edge *outside* this set is collateral damage to benign access.
        """
        edges: Set[Edge] = set()
        for chain in self.chains:
            edges.update(chain.edges)
        return edges
