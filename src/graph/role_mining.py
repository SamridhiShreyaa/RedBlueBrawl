"""Role mining: find near-duplicate / redundant IAM roles for consolidation.

The README promises "role mining using graph algorithms." The legacy
:func:`src.graph.queries.get_high_privilege_roles` only thresholds on a role's
*permission count*, which is not role mining -- it says nothing about which
roles are **redundant with each other**. Real role mining (Kuhlmann/Schimpf,
Vaidya et al.) clusters roles by the *set of permissions they grant* and
surfaces groups whose permission sets overlap so heavily they should be merged.

This module clusters roles on **Jaccard similarity of their permission sets**
(average-linkage agglomerative clustering) and surfaces consolidation
suggestions. The legacy permission-count rule is kept as the ``"count"``
baseline for comparison only.

Why not an embedding (node2vec)?
--------------------------------
A node2vec-over-role-permission-graph variant was implemented and benchmarked
head-to-head against this Jaccard approach on two planted-ground-truth
benchmarks (see ``eval/role_mining_eval.py`` and ``eval/README.md``):

* **exact** near-duplicates: Jaccard won clearly (F1 0.877 vs 0.619 -- the
  embedding over-merged structurally-similar-but-distinct roles).
* **functional** similarity (same-job roles with partial or ZERO exact
  overlap -- the case built to showcase an embedding's edge): a **tie**, both
  perfect. Average-linkage clustering reaches zero-overlap pairs
  *transitively* through the group's cohort roles -- the same co-occurrence
  channel node2vec's random walks exploit -- so plain Jaccard extracts the
  same signal without the dependency.

No benchmark existed where the embedding beat Jaccard-plus-clustering, so per
the pre-registered decision rule it was dropped along with the ``node2vec``
dependency. The full implementation, benchmark evidence, and reproducible
comparison live at the evidence commit (25a2c2c, "functional-similarity
benchmark -- node2vec TIES Jaccard").

Determinism
-----------
Jaccard distances and AgglomerativeClustering are exact set arithmetic and
deterministic linkage -- no seeds, no hash-order sensitivity, identical output
across processes by construction.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from itertools import combinations
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx
import numpy as np

logger = logging.getLogger(__name__)

RolePair = Tuple[str, str]

# Clustering thresholds, tuned by sweeping the role-mining benchmarks
# (eval/role_mining_eval.py) for best mean F1 on planted pairs; sweep tables in
# eval/README.md. Exact near-duplicates sit in a tight similarity band
# (Jaccard >= ~0.7); functionally-similar same-job roles sit in a looser one,
# reached transitively through cohort roles at distance <= ~0.8.
DEFAULT_JACCARD_DISTANCE = 0.30    # exact near-duplicates: similarity >= 0.70
FUNCTIONAL_JACCARD_DISTANCE = 0.80  # functional similarity: perfect F1 band 0.75-0.85


# --------------------------------------------------------------------------
# result types
# --------------------------------------------------------------------------

@dataclass
class ConsolidationSuggestion:
    """A group of roles whose permission sets overlap enough to merge.

    Attributes:
        roles: The role ids in the redundant cluster (>= 2).
        shared_actions: Actions granted by *every* role in the group.
        union_actions: Actions granted by *any* role in the group -- the
            permission set a single merged role would need.
        mean_jaccard: Mean pairwise Jaccard of the group's action sets; how
            tight the redundancy is (1.0 == identical roles).
    """

    roles: List[str]
    shared_actions: Set[str]
    union_actions: Set[str]
    mean_jaccard: float

    def pairs(self) -> List[RolePair]:
        """All unordered role pairs implied by this group (normalized order)."""
        return [_norm_pair(a, b) for a, b in combinations(sorted(self.roles), 2)]


# --------------------------------------------------------------------------
# permission-set extraction
# --------------------------------------------------------------------------

def role_action_sets(graph: nx.DiGraph) -> Dict[str, Set[str]]:
    """Map each Role node to the set of distinct actions it GRANTS.

    Permission grant nodes are collapsed to their ``action`` string, so a role
    that grants the same action twice (two grant nodes) contributes it once.
    """
    sets: Dict[str, Set[str]] = {}
    for node, data in graph.nodes(data=True):
        if data.get("label") != "Role":
            continue
        actions: Set[str] = set()
        for perm in graph.successors(node):
            pdata = graph.nodes[perm]
            if pdata.get("label") == "Permission":
                action = pdata.get("action")
                if action:
                    actions.add(action)
        sets[node] = actions
    return sets


def _norm_pair(a: str, b: str) -> RolePair:
    return (a, b) if a <= b else (b, a)


def _jaccard(a: Set[str], b: Set[str]) -> float:
    if not a and not b:
        return 1.0
    union = a | b
    return len(a & b) / len(union) if union else 0.0


# --------------------------------------------------------------------------
# clustering
# --------------------------------------------------------------------------

def _agglomerative_labels(
    distance_matrix: np.ndarray, distance_threshold: float
) -> np.ndarray:
    """Average-linkage agglomerative clustering on a precomputed distance matrix."""
    from sklearn.cluster import AgglomerativeClustering

    n = distance_matrix.shape[0]
    if n < 2:
        return np.zeros(n, dtype=int)
    model = AgglomerativeClustering(
        n_clusters=None,
        metric="precomputed",
        linkage="average",
        distance_threshold=distance_threshold,
    )
    return model.fit_predict(distance_matrix)


def cluster_by_jaccard(
    graph: nx.DiGraph,
    distance_threshold: float = DEFAULT_JACCARD_DISTANCE,
) -> Dict[str, int]:
    """Cluster roles on Jaccard distance (1 - Jaccard) of their action sets.

    Returns ``{role_id: cluster_label}``; roles sharing a label are mutually
    redundant consolidation candidates (singletons found no peer). Average
    linkage lets a loose threshold also pair *functionally* similar roles
    transitively -- through intermediate roles that overlap both -- which is
    how this method matched a node2vec embedding on the functional benchmark
    (see module docstring). Roles with no permissions are skipped (they cannot
    be anyone's duplicate).
    """
    action_sets = {r: a for r, a in role_action_sets(graph).items() if a}
    if len(action_sets) < 2:
        return {r: i for i, r in enumerate(action_sets)}
    roles = sorted(action_sets)
    n = len(roles)
    dist = np.zeros((n, n), dtype=float)
    for i in range(n):
        for j in range(i + 1, n):
            d = 1.0 - _jaccard(action_sets[roles[i]], action_sets[roles[j]])
            dist[i, j] = dist[j, i] = d
    labels = _agglomerative_labels(dist, distance_threshold)
    return {role: int(lbl) for role, lbl in zip(roles, labels)}


# --------------------------------------------------------------------------
# duplicate-pair extraction + suggestions
# --------------------------------------------------------------------------

def _pairs_from_labels(labels: Dict[str, int]) -> Set[RolePair]:
    """All intra-cluster role pairs from a ``{role: label}`` assignment."""
    groups: Dict[int, List[str]] = {}
    for role, label in labels.items():
        groups.setdefault(label, []).append(role)
    pairs: Set[RolePair] = set()
    for members in groups.values():
        if len(members) < 2:
            continue
        for a, b in combinations(sorted(members), 2):
            pairs.add(_norm_pair(a, b))
    return pairs


def find_near_duplicate_roles(
    graph: nx.DiGraph,
    method: str = "jaccard",
    distance_threshold: Optional[float] = None,
    **kwargs,
) -> Set[RolePair]:
    """Return the set of near-duplicate role pairs found by ``method``.

    Args:
        method: ``"jaccard"`` (set-overlap clustering, the recommended method)
            or ``"count"`` (legacy permission-count threshold, baseline only).
        distance_threshold: Override the clustering threshold (ignored by
            ``"count"``). :data:`DEFAULT_JACCARD_DISTANCE` targets exact
            near-duplicates; pass :data:`FUNCTIONAL_JACCARD_DISTANCE` to also
            capture functionally-similar roles transitively.
        **kwargs: For ``"count"``: ``min_permissions`` (default 5).
    """
    if method == "jaccard":
        thr = DEFAULT_JACCARD_DISTANCE if distance_threshold is None else distance_threshold
        return _pairs_from_labels(cluster_by_jaccard(graph, distance_threshold=thr))
    if method == "count":
        return _count_threshold_pairs(graph, min_permissions=kwargs.get("min_permissions", 5))
    raise ValueError(
        f"unknown role-mining method {method!r}; expected 'jaccard' or 'count' "
        "(the node2vec method was dropped after losing/tying every benchmark "
        "against jaccard -- see eval/README.md)"
    )


def _count_threshold_pairs(graph: nx.DiGraph, min_permissions: int = 5) -> Set[RolePair]:
    """Legacy baseline: every pair among roles that exceed a permission-count.

    This mirrors :func:`src.graph.queries.get_high_privilege_roles` -- it knows
    nothing about *overlap*, so it pairs unrelated big roles. Kept only to show
    how far a count threshold is from real role mining.
    """
    action_sets = role_action_sets(graph)
    big = sorted(r for r, a in action_sets.items() if len(a) >= min_permissions)
    return {_norm_pair(a, b) for a, b in combinations(big, 2)}


def consolidation_suggestions(
    graph: nx.DiGraph,
    method: str = "jaccard",
    distance_threshold: Optional[float] = None,
) -> List[ConsolidationSuggestion]:
    """Human-readable consolidation groups, most-redundant first.

    Clusters roles with Jaccard overlap, then for each multi-role cluster
    reports the shared/union action sets and how tight the overlap is.
    """
    if method != "jaccard":
        raise ValueError(
            f"consolidation_suggestions supports 'jaccard', got {method!r}"
        )
    thr = DEFAULT_JACCARD_DISTANCE if distance_threshold is None else distance_threshold
    labels = cluster_by_jaccard(graph, distance_threshold=thr)

    action_sets = role_action_sets(graph)
    groups: Dict[int, List[str]] = {}
    for role, label in labels.items():
        groups.setdefault(label, []).append(role)

    suggestions: List[ConsolidationSuggestion] = []
    for members in groups.values():
        if len(members) < 2:
            continue
        members = sorted(members)
        sets = [action_sets.get(r, set()) for r in members]
        shared = set.intersection(*sets) if sets else set()
        union = set.union(*sets) if sets else set()
        pair_jacs = [_jaccard(sets[i], sets[j])
                     for i, j in combinations(range(len(members)), 2)]
        mean_j = float(np.mean(pair_jacs)) if pair_jacs else 0.0
        suggestions.append(ConsolidationSuggestion(
            roles=members, shared_actions=shared, union_actions=union,
            mean_jaccard=round(mean_j, 4),
        ))
    suggestions.sort(key=lambda s: s.mean_jaccard, reverse=True)
    return suggestions
