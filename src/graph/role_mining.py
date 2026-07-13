"""Role mining: find near-duplicate / redundant IAM roles for consolidation.

The README promises "role mining using graph algorithms." The legacy
:func:`src.graph.queries.get_high_privilege_roles` only thresholds on a role's
*permission count*, which is not role mining -- it says nothing about which
roles are **redundant with each other**. Real role mining (Kuhlmann/Schimpf,
Vaidya et al.) clusters roles by the *set of permissions they grant* and
surfaces groups whose permission sets overlap so heavily they should be merged.

This module implements that with **node2vec embeddings over a role-permission
bipartite graph**, plus two baselines so the embedding approach is judged
honestly rather than against a straw man:

* ``node2vec`` -- embed each role from the structure of the role-permission
  graph, then cluster the embeddings; roles landing in the same cluster are
  consolidation candidates.
* ``jaccard`` -- cluster roles directly on Jaccard similarity of their
  permission (action) sets. This is the strong, obvious baseline: if node2vec
  cannot beat exact set-overlap, we say so.
* ``count`` -- the legacy permission-count threshold, kept only as a floor.

Why a role-permission **bipartite projection** and not the raw IAM graph
-----------------------------------------------------------------------
In the project's graph every permission *grant* is its own node
(``"<role>::<action>"``), so two roles with identical permission sets connect
to **disjoint** grant nodes -- structurally they look unrelated, and node2vec
walks would never bring them together. Collapsing grants to a single node per
distinct **action** is what makes two roles that grant the same actions
adjacent (distance 2, through the shared action nodes). We drop User nodes
entirely: role mining is about role<->permission redundancy, not who holds a
role. This projection is the standard object the role-mining literature
operates on.

Determinism
-----------
Embeddings are deterministic **across processes**, not just within one:

* node2vec walks and gensim Word2Vec are seeded and run single-worker;
* gensim is given a stable ``hashfxn`` (:func:`stable_hash`, md5-based) instead
  of Python's builtin ``hash``, whose value for strings changes per interpreter
  launch unless ``PYTHONHASHSEED`` is pinned -- gensim seeds each token's
  initial vector from it, so the builtin would make embeddings differ run to
  run. Pinning the hash function at the source is strictly stronger than
  requiring every caller to export ``PYTHONHASHSEED``;
* the projection is built in sorted order (set iteration order is also
  hash-randomized, and graph insertion order feeds the walk order).

AgglomerativeClustering is deterministic. ``tests/test_role_mining.py`` proves
cross-process determinism by embedding the same graph in subprocesses launched
with *different* ``PYTHONHASHSEED`` values.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from itertools import combinations
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx
import numpy as np

logger = logging.getLogger(__name__)

RolePair = Tuple[str, str]

# Node-name prefixes keep role ids and action strings from ever colliding in
# the bipartite projection (a role literally named "s3:GetObject" would
# otherwise merge with the action node).
ROLE_PREFIX = "role::"
ACTION_PREFIX = "action::"

# node2vec / clustering defaults, calibrated on the eval tenants (see
# eval/role_mining_eval.py). Exposed as function args so they can be tuned.
DEFAULT_DIMENSIONS = 64
DEFAULT_WALK_LENGTH = 30
DEFAULT_NUM_WALKS = 100
DEFAULT_WINDOW = 5
DEFAULT_SEED = 42

# Clustering thresholds, tuned by sweeping the role-mining benchmark
# (eval/role_mining_eval.py) for best mean F1 on planted duplicate pairs:
#   * node2vec  cosine distance 0.15  (F1 ~0.57; looser 0.30 collapses to ~0.15
#     as it over-merges distractors, tighter 0.05 starves recall)
#   * jaccard   distance 0.30, i.e. Jaccard similarity >= 0.70  (F1 ~0.88)
# The gap is the honest headline: on exact-overlap duplicate detection the
# Jaccard baseline beats node2vec (see eval/README.md).
DEFAULT_COSINE_DISTANCE = 0.15
DEFAULT_JACCARD_DISTANCE = 0.30

# Operating points for the FUNCTIONAL-similarity benchmark (same-job roles with
# partial/zero exact overlap; see eval/role_mining_eval.py). Functional pairs
# embed in a looser band (cosine sim ~0.45-0.75) than exact near-duplicates
# (~0.85+), so both methods get their own symmetrically-swept threshold --
# each method's best mean F1 on that benchmark, same procedure as the exact
# thresholds above. Sweep (seeds 0-2 x low/medium):
#   * node2vec  perfect F1 band at cosine distance 0.40-0.55 (0.60 -> 0.917,
#     0.65 -> 0.344 as distractor blobs merge in); midpoint 0.50 chosen.
#   * jaccard   perfect F1 band at distance 0.75-0.85 (0.70 -> 0.952,
#     0.90 -> 0.250 total collapse); midpoint 0.80 chosen. Jaccard reaches
#     zero-exact-overlap pairs TRANSITIVELY: average-linkage clustering merges
#     the pair through group cohorts each role overlaps -- the same
#     co-occurrence channel node2vec walks. That transitivity is why the
#     functional benchmark ended in a tie (see eval/README.md).
FUNCTIONAL_COSINE_DISTANCE = 0.50
FUNCTIONAL_JACCARD_DISTANCE = 0.80


def stable_hash(token: str) -> int:
    """Deterministic string hash for gensim (md5-based, PYTHONHASHSEED-proof).

    gensim seeds each vocabulary token's initial vector from ``hashfxn(token)``;
    the default is Python's builtin ``hash``, which is salted per interpreter
    launch, making embeddings irreproducible across processes. This replacement
    pins cross-process determinism at the source.
    """
    return int(hashlib.md5(str(token).encode("utf-8")).hexdigest()[:8], 16)


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
# projection helpers
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


def build_role_action_graph(graph: nx.DiGraph) -> nx.Graph:
    """Project the IAM graph onto an undirected role<->action bipartite graph.

    Nodes are prefixed (:data:`ROLE_PREFIX` / :data:`ACTION_PREFIX`) and tagged
    with a ``kind`` attribute. An edge ``role -- action`` exists iff the role
    grants that action. Roles with no permissions still appear as isolated
    nodes so they are represented (they simply cannot be anyone's duplicate).
    """
    proj = nx.Graph()
    for role, actions in role_action_sets(graph).items():
        rnode = ROLE_PREFIX + role
        proj.add_node(rnode, kind="role", role_id=role)
        # Sorted: set iteration order is hash-randomized per interpreter launch,
        # and graph insertion order feeds node2vec's walk order -- unsorted
        # iteration would silently break cross-process determinism.
        for action in sorted(actions):
            anode = ACTION_PREFIX + action
            proj.add_node(anode, kind="action", action=action)
            proj.add_edge(rnode, anode)
    return proj


def _norm_pair(a: str, b: str) -> RolePair:
    return (a, b) if a <= b else (b, a)


def _jaccard(a: Set[str], b: Set[str]) -> float:
    if not a and not b:
        return 1.0
    union = a | b
    return len(a & b) / len(union) if union else 0.0


# --------------------------------------------------------------------------
# node2vec embedding
# --------------------------------------------------------------------------

def embed_roles(
    graph: nx.DiGraph,
    dimensions: int = DEFAULT_DIMENSIONS,
    walk_length: int = DEFAULT_WALK_LENGTH,
    num_walks: int = DEFAULT_NUM_WALKS,
    window: int = DEFAULT_WINDOW,
    seed: int = DEFAULT_SEED,
) -> Dict[str, np.ndarray]:
    """Return ``{role_id: embedding_vector}`` from node2vec over the projection.

    Deterministic for a fixed ``seed`` within a process: node2vec walks are
    seeded and gensim runs single-worker. Roles that grant no permissions are
    skipped (they have no structural context to embed and cannot be duplicates).
    """
    from node2vec import Node2Vec  # local import: heavy (gensim) dependency

    proj = build_role_action_graph(graph)
    role_nodes = [n for n, d in proj.nodes(data=True) if d.get("kind") == "role"]
    # Node2Vec/gensim need a positive-degree node to walk from; drop isolates.
    connected_roles = [n for n in role_nodes if proj.degree(n) > 0]
    if len(connected_roles) < 2:
        return {}

    n2v = Node2Vec(
        proj,
        dimensions=dimensions,
        walk_length=walk_length,
        num_walks=num_walks,
        workers=1,
        seed=seed,
        quiet=True,
    )
    # hashfxn=stable_hash pins gensim's per-token init vectors so embeddings
    # reproduce across interpreter launches (see module docstring).
    model = n2v.fit(window=window, min_count=1, batch_words=4, seed=seed,
                    workers=1, hashfxn=stable_hash)

    embeddings: Dict[str, np.ndarray] = {}
    for rnode in connected_roles:
        role_id = proj.nodes[rnode]["role_id"]
        embeddings[role_id] = np.asarray(model.wv[rnode], dtype=float)
    return embeddings


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


def _cosine_distance_matrix(vectors: np.ndarray) -> np.ndarray:
    """Pairwise cosine *distance* (1 - cosine similarity), clipped to [0, 2]."""
    norms = np.linalg.norm(vectors, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    unit = vectors / norms
    sim = np.clip(unit @ unit.T, -1.0, 1.0)
    dist = 1.0 - sim
    np.fill_diagonal(dist, 0.0)
    return dist


def cluster_by_node2vec(
    graph: nx.DiGraph,
    distance_threshold: float = DEFAULT_COSINE_DISTANCE,
    **embed_kwargs,
) -> Dict[str, int]:
    """Embed roles with node2vec and cluster them; ``{role_id: cluster_label}``.

    Roles in the same label are mutually near-duplicate consolidation
    candidates. Singleton clusters mean "no redundant peer found".
    """
    embeddings = embed_roles(graph, **embed_kwargs)
    if len(embeddings) < 2:
        return {r: i for i, r in enumerate(embeddings)}
    roles = sorted(embeddings)
    vectors = np.vstack([embeddings[r] for r in roles])
    labels = _agglomerative_labels(_cosine_distance_matrix(vectors), distance_threshold)
    return {role: int(lbl) for role, lbl in zip(roles, labels)}


def cluster_by_jaccard(
    graph: nx.DiGraph,
    distance_threshold: float = DEFAULT_JACCARD_DISTANCE,
) -> Dict[str, int]:
    """Cluster roles on Jaccard distance (1 - Jaccard) of their action sets.

    The strong baseline: same clustering machinery as :func:`cluster_by_node2vec`
    but on exact set overlap instead of learned embeddings.
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
    method: str = "node2vec",
    distance_threshold: Optional[float] = None,
    **kwargs,
) -> Set[RolePair]:
    """Return the set of near-duplicate role pairs found by ``method``.

    Args:
        method: ``"node2vec"`` (embedding clustering), ``"jaccard"`` (set-overlap
            clustering), or ``"count"`` (legacy permission-count threshold).
        distance_threshold: Override the method's default clustering threshold
            (ignored by ``"count"``).
        **kwargs: For ``"node2vec"``: passed to :func:`embed_roles`. For
            ``"count"``: ``min_permissions`` (default 5).
    """
    if method == "node2vec":
        thr = DEFAULT_COSINE_DISTANCE if distance_threshold is None else distance_threshold
        return _pairs_from_labels(cluster_by_node2vec(graph, distance_threshold=thr, **kwargs))
    if method == "jaccard":
        thr = DEFAULT_JACCARD_DISTANCE if distance_threshold is None else distance_threshold
        return _pairs_from_labels(cluster_by_jaccard(graph, distance_threshold=thr))
    if method == "count":
        return _count_threshold_pairs(graph, min_permissions=kwargs.get("min_permissions", 5))
    raise ValueError(
        f"unknown role-mining method {method!r}; expected 'node2vec', 'jaccard' or 'count'"
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
    method: str = "node2vec",
    distance_threshold: Optional[float] = None,
    **kwargs,
) -> List[ConsolidationSuggestion]:
    """Human-readable consolidation groups, most-redundant first.

    Clusters roles with ``method``, then for each multi-role cluster reports the
    shared/union action sets and how tight the overlap is. Only ``node2vec`` and
    ``jaccard`` produce meaningful groups; ``count`` has no cluster structure.
    """
    if method == "node2vec":
        thr = DEFAULT_COSINE_DISTANCE if distance_threshold is None else distance_threshold
        labels = cluster_by_node2vec(graph, distance_threshold=thr, **kwargs)
    elif method == "jaccard":
        thr = DEFAULT_JACCARD_DISTANCE if distance_threshold is None else distance_threshold
        labels = cluster_by_jaccard(graph, distance_threshold=thr)
    else:
        raise ValueError(
            f"consolidation_suggestions supports 'node2vec' or 'jaccard', got {method!r}"
        )

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
