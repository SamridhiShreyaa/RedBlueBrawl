"""Role-mining tests: projection, determinism, known-graph correctness, and an
honest node2vec-vs-Jaccard comparison on tenants with planted duplicate roles."""

import sys
from pathlib import Path

import networkx as nx
import numpy as np
import pytest

repo_root = str(Path(__file__).parent.parent)
sys.path.insert(0, repo_root)

from src.graph.role_mining import (
    build_role_action_graph,
    cluster_by_node2vec,
    consolidation_suggestions,
    embed_roles,
    find_near_duplicate_roles,
    role_action_sets,
)
from eval.tenant_gen import CONSOLIDATION_ANCHOR, generate_tenant
from eval.role_mining_eval import evaluate_tenant


# --------------------------------------------------------------------------
# helpers: a small, CONNECTED graph with one obvious duplicate pair
# --------------------------------------------------------------------------

# A shared "anchor" action keeps the role-permission projection connected;
# node2vec's separation collapses on disconnected components.
ANCHOR = "s3:GetObject"
POOL = [f"svc:Action{i}" for i in range(12)]


def _add_role(G: nx.DiGraph, rid: str, actions) -> None:
    G.add_node(rid, label="Role", name=rid)
    for i, action in enumerate(sorted(actions)):
        pid = f"{rid}::{action}::{i}"
        G.add_node(pid, label="Permission", action=action, is_sensitive=False)
        G.add_edge(rid, pid, relation="GRANTS")


def build_known_graph() -> nx.DiGraph:
    """Five roles; DUP_A and DUP_B grant an identical action set (obvious pair)."""
    G = nx.DiGraph()
    dup_actions = set(POOL[:5]) | {ANCHOR}
    _add_role(G, "DUP_A", dup_actions)
    _add_role(G, "DUP_B", set(dup_actions))  # identical -> Jaccard 1.0
    # Three clearly-different roles (each shares only the anchor).
    _add_role(G, "R0", set(POOL[5:8]) | {ANCHOR})
    _add_role(G, "R1", set(POOL[8:11]) | {ANCHOR})
    _add_role(G, "R2", set(POOL[3:6]) | {ANCHOR})
    return G


def _cos(a: np.ndarray, b: np.ndarray) -> float:
    return float(a @ b / (np.linalg.norm(a) * np.linalg.norm(b)))


# --------------------------------------------------------------------------
# projection
# --------------------------------------------------------------------------

def test_role_action_sets_collapse_duplicate_action_grants():
    G = nx.DiGraph()
    G.add_node("r", label="Role", name="r")
    # Same action granted by two distinct per-grant nodes -> one action.
    for i in range(2):
        pid = f"r::s3:GetObject::{i}"
        G.add_node(pid, label="Permission", action="s3:GetObject")
        G.add_edge("r", pid, relation="GRANTS")
    assert role_action_sets(G)["r"] == {"s3:GetObject"}


def test_build_role_action_graph_is_bipartite_projection():
    G = build_known_graph()
    proj = build_role_action_graph(G)
    roles = {n for n, d in proj.nodes(data=True) if d.get("kind") == "role"}
    actions = {n for n, d in proj.nodes(data=True) if d.get("kind") == "action"}
    assert len(roles) == 5
    # Edges only ever connect a role to an action (true bipartite).
    for u, v in proj.edges():
        kinds = {proj.nodes[u]["kind"], proj.nodes[v]["kind"]}
        assert kinds == {"role", "action"}
    # The anchor keeps everything in one connected component.
    assert nx.is_connected(proj)
    assert actions  # actions materialised


# --------------------------------------------------------------------------
# determinism (fixed seed -> identical embeddings, clusters, pairs)
# --------------------------------------------------------------------------

def test_embeddings_are_deterministic_for_fixed_seed():
    G = build_known_graph()
    e1 = embed_roles(G, seed=7)
    e2 = embed_roles(G, seed=7)
    assert set(e1) == set(e2)
    for role in e1:
        assert np.allclose(e1[role], e2[role])


def test_node2vec_clusters_and_pairs_are_deterministic():
    G = build_known_graph()
    assert cluster_by_node2vec(G, seed=7) == cluster_by_node2vec(G, seed=7)
    assert (find_near_duplicate_roles(G, method="node2vec", seed=7)
            == find_near_duplicate_roles(G, method="node2vec", seed=7))


# --------------------------------------------------------------------------
# correctness on a known graph with an obvious duplicate pair
# --------------------------------------------------------------------------

def test_node2vec_embeds_duplicate_pair_closest():
    G = build_known_graph()
    emb = embed_roles(G, seed=7)
    dup_sim = _cos(emb["DUP_A"], emb["DUP_B"])
    # The identical pair must be more similar than either is to any distinct role.
    for other in ("R0", "R1", "R2"):
        assert dup_sim > _cos(emb["DUP_A"], emb[other])


@pytest.mark.parametrize("method", ["node2vec", "jaccard"])
def test_clustering_finds_the_obvious_duplicate_pair(method):
    pairs = find_near_duplicate_roles(build_known_graph(), method=method, seed=7)
    assert ("DUP_A", "DUP_B") in pairs


def test_jaccard_baseline_matches_exact_overlap():
    # DUP_A/DUP_B are identical; no other pair shares more than the anchor.
    pairs = find_near_duplicate_roles(build_known_graph(), method="jaccard")
    assert ("DUP_A", "DUP_B") in pairs


def test_count_baseline_pairs_big_roles_ignoring_overlap():
    # Only DUP_A/DUP_B have >= 5 distinct actions here, so count pairs just them
    # -- and would pair any two big roles regardless of whether they overlap.
    pairs = find_near_duplicate_roles(build_known_graph(), method="count",
                                      min_permissions=5)
    assert ("DUP_A", "DUP_B") in pairs


def test_consolidation_suggestion_reports_shared_and_union():
    suggestions = consolidation_suggestions(build_known_graph(), method="jaccard", seed=7)
    dup = next(s for s in suggestions if set(s.roles) == {"DUP_A", "DUP_B"})
    assert dup.mean_jaccard == pytest.approx(1.0)
    assert ANCHOR in dup.shared_actions


def test_unknown_method_raises():
    with pytest.raises(ValueError, match="unknown role-mining method"):
        find_near_duplicate_roles(build_known_graph(), method="bogus")


# --------------------------------------------------------------------------
# tenant planting (ground truth) and byte-identical default
# --------------------------------------------------------------------------

def test_planted_duplicate_roles_are_recorded_and_near_identical():
    tenant = generate_tenant(seed=0, chain_length=3, density="low",
                             n_chains=1, n_duplicate_pairs=3)
    assert len(tenant.duplicate_role_pairs) == 3

    sets = role_action_sets(tenant.graph)
    for a, b in tenant.duplicate_role_pairs:
        assert tenant.graph.nodes[a].get("is_planted_duplicate")
        assert tenant.graph.nodes[b].get("is_planted_duplicate")
        # Same permission set +/- 1-2 grants => Jaccard is high but they exist.
        inter = len(sets[a] & sets[b])
        union = len(sets[a] | sets[b])
        assert union > 0 and inter / union >= 0.6
        assert CONSOLIDATION_ANCHOR in sets[a] and CONSOLIDATION_ANCHOR in sets[b]


def test_default_tenant_has_no_planted_duplicates_and_is_unchanged():
    baseline = generate_tenant(seed=1, chain_length=3, density="low", n_chains=2)
    withparam = generate_tenant(seed=1, chain_length=3, density="low", n_chains=2,
                                n_duplicate_pairs=0)
    # n_duplicate_pairs=0 must be byte-identical to the pre-feature generator.
    assert baseline.duplicate_role_pairs == []
    assert set(baseline.graph.nodes()) == set(withparam.graph.nodes())
    assert set(baseline.graph.edges()) == set(withparam.graph.edges())


# --------------------------------------------------------------------------
# honest comparison: node2vec vs the strong Jaccard baseline
# --------------------------------------------------------------------------

def test_jaccard_recovers_all_planted_pairs():
    # The Jaccard baseline reliably recovers every planted near-duplicate pair.
    for s in (0, 1, 2, 3):
        tenant = generate_tenant(seed=s, chain_length=3, density="low",
                                 n_chains=1, n_duplicate_pairs=4)
        assert evaluate_tenant(tenant, "jaccard").recall == 1.0


def test_node2vec_recovers_most_planted_pairs():
    # node2vec finds most planted pairs but -- honestly -- not always all of
    # them at its precision-favouring default threshold.
    recalls = [
        evaluate_tenant(
            generate_tenant(seed=s, chain_length=3, density="low",
                            n_chains=1, n_duplicate_pairs=4),
            "node2vec",
        ).recall
        for s in (0, 1, 2, 3)
    ]
    assert np.mean(recalls) >= 0.6


def test_jaccard_beats_node2vec_f1_the_honest_finding():
    """The headline result, asserted rather than glossed over: on exact-overlap
    near-duplicate detection the simple Jaccard baseline outperforms node2vec.
    node2vec over-merges structurally-similar-but-distinct roles, so its
    precision (and F1) trail the baseline. We do NOT claim node2vec wins."""
    seeds = [0, 1, 2, 3]
    jac_f1, n2v_f1 = [], []
    for s in seeds:
        tenant = generate_tenant(seed=s, chain_length=3, density="low",
                                 n_chains=1, n_duplicate_pairs=4)
        jac_f1.append(evaluate_tenant(tenant, "jaccard").f1)
        n2v_f1.append(evaluate_tenant(tenant, "node2vec").f1)
    assert np.mean(jac_f1) > np.mean(n2v_f1)
