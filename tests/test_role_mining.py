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
from eval.tenant_gen import (
    CONSOLIDATION_ANCHOR,
    FUNCTIONAL_GROUPS,
    FUNCTIONAL_OVERLAP_CYCLE,
    generate_tenant,
)
from eval.role_mining_eval import evaluate_functional_tenant, evaluate_tenant


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


# --------------------------------------------------------------------------
# functional-pair planting (ground truth) and byte-identical default
# --------------------------------------------------------------------------

def _group_actions(sets, role):
    return sets[role] - {CONSOLIDATION_ANCHOR}


def test_planted_functional_pairs_follow_the_stated_design():
    tenant = generate_tenant(seed=0, chain_length=3, density="low",
                             n_chains=1, n_functional_pairs=4)
    assert len(tenant.functional_role_pairs) == 4
    assert tenant.functional_cohort_roles  # cohorts recorded as scaffolding

    sets = role_action_sets(tenant.graph)
    overlaps = []
    for k, (a, b) in enumerate(tenant.functional_role_pairs):
        group = tenant.graph.nodes[a]["functional_group"]
        assert tenant.graph.nodes[b]["functional_group"] == group
        pool = set(FUNCTIONAL_GROUPS[group])
        # Both roles draw only from their group's pool (plus the anchor).
        assert _group_actions(sets, a) <= pool
        assert _group_actions(sets, b) <= pool
        # Exact overlap follows the declared schedule -- including ZERO.
        overlap = len(_group_actions(sets, a) & _group_actions(sets, b))
        assert overlap == FUNCTIONAL_OVERLAP_CYCLE[k % len(FUNCTIONAL_OVERLAP_CYCLE)]
        overlaps.append(overlap)
        # Anchor present for projection connectivity.
        assert CONSOLIDATION_ANCHOR in sets[a] and CONSOLIDATION_ANCHOR in sets[b]
    # The pair Jaccard is blind to by construction really exists.
    assert 0 in overlaps

    for cohort in tenant.functional_cohort_roles:
        assert tenant.graph.nodes[cohort].get("is_functional_cohort")


def test_default_tenant_has_no_functional_pairs_and_is_unchanged():
    baseline = generate_tenant(seed=1, chain_length=3, density="low", n_chains=2)
    withparam = generate_tenant(seed=1, chain_length=3, density="low", n_chains=2,
                                n_functional_pairs=0)
    assert baseline.functional_role_pairs == []
    assert baseline.functional_cohort_roles == []
    # n_functional_pairs=0 must be byte-identical to the pre-feature generator.
    assert set(baseline.graph.nodes()) == set(withparam.graph.nodes())
    assert set(baseline.graph.edges()) == set(withparam.graph.edges())


# --------------------------------------------------------------------------
# functional benchmark: the enforced finding is a TIE, not a node2vec win
# --------------------------------------------------------------------------

def test_functional_benchmark_finding_jaccard_ties_node2vec():
    """Enforce the OBSERVED functional-benchmark relationship (a tie), not the
    expected one. The hypothesis was node2vec_recall > jaccard_recall on
    functional pairs (Jaccard cannot see a zero-exact-overlap pair directly).
    The benchmark falsified it: average-linkage clustering reaches those pairs
    TRANSITIVELY through the group cohorts each role overlaps -- the same
    co-occurrence structure node2vec walks -- so Jaccard also scores perfect
    recall, including the zero-overlap pairs. Since node2vec loses the exact
    benchmark and only ties here, it is not earning its dependency; this test
    is the recorded evidence for dropping it."""
    for s in (0, 1, 2):
        tenant = generate_tenant(seed=s, chain_length=3, density="low",
                                 n_chains=1, n_functional_pairs=4)
        jac = evaluate_functional_tenant(tenant, "jaccard")
        n2v = evaluate_functional_tenant(tenant, "node2vec")
        # Jaccard catches every planted pair -- including the zero-overlap one.
        assert jac.recall == 1.0
        # node2vec does NOT beat it (the tie; both perfect on this grid).
        assert n2v.f1 <= jac.f1


# --------------------------------------------------------------------------
# cross-process determinism (stable hashfxn, not PYTHONHASHSEED-dependent)
# --------------------------------------------------------------------------

_DIGEST_SNIPPET = r"""
import warnings; warnings.filterwarnings("ignore")
import hashlib, sys
sys.path.insert(0, {repo!r})
import numpy as np
from tests.test_role_mining import build_known_graph
from src.graph.role_mining import embed_roles

emb = embed_roles(build_known_graph(), seed=7)
vec = np.concatenate([emb[r] for r in sorted(emb)])
print(hashlib.md5(vec.round(8).tobytes()).hexdigest())
"""


def _embedding_digest_in_subprocess(hashseed: str) -> str:
    import subprocess

    env = dict(**__import__("os").environ, PYTHONHASHSEED=hashseed)
    result = subprocess.run(
        [sys.executable, "-c", _DIGEST_SNIPPET.format(repo=repo_root)],
        capture_output=True, text=True, env=env, timeout=300,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip().splitlines()[-1]


def test_embeddings_are_deterministic_across_processes():
    """Same graph, two interpreters launched with DIFFERENT hash seeds ->
    identical embeddings. gensim seeds token vectors from hashfxn(token); we
    pass a stable md5-based hashfxn, so reproducibility does not depend on the
    caller remembering to pin PYTHONHASHSEED."""
    d0 = _embedding_digest_in_subprocess("0")
    d1 = _embedding_digest_in_subprocess("12345")
    assert d0 == d1
