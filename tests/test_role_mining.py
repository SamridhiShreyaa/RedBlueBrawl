"""Role-mining tests: Jaccard clustering correctness, planted-pair benchmarks
(exact + functional), and the recorded findings that led to dropping node2vec.

A node2vec embedding method existed here and was benchmarked head-to-head; it
lost the exact benchmark and only tied the functional one, so it was dropped
(evidence commit 25a2c2c carries the implementation and its tests). The
assertions below enforce what remains: the Jaccard method's measured behaviour
on both benchmarks, including the zero-exact-overlap pairs it reaches through
clustering transitivity.
"""

import sys
from pathlib import Path

import networkx as nx
import numpy as np
import pytest

repo_root = str(Path(__file__).parent.parent)
sys.path.insert(0, repo_root)

from src.graph.role_mining import (
    FUNCTIONAL_JACCARD_DISTANCE,
    consolidation_suggestions,
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
# helpers: a small graph with one obvious duplicate pair
# --------------------------------------------------------------------------

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


# --------------------------------------------------------------------------
# permission-set extraction
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


# --------------------------------------------------------------------------
# correctness + determinism on a known graph
# --------------------------------------------------------------------------

def test_jaccard_finds_the_obvious_duplicate_pair_and_nothing_else():
    pairs = find_near_duplicate_roles(build_known_graph(), method="jaccard")
    assert pairs == {("DUP_A", "DUP_B")}


def test_jaccard_is_deterministic():
    # Pure set arithmetic + deterministic linkage: no seeds, no hash-order
    # sensitivity, identical output every call.
    G = build_known_graph()
    assert (find_near_duplicate_roles(G, method="jaccard")
            == find_near_duplicate_roles(G, method="jaccard"))


def test_count_baseline_pairs_big_roles_ignoring_overlap():
    # Only DUP_A/DUP_B have >= 5 distinct actions here, so count pairs just them
    # -- and would pair any two big roles regardless of whether they overlap.
    pairs = find_near_duplicate_roles(build_known_graph(), method="count",
                                      min_permissions=5)
    assert ("DUP_A", "DUP_B") in pairs


def test_consolidation_suggestion_reports_shared_and_union():
    suggestions = consolidation_suggestions(build_known_graph())
    dup = next(s for s in suggestions if set(s.roles) == {"DUP_A", "DUP_B"})
    assert dup.mean_jaccard == pytest.approx(1.0)
    assert ANCHOR in dup.shared_actions


def test_unknown_method_raises():
    with pytest.raises(ValueError, match="unknown role-mining method"):
        find_near_duplicate_roles(build_known_graph(), method="node2vec")


# --------------------------------------------------------------------------
# tenant planting (ground truth) and byte-identical defaults
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
    # The pair set-overlap is blind to DIRECTLY really exists.
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
# the two benchmarks: measured behaviour, enforced
# --------------------------------------------------------------------------

def test_jaccard_recovers_all_planted_exact_pairs_with_strong_f1():
    # Exact benchmark: perfect recall, F1 far above the count floor
    # (committed grid mean: jaccard 0.877 vs count 0.157).
    f1s = []
    for s in (0, 1, 2, 3):
        tenant = generate_tenant(seed=s, chain_length=3, density="low",
                                 n_chains=1, n_duplicate_pairs=4)
        m = evaluate_tenant(tenant, "jaccard")
        assert m.recall == 1.0
        f1s.append(m.f1)
    assert np.mean(f1s) >= 0.8


def test_jaccard_catches_zero_overlap_functional_pairs_transitively():
    """The finding that dropped node2vec, enforced. Functional pairs include a
    same-group pair sharing NO exact action; direct set overlap cannot pair it
    (both roles share only the anchor, like an unrelated cross-group pair).
    Average-linkage clustering at the functional threshold still reaches it --
    transitively through the group's cohort roles -- so Jaccard scores perfect
    recall AND precision on the functional benchmark, matching the node2vec
    embedding this was expected to lose to (evidence commit 25a2c2c)."""
    for s in (0, 1, 2):
        tenant = generate_tenant(seed=s, chain_length=3, density="low",
                                 n_chains=1, n_functional_pairs=4)
        m = evaluate_functional_tenant(tenant, "jaccard")
        assert m.recall == 1.0  # includes the zero-exact-overlap pair
        assert m.precision == 1.0  # no cross-function pair flagged


def test_functional_threshold_is_looser_than_exact():
    # Documented relationship between the two swept operating points.
    from src.graph.role_mining import DEFAULT_JACCARD_DISTANCE
    assert FUNCTIONAL_JACCARD_DISTANCE > DEFAULT_JACCARD_DISTANCE
