"""Tests for the evaluation harness under eval/."""

import os
import sys
from pathlib import Path

import pytest

repo_root = str(Path(__file__).parent.parent)
sys.path.insert(0, repo_root)

from eval.tenant_gen import TECHNIQUE_ACTIONS, generate_tenant
from eval.methods import HeuristicMethod, RandomMethod, MethodOutput
from eval.metrics import score
from eval import run_eval


# --------------------------------------------------------------------------
# tenant generation
# --------------------------------------------------------------------------

def test_generate_tenant_is_deterministic():
    a = generate_tenant(seed=7, chain_length=3, density="low", n_chains=3)
    b = generate_tenant(seed=7, chain_length=3, density="low", n_chains=3)

    assert set(a.graph.nodes()) == set(b.graph.nodes())
    assert set(a.graph.edges()) == set(b.graph.edges())
    assert a.risky_permissions() == b.risky_permissions()
    assert [c.breaking_edges for c in a.chains] == [c.breaking_edges for c in b.chains]


def test_different_seed_changes_tenant():
    a = generate_tenant(seed=1, chain_length=3, density="medium", n_chains=3)
    b = generate_tenant(seed=2, chain_length=3, density="medium", n_chains=3)
    # Distractor structure is seed-driven, so the graphs must differ somewhere.
    assert set(a.graph.edges()) != set(b.graph.edges())


def test_ground_truth_is_consistent_with_graph():
    tenant = generate_tenant(seed=3, chain_length=4, density="low", n_chains=3)

    assert len(tenant.chains) == 3
    for chain in tenant.chains:
        # Every breaking edge and every risky perm actually exists in the graph.
        for u, v in chain.breaking_edges:
            assert tenant.graph.has_edge(u, v), f"missing breaking edge {(u, v)}"
        for perm in chain.risky_perms:
            assert tenant.graph.has_node(perm)
            assert tenant.graph.nodes[perm].get("label") == "Permission"
        # Technique actions come from the known privesc catalogue.
        for action in chain.technique_actions:
            assert action in TECHNIQUE_ACTIONS

    # Freshly generated, nothing is removed, so no chain is broken yet.
    for chain in tenant.chains:
        assert not chain.is_broken_by(removed_edges=set(), removed_nodes=set())


def test_chain_length_controls_number_of_roles():
    short = generate_tenant(seed=0, chain_length=2, density="low", n_chains=1)
    long = generate_tenant(seed=0, chain_length=5, density="low", n_chains=1)
    assert len(long.chains[0].roles) > len(short.chains[0].roles)


def test_risky_and_benign_permissions_partition():
    tenant = generate_tenant(seed=5, chain_length=3, density="high", n_chains=3)
    risky = tenant.risky_permissions()
    benign = tenant.benign_permissions()
    assert risky.isdisjoint(benign)
    assert risky | benign == tenant.all_permissions()
    assert len(benign) > 0  # high density must contribute benign distractors


# --------------------------------------------------------------------------
# metrics
# --------------------------------------------------------------------------

def test_perfect_predictor_scores_one():
    tenant = generate_tenant(seed=2, chain_length=3, density="low", n_chains=3)

    # Flag exactly the risky perms; cut one breaking edge from each chain.
    removed = {chain.breaking_edges[0] for chain in tenant.chains}
    output = MethodOutput(
        predicted_risky_perms=set(tenant.risky_permissions()),
        removed_edges=removed,
        removed_nodes=set(),
    )
    m = score(tenant, output)

    assert m.precision == 1.0
    assert m.recall == 1.0
    assert m.f1 == 1.0
    assert m.fpr == 0.0
    assert m.pct_paths_broken == 100.0
    assert m.benign_edges_cut == 0  # breaking edges are not collateral


def test_empty_predictor_scores_zero():
    tenant = generate_tenant(seed=2, chain_length=3, density="low", n_chains=3)
    m = score(tenant, MethodOutput())
    assert m.recall == 0.0
    assert m.f1 == 0.0
    assert m.pct_paths_broken == 0.0
    assert m.benign_edges_cut == 0


def test_collateral_edge_is_counted():
    tenant = generate_tenant(seed=4, chain_length=2, density="low", n_chains=1)

    # A benign HAS_ROLE edge that belongs to no planted chain.
    benign_edge = None
    participating = tenant.participating_edges()
    for edge in tenant.graph.edges():
        if edge not in participating:
            benign_edge = edge
            break
    assert benign_edge is not None

    m = score(tenant, MethodOutput(removed_edges={benign_edge}))
    assert m.benign_edges_cut == 1
    assert m.pct_paths_broken == 0.0  # a benign cut breaks nothing


def test_false_positive_rate_reflects_benign_flags():
    tenant = generate_tenant(seed=6, chain_length=3, density="low", n_chains=2)
    benign = list(tenant.benign_permissions())
    assert benign
    output = MethodOutput(predicted_risky_perms={benign[0]})
    m = score(tenant, output)
    assert m.fpr > 0.0
    assert m.precision == 0.0  # flagged only a benign perm


# --------------------------------------------------------------------------
# methods
# --------------------------------------------------------------------------

def test_heuristic_method_runs_and_returns_valid_output():
    tenant = generate_tenant(seed=1, chain_length=3, density="low", n_chains=3)
    out = HeuristicMethod().run(tenant.graph)

    assert isinstance(out, MethodOutput)
    # Flagged ids must be real permission nodes.
    for perm in out.predicted_risky_perms:
        assert tenant.graph.nodes[perm].get("label") == "Permission"
    # Removed edges/nodes must have come from the original graph.
    for u, v in out.removed_edges:
        assert tenant.graph.has_edge(u, v)
    for node in out.removed_nodes:
        assert tenant.graph.has_node(node)


def test_random_method_respects_budget_and_is_deterministic():
    tenant = generate_tenant(seed=1, chain_length=3, density="medium", n_chains=3)
    budgets = {"risky": 5, "edges": 4}

    a = RandomMethod(seed=42).run(tenant.graph, budgets=budgets)
    b = RandomMethod(seed=42).run(tenant.graph, budgets=budgets)

    assert len(a.predicted_risky_perms) == 5
    assert len(a.removed_edges) == 4
    assert a.predicted_risky_perms == b.predicted_risky_perms
    assert a.removed_edges == b.removed_edges


def test_random_method_clamps_oversized_budget():
    tenant = generate_tenant(seed=1, chain_length=2, density="low", n_chains=1)
    n_perms = len(tenant.all_permissions())
    out = RandomMethod(seed=0).run(tenant.graph, budgets={"risky": n_perms + 999, "edges": 0})
    assert len(out.predicted_risky_perms) == n_perms
    assert len(out.removed_edges) == 0


# --------------------------------------------------------------------------
# orchestration
# --------------------------------------------------------------------------

EXPECTED_METHODS = {"heuristic", "signature_cf", "reachability_cf", "random"}


def test_run_grid_smoke_and_outputs(tmp_path):
    df = run_eval.run_grid(
        chain_lengths=[2, 3], densities=["low"], seeds=[0, 1], n_chains=2,
    )

    # Four methods x 2 lengths x 1 density x 2 seeds = 16 rows.
    assert len(df) == 16
    assert set(df["method"].unique()) == EXPECTED_METHODS
    assert set(df["benchmark"].unique()) == {"original"}
    for col in ("precision", "recall", "f1", "fpr", "pct_paths_broken", "benign_edges_cut"):
        assert col in df.columns

    summaries = run_eval.write_outputs(df, str(tmp_path))
    assert set(summaries["by_method"]["method"]) == EXPECTED_METHODS
    for name in ("raw_results.csv", "summary.csv", "summary_by_method.csv"):
        assert (tmp_path / name).exists()


def test_both_benchmarks_present_in_full_run():
    df = run_eval.run_all_benchmarks(
        chain_lengths=[2, 3], densities=["low"], seeds=[0, 1], n_chains=2,
    )
    assert set(df["benchmark"].unique()) == {"original", "novel"}


def test_counterfactual_scorers_beat_heuristic_without_regressing_breaks():
    df = run_eval.run_grid(
        chain_lengths=[2, 3, 4], densities=["low", "high"], seeds=[0, 1, 2], n_chains=3,
    )
    by_method = df.groupby("method")[["f1", "pct_paths_broken"]].mean()

    heur_f1 = by_method.loc["heuristic", "f1"]
    assert by_method.loc["signature_cf", "f1"] > heur_f1
    assert by_method.loc["reachability_cf", "f1"] > heur_f1

    # Shared remediation => identical path-break rate (no regression).
    heur_break = by_method.loc["heuristic", "pct_paths_broken"]
    assert by_method.loc["signature_cf", "pct_paths_broken"] >= heur_break
    assert by_method.loc["reachability_cf", "pct_paths_broken"] >= heur_break
