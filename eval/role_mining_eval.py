"""Role-mining benchmarks: exact-overlap duplicates AND functional similarity.

The privilege-escalation harness (``run_eval.py``) grades detection/remediation.
This companion harness grades the other README claim -- "role mining using graph
algorithms" -- on two pair-level benchmarks with planted ground truth:

**exact** -- near-duplicate pairs (same permission set +/- 1-2 grants), planted
via ``generate_tenant(..., n_duplicate_pairs=k)``. Measures exact redundancy.

**functional** -- same-job pairs drawn from one functional group whose exact
action overlap is partial and sometimes ZERO (``n_functional_pairs=k``; see
:func:`eval.tenant_gen._plant_functional_pairs` for the auditable design).
Measures whether a method can pair roles that do the same job via
related-but-not-identical permissions -- the case set-overlap metrics are
structurally blind to.

Methods compared (did we flag the planted pair?):

    * ``jaccard``   -- cluster roles on Jaccard overlap of their permission
      sets (``src.graph.role_mining``). The recommended method.
    * ``count``     -- the legacy permission-count threshold. A floor, not a
      real competitor.

A ``node2vec`` embedding method was also benchmarked here and then DROPPED: it
lost the exact benchmark (F1 0.619 vs jaccard 0.877) and only tied the
functional one (both 1.000 -- average-linkage clustering reaches
zero-exact-overlap pairs transitively through group cohorts, the same
co-occurrence channel the embedding walks). The committed results CSVs still
carry its rows as recorded evidence; to reproduce them, check out the evidence
commit (25a2c2c), which contains the full node2vec implementation.

Scoring universes (each applied identically to every method):

    * exact: all **non-chain** roles (planted escalation chains create
      structurally-identical roles across chains -- a different experiment).
    * functional: the **planted functional-pair roles only**. Rationale: the
      functional question is discrimination -- among roles that each do some
      job, does the method match same-function partners (including
      zero-exact-overlap ones) and refuse cross-function ones? Cohort roles are
      excluded because pairing a role with its group's cohort is functionally
      correct but unplanted; distractor-distractor pairs are excluded because
      the small benign action pool makes random distractors *genuine* exact
      near-duplicates of each other, which is precisely what the exact
      benchmark already measures.

Operating points: each method uses its own per-benchmark clustering threshold,
swept symmetrically for best mean F1 (constants in ``src.graph.role_mining``);
functional pairs live in a looser similarity band than exact duplicates, so
reusing the exact thresholds would score every method at ~0 and say nothing.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import asdict, dataclass
from itertools import combinations
from typing import Dict, List, Set, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.graph.role_mining import (  # noqa: E402
    FUNCTIONAL_JACCARD_DISTANCE,
    find_near_duplicate_roles,
)
from eval.tenant import Tenant  # noqa: E402
from eval.tenant_gen import generate_tenant  # noqa: E402

RolePair = Tuple[str, str]
METHODS = ["jaccard", "count"]

# Per-benchmark clustering thresholds (swept symmetrically; see module doc).
# "count" has no threshold -- it is the same permission-count rule everywhere.
FUNCTIONAL_THRESHOLDS = {
    "jaccard": FUNCTIONAL_JACCARD_DISTANCE,
    "count": None,
}


@dataclass
class PairMetrics:
    precision: float
    recall: float
    f1: float
    n_planted: int
    n_predicted: int
    tp: int
    fp: int


def _safe_div(num: float, den: float) -> float:
    return num / den if den else 0.0


def score_pairs(planted: Set[RolePair], predicted: Set[RolePair]) -> PairMetrics:
    """Precision/recall/F1 of predicted duplicate pairs against planted ones."""
    tp = len(planted & predicted)
    fp = len(predicted - planted)
    fn = len(planted - predicted)
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    return PairMetrics(
        precision=round(precision, 4), recall=round(recall, 4), f1=round(f1, 4),
        n_planted=len(planted), n_predicted=len(predicted), tp=tp, fp=fp,
    )


def _restrict_to_candidates(pairs: Set[RolePair], candidates: Set[str]) -> Set[RolePair]:
    """Keep only pairs whose *both* roles are scoreable (non-chain) candidates."""
    return {p for p in pairs if p[0] in candidates and p[1] in candidates}


def evaluate_tenant(tenant: Tenant, method: str, **kwargs) -> PairMetrics:
    """Exact-overlap benchmark: score one method over non-chain roles."""
    all_roles = {n for n, d in tenant.graph.nodes(data=True) if d.get("label") == "Role"}
    candidates = all_roles - tenant.chain_roles()

    predicted = _restrict_to_candidates(
        find_near_duplicate_roles(tenant.graph, method=method, **kwargs), candidates
    )
    planted = _restrict_to_candidates(tenant.planted_duplicate_pairs(), candidates)
    return score_pairs(planted, predicted)


def evaluate_functional_tenant(tenant: Tenant, method: str, **kwargs) -> PairMetrics:
    """Functional benchmark: score one method over the planted functional roles.

    The universe is the planted functional-pair roles (cohorts excluded -- see
    module docstring), so the question is pure same-function discrimination.
    Unless overridden, the method runs at its functional-benchmark threshold.
    """
    if "distance_threshold" not in kwargs and FUNCTIONAL_THRESHOLDS.get(method) is not None:
        kwargs["distance_threshold"] = FUNCTIONAL_THRESHOLDS[method]

    candidates = tenant.functional_pair_roles()
    predicted = _restrict_to_candidates(
        find_near_duplicate_roles(tenant.graph, method=method, **kwargs), candidates
    )
    planted = _restrict_to_candidates(tenant.planted_functional_pairs(), candidates)
    return score_pairs(planted, predicted)


def run_grid(seeds: List[int], densities: List[str], n_duplicate_pairs: int = 4,
             n_chains: int = 1, chain_length: int = 3) -> List[Dict]:
    """Exact-overlap benchmark across a grid of tenants; raw per-run rows.

    ``n_chains`` defaults to 1: a single escalation chain has no sibling chain to
    duplicate, so it contributes no accidental cross-chain duplicate roles.
    """
    rows: List[Dict] = []
    for density in densities:
        for seed in seeds:
            tenant = generate_tenant(
                seed=seed, chain_length=chain_length, density=density,
                n_chains=n_chains, n_duplicate_pairs=n_duplicate_pairs,
            )
            for method in METHODS:
                metrics = evaluate_tenant(tenant, method)
                row = {"benchmark": "exact", "method": method, "density": density,
                       "seed": seed, "tenant_id": tenant.tenant_id}
                row.update(asdict(metrics))
                rows.append(row)
    return rows


def run_functional_grid(seeds: List[int], densities: List[str],
                        n_functional_pairs: int = 4, n_chains: int = 1,
                        chain_length: int = 3) -> List[Dict]:
    """Functional-similarity benchmark across a grid of tenants; raw rows.

    ``n_functional_pairs`` defaults to 4 = one pair per functional group, so no
    two planted pairs share a group (a same-group cross-pair combination would
    itself be functionally similar and would muddy the ground truth).
    """
    rows: List[Dict] = []
    for density in densities:
        for seed in seeds:
            tenant = generate_tenant(
                seed=seed, chain_length=chain_length, density=density,
                n_chains=n_chains, n_functional_pairs=n_functional_pairs,
            )
            for method in METHODS:
                metrics = evaluate_functional_tenant(tenant, method)
                row = {"benchmark": "functional", "method": method,
                       "density": density, "seed": seed,
                       "tenant_id": tenant.tenant_id}
                row.update(asdict(metrics))
                rows.append(row)
    return rows


def summarize(rows: List[Dict]) -> Dict[Tuple[str, str], Dict[str, float]]:
    """Mean precision/recall/f1 per (benchmark, method)."""
    cols = ["precision", "recall", "f1"]
    summary: Dict[Tuple[str, str], Dict[str, float]] = {}
    benchmarks = sorted({r["benchmark"] for r in rows})
    for benchmark in benchmarks:
        for method in METHODS:
            sub = [r for r in rows if r["method"] == method
                   and r["benchmark"] == benchmark]
            if not sub:
                continue
            summary[(benchmark, method)] = {
                c: round(sum(r[c] for r in sub) / len(sub), 4) for c in cols
            }
    return summary


def _print_summary(summary: Dict[Tuple[str, str], Dict[str, float]]) -> None:
    print(f"\n{'benchmark':<12}{'method':<12}{'precision':>11}{'recall':>9}{'f1':>8}")
    print("-" * 52)
    for benchmark in ("exact", "functional"):
        for method in METHODS:
            s = summary.get((benchmark, method))
            if s:
                print(f"{benchmark:<12}{method:<12}"
                      f"{s['precision']:>11.3f}{s['recall']:>9.3f}{s['f1']:>8.3f}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Role-mining pair-detection benchmarks")
    parser.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2, 3, 4])
    parser.add_argument("--densities", nargs="+", default=["low", "medium"])
    parser.add_argument("--n-duplicate-pairs", type=int, default=4)
    parser.add_argument("--n-functional-pairs", type=int, default=4)
    parser.add_argument("--results-dir",
                        default=os.path.join(os.path.dirname(__file__), "results"))
    parser.add_argument("--no-csv", action="store_true")
    args = parser.parse_args()

    print(f"Role-mining benchmarks: seeds={args.seeds} densities={args.densities} "
          f"exact_pairs/tenant={args.n_duplicate_pairs} "
          f"functional_pairs/tenant={args.n_functional_pairs}")
    rows = run_grid(args.seeds, args.densities,
                    n_duplicate_pairs=args.n_duplicate_pairs)
    rows += run_functional_grid(args.seeds, args.densities,
                                n_functional_pairs=args.n_functional_pairs)
    summary = summarize(rows)
    _print_summary(summary)

    if not args.no_csv:
        try:
            import pandas as pd
            os.makedirs(args.results_dir, exist_ok=True)
            pd.DataFrame(rows).to_csv(
                os.path.join(args.results_dir, "role_mining_raw.csv"), index=False)
            pd.DataFrame(
                [{"benchmark": b, "method": m, **s} for (b, m), s in summary.items()]
            ).to_csv(os.path.join(args.results_dir, "role_mining_summary.csv"), index=False)
            print(f"\nWrote CSVs to {args.results_dir}")
        except ImportError:
            print("\n(pandas unavailable -- skipped CSV output)")


if __name__ == "__main__":
    main()
