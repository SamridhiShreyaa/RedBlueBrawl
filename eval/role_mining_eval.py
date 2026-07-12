"""Role-mining benchmark: do we recover the *planted* near-duplicate roles?

The privilege-escalation harness (``run_eval.py``) grades detection/remediation.
This companion harness grades the other README claim -- "role mining using graph
algorithms" -- against tenants that carry planted near-duplicate role pairs as
ground truth (:func:`eval.tenant_gen.generate_tenant` with ``n_duplicate_pairs``).

Three methods are compared at the **pair level** (did we flag the two roles that
were planted to be redundant?):

    * ``node2vec``  -- embed roles over the role-permission bipartite graph and
      cluster the embeddings (``src.graph.role_mining``).
    * ``jaccard``   -- cluster roles on exact Jaccard overlap of their permission
      sets. The strong baseline node2vec must actually beat to earn its keep.
    * ``count``     -- the legacy permission-count threshold. A floor, not a
      real competitor.

Scoring universe. Planted escalation chains create structurally-identical roles
across chains, which are *not* role-mining ground truth; we therefore score only
over **non-chain** roles (``Tenant.chain_roles``). A predicted pair touching a
chain role is dropped from both prediction and truth, so the comparison is about
the consolidation experiment alone.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import asdict, dataclass
from itertools import combinations
from typing import Dict, List, Set, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.graph.role_mining import find_near_duplicate_roles  # noqa: E402
from eval.tenant import Tenant  # noqa: E402
from eval.tenant_gen import generate_tenant  # noqa: E402

RolePair = Tuple[str, str]
METHODS = ["node2vec", "jaccard", "count"]


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
    """Run one method on one tenant and score it over non-chain roles."""
    all_roles = {n for n, d in tenant.graph.nodes(data=True) if d.get("label") == "Role"}
    candidates = all_roles - tenant.chain_roles()

    predicted = _restrict_to_candidates(
        find_near_duplicate_roles(tenant.graph, method=method, **kwargs), candidates
    )
    planted = _restrict_to_candidates(tenant.planted_duplicate_pairs(), candidates)
    return score_pairs(planted, predicted)


def run_grid(seeds: List[int], densities: List[str], n_duplicate_pairs: int = 4,
             n_chains: int = 1, chain_length: int = 3) -> List[Dict]:
    """Evaluate every method across a grid of tenants. Returns raw per-run rows.

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
                row = {"method": method, "density": density, "seed": seed,
                       "tenant_id": tenant.tenant_id}
                row.update(asdict(metrics))
                rows.append(row)
    return rows


def summarize(rows: List[Dict]) -> Dict[str, Dict[str, float]]:
    """Mean precision/recall/f1 per method."""
    cols = ["precision", "recall", "f1"]
    summary: Dict[str, Dict[str, float]] = {}
    for method in METHODS:
        method_rows = [r for r in rows if r["method"] == method]
        if not method_rows:
            continue
        summary[method] = {
            c: round(sum(r[c] for r in method_rows) / len(method_rows), 4) for c in cols
        }
    return summary


def _print_summary(summary: Dict[str, Dict[str, float]]) -> None:
    print(f"\n{'method':<12}{'precision':>11}{'recall':>9}{'f1':>8}")
    print("-" * 40)
    for method in METHODS:
        if method in summary:
            s = summary[method]
            print(f"{method:<12}{s['precision']:>11.3f}{s['recall']:>9.3f}{s['f1']:>8.3f}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Role-mining pair-detection benchmark")
    parser.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2, 3, 4])
    parser.add_argument("--densities", nargs="+", default=["low", "medium"])
    parser.add_argument("--n-duplicate-pairs", type=int, default=4)
    parser.add_argument("--results-dir",
                        default=os.path.join(os.path.dirname(__file__), "results"))
    parser.add_argument("--no-csv", action="store_true")
    args = parser.parse_args()

    print(f"Role-mining benchmark: seeds={args.seeds} densities={args.densities} "
          f"planted_pairs/tenant={args.n_duplicate_pairs}")
    rows = run_grid(args.seeds, args.densities, n_duplicate_pairs=args.n_duplicate_pairs)
    summary = summarize(rows)
    _print_summary(summary)

    if not args.no_csv:
        try:
            import pandas as pd
            os.makedirs(args.results_dir, exist_ok=True)
            pd.DataFrame(rows).to_csv(
                os.path.join(args.results_dir, "role_mining_raw.csv"), index=False)
            pd.DataFrame(
                [{"method": m, **s} for m, s in summary.items()]
            ).to_csv(os.path.join(args.results_dir, "role_mining_summary.csv"), index=False)
            print(f"\nWrote CSVs to {args.results_dir}")
        except ImportError:
            print("\n(pandas unavailable -- skipped CSV output)")


if __name__ == "__main__":
    main()
