"""Run every method over a fixed grid of tenants and emit a comparison.

Usage:
    python eval/run_eval.py                 # full grid, writes eval/results/
    python eval/run_eval.py --quick         # tiny grid for a fast sanity run

Outputs (all under --results-dir, default eval/results/):
    raw_results.csv        one row per (method, tenant)
    summary.csv            mean metrics per (method, chain_length, density)
    summary_by_method.csv  mean metrics per method (the headline table)
    comparison.png         F1 and %-paths-broken vs chain length, per method
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Dict, List

# Allow `python eval/run_eval.py` from the repo root.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pandas as pd  # noqa: E402

from eval.metrics import score  # noqa: E402
from eval.methods import (  # noqa: E402
    HeuristicMethod,
    RandomMethod,
    ReachabilityMethod,
    SignatureCounterfactualMethod,
)
from eval.tenant_gen import DENSITY_PRESETS, generate_tenant  # noqa: E402

DEFAULT_CHAIN_LENGTHS = [2, 3, 4, 5]
DEFAULT_DENSITIES = ["low", "medium", "high"]
DEFAULT_SEEDS = [0, 1, 2, 3, 4]

METRIC_COLUMNS = [
    "precision", "recall", "f1", "fpr",
    "pct_paths_broken", "benign_edges_cut",
]


def run_grid(chain_lengths: List[int], densities: List[str], seeds: List[int],
             n_chains: int = 3, random_seed: int = 0,
             novel_technique: bool = False) -> pd.DataFrame:
    """Evaluate all methods across the grid. Returns one row per (method, tenant).

    ``novel_technique`` selects the benchmark: the original sts-based chains, or
    chains that escalate via an action absent from every hardcoded privesc list.

    The random baseline is given the heuristic's per-tenant budget (number of
    permissions flagged and edges cut) so the comparison isolates *targeting*
    quality from how much each method is allowed to touch.
    """
    heuristic = HeuristicMethod()
    signature_cf = SignatureCounterfactualMethod()
    reachability_cf = ReachabilityMethod()
    random_method = RandomMethod(seed=random_seed)

    benchmark = "novel" if novel_technique else "original"

    rows: List[Dict] = []
    for chain_length in chain_lengths:
        for density in densities:
            for seed in seeds:
                tenant = generate_tenant(
                    seed=seed, chain_length=chain_length,
                    density=density, n_chains=n_chains,
                    novel_technique=novel_technique,
                )

                heur_out = heuristic.run(tenant.graph)
                heur_metrics = score(tenant, heur_out)
                rows.append(_row("heuristic", benchmark, chain_length, density,
                                 seed, tenant.tenant_id, heur_metrics))

                for method in (signature_cf, reachability_cf):
                    out = method.run(tenant.graph)
                    rows.append(_row(method.name, benchmark, chain_length,
                                     density, seed, tenant.tenant_id,
                                     score(tenant, out)))

                # Random baseline, budget-matched to the heuristic so the
                # comparison isolates targeting quality from spend.
                budgets = {
                    "risky": len(heur_out.predicted_risky_perms),
                    "edges": len(heur_out.removed_edges),
                }
                rand_out = random_method.run(tenant.graph, budgets=budgets)
                rand_metrics = score(tenant, rand_out)
                rows.append(_row("random", benchmark, chain_length, density,
                                 seed, tenant.tenant_id, rand_metrics))

    return pd.DataFrame(rows)


def run_all_benchmarks(chain_lengths: List[int], densities: List[str],
                       seeds: List[int], n_chains: int = 3,
                       random_seed: int = 0) -> pd.DataFrame:
    """Run both the original and novel-technique benchmarks, concatenated."""
    original = run_grid(chain_lengths, densities, seeds, n_chains, random_seed,
                        novel_technique=False)
    novel = run_grid(chain_lengths, densities, seeds, n_chains, random_seed,
                     novel_technique=True)
    return pd.concat([original, novel], ignore_index=True)


def _row(method: str, benchmark: str, chain_length: int, density: str, seed: int,
         tenant_id: str, metrics) -> Dict:
    row = {
        "method": method,
        "benchmark": benchmark,
        "chain_length": chain_length,
        "density": density,
        "seed": seed,
        "tenant_id": tenant_id,
    }
    row.update(metrics.as_row())
    return row


def summarize(df: pd.DataFrame) -> Dict[str, pd.DataFrame]:
    """Aggregate raw rows into per-config and per-method summaries."""
    group_cols = ["benchmark"] if "benchmark" in df.columns else []
    by_config = (
        df.groupby(group_cols + ["method", "chain_length", "density"],
                   as_index=False)[METRIC_COLUMNS]
        .mean()
        .round(4)
    )
    by_method = (
        df.groupby(group_cols + ["method"], as_index=False)[METRIC_COLUMNS]
        .mean()
        .round(4)
    )
    return {"by_config": by_config, "by_method": by_method}


def make_plot(df: pd.DataFrame, out_path: str) -> bool:
    """F1 and %-paths-broken vs chain length, per method. Returns success."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as exc:  # pragma: no cover - environment-dependent
        print(f"[plot] matplotlib unavailable, skipping plot: {exc}")
        return False

    benchmarks = sorted(df["benchmark"].unique()) if "benchmark" in df.columns else ["all"]
    methods = sorted(df["method"].unique())

    fig, axes = plt.subplots(1, len(benchmarks), figsize=(6 * len(benchmarks), 5),
                             squeeze=False)
    for col, benchmark in enumerate(benchmarks):
        ax = axes[0][col]
        bench_df = df[df["benchmark"] == benchmark] if "benchmark" in df.columns else df
        agg = bench_df.groupby(["method", "chain_length"], as_index=False)[METRIC_COLUMNS].mean()
        for method in methods:
            sub = agg[agg["method"] == method].sort_values("chain_length")
            ax.plot(sub["chain_length"], sub["f1"], marker="o", label=method)
        ax.set_xlabel("chain length (role hops)")
        ax.set_ylabel("detection F1")
        ax.set_title(f"{benchmark} benchmark")
        ax.set_ylim(-0.05, 1.05)
        ax.grid(True, alpha=0.3)
        ax.legend()

    fig.suptitle("RedBlueBrawl: detection F1 by method (signature vs reachability)")
    fig.tight_layout()
    fig.savefig(out_path, dpi=120)
    plt.close(fig)
    return True


def write_outputs(df: pd.DataFrame, results_dir: str) -> Dict[str, pd.DataFrame]:
    os.makedirs(results_dir, exist_ok=True)
    summaries = summarize(df)

    df.to_csv(os.path.join(results_dir, "raw_results.csv"), index=False)
    summaries["by_config"].to_csv(
        os.path.join(results_dir, "summary.csv"), index=False)
    summaries["by_method"].to_csv(
        os.path.join(results_dir, "summary_by_method.csv"), index=False)

    make_plot(df, os.path.join(results_dir, "comparison.png"))
    return summaries


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the RedBlueBrawl eval harness")
    parser.add_argument("--results-dir",
                        default=os.path.join(os.path.dirname(__file__), "results"))
    parser.add_argument("--chain-lengths", type=int, nargs="+",
                        default=DEFAULT_CHAIN_LENGTHS)
    parser.add_argument("--densities", nargs="+", default=DEFAULT_DENSITIES,
                        choices=sorted(DENSITY_PRESETS))
    parser.add_argument("--seeds", type=int, nargs="+", default=DEFAULT_SEEDS)
    parser.add_argument("--n-chains", type=int, default=3)
    parser.add_argument("--random-seed", type=int, default=0)
    parser.add_argument("--quick", action="store_true",
                        help="tiny grid (lengths 2,4; low/high; 2 seeds)")
    args = parser.parse_args()

    if args.quick:
        chain_lengths = [2, 4]
        densities = ["low", "high"]
        seeds = [0, 1]
    else:
        chain_lengths = args.chain_lengths
        densities = args.densities
        seeds = args.seeds

    print(f"Running grid: lengths={chain_lengths} densities={densities} "
          f"seeds={seeds} n_chains={args.n_chains}")
    print("Benchmarks: original (sts-based) + novel (unlisted escalation action)")
    df = run_all_benchmarks(chain_lengths, densities, seeds,
                            n_chains=args.n_chains, random_seed=args.random_seed)
    summaries = write_outputs(df, args.results_dir)

    print("\n=== Comparison (mean per benchmark) ===")
    print(summaries["by_method"].to_string(index=False))
    print(f"\nWrote CSVs + plot to {args.results_dir}")


if __name__ == "__main__":
    main()
