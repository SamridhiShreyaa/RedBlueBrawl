"""Scoring a method's output against a tenant's ground truth.

All metrics are computed against what was *planted*, never re-derived from a
heuristic, so a method cannot "define away" its own mistakes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Set, Tuple

from eval.methods import MethodOutput
from eval.tenant import Tenant

Edge = Tuple[str, str]


@dataclass
class EvalMetrics:
    # risky-permission detection
    precision: float
    recall: float
    f1: float
    fpr: float  # false-positive rate over benign permissions
    # remediation quality
    pct_paths_broken: float  # 0..100
    benign_edges_cut: int
    # bookkeeping (useful context in the table)
    n_permissions: int
    n_gt_risky: int
    n_predicted_risky: int
    n_removed_edges: int
    n_chains: int

    def as_row(self) -> dict:
        return asdict(self)


def _safe_div(num: float, den: float) -> float:
    return num / den if den else 0.0


def score(tenant: Tenant, output: MethodOutput) -> EvalMetrics:
    """Grade a single method run on a single tenant."""
    all_perms = tenant.all_permissions()
    gt_risky = tenant.risky_permissions()
    gt_benign = all_perms - gt_risky

    predicted = set(output.predicted_risky_perms) & all_perms  # ignore stray ids

    tp = len(predicted & gt_risky)
    fp = len(predicted & gt_benign)
    fn = len(gt_risky - predicted)

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    fpr = _safe_div(fp, len(gt_benign))

    # remediation: how many planted routes did we actually sever?
    removed_edges: Set[Edge] = set(output.removed_edges)
    removed_nodes: Set[str] = set(output.removed_nodes)
    broken = sum(
        1 for chain in tenant.chains
        if chain.is_broken_by(removed_edges, removed_nodes)
    )
    pct_paths_broken = _safe_div(broken, len(tenant.chains)) * 100.0

    # collateral: edges cut that belong to no planted chain
    participating = tenant.participating_edges()
    benign_edges_cut = len(removed_edges - participating)

    return EvalMetrics(
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        fpr=round(fpr, 4),
        pct_paths_broken=round(pct_paths_broken, 2),
        benign_edges_cut=benign_edges_cut,
        n_permissions=len(all_perms),
        n_gt_risky=len(gt_risky),
        n_predicted_risky=len(predicted),
        n_removed_edges=len(removed_edges),
        n_chains=len(tenant.chains),
    )
