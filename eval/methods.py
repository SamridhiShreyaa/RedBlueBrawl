"""Detection/remediation methods under evaluation.

Every method takes an IAM graph and returns a :class:`MethodOutput`:

    * ``predicted_risky_perms`` -- permission node ids the method calls risky.
    * ``removed_edges`` / ``removed_nodes`` -- what its remediation strips out.

Methods:

    * :class:`HeuristicMethod` -- the project's original pipeline: the legacy
      weighted-sum scorer (HeuristicRiskScorer) for detection, RedAgent +
      BlueAgent for remediation. This is the baseline to beat.
    * :class:`SignatureCounterfactualMethod` -- counterfactual detection gated
      on a hardcoded ASSUME/PRIVESC action vocabulary.
    * :class:`ReachabilityMethod` -- counterfactual detection driven by real
      trust-edge reachability to sensitive targets; no action-name lists, so it
      generalises to novel escalation techniques.
    * :class:`RandomMethod` -- uniform random with a budget matched to the
      heuristic, isolating targeting quality from spend.

All three non-random methods share RedAgent+BlueAgent remediation, so their
path-break columns are identical by construction and every detection difference
is attributable to the scorer alone.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx

from src.adversarial.blue_agent import BlueAgent
from src.adversarial.red_agent import RedAgent
from src.causal.risk_scorer import (
    HeuristicRiskScorer,
    ReachabilityRiskScorer,
    RiskLevel,
    SignatureCounterfactualScorer,
)

Edge = Tuple[str, str]


@dataclass
class MethodOutput:
    predicted_risky_perms: Set[str] = field(default_factory=set)
    removed_edges: Set[Edge] = field(default_factory=set)
    removed_nodes: Set[str] = field(default_factory=set)


def _permission_nodes(graph: nx.DiGraph) -> List[str]:
    return [n for n, d in graph.nodes(data=True) if d.get("label") == "Permission"]


def _removable_edges(graph: nx.DiGraph) -> List[Edge]:
    return [(u, v) for u, v in graph.edges()]


def _discover_and_remediate(graph: nx.DiGraph):
    """Shared RedAgent attack discovery + BlueAgent remediation.

    Returns ``(attack_paths, removed_edges, removed_nodes)``. Deterministic for
    a given graph, so any method using this has an identical path-break rate.
    """
    red = RedAgent(graph)
    attack_paths = red.find_escalation_paths(max_paths=50)

    blue = BlueAgent(graph)  # copies the graph internally
    strategy = blue.generate_defenses(attack_paths)
    hardened, _ = blue.apply_defenses(strategy)

    removed_edges = set(graph.edges()) - set(hardened.edges())
    removed_nodes = set(graph.nodes()) - set(hardened.nodes())
    return attack_paths, removed_edges, removed_nodes


def _risky_from_scorer(scorer) -> Set[str]:
    return {
        s.permission_id for s in scorer.score_all_permissions()
        if s.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
    }


class HeuristicMethod:
    """Legacy weighted-sum detection + RedAgent/BlueAgent remediation (baseline)."""

    name = "heuristic"

    def run(self, graph: nx.DiGraph, budgets: Optional[Dict[str, int]] = None) -> MethodOutput:
        predicted = _risky_from_scorer(HeuristicRiskScorer(graph))
        attack_paths, removed_edges, removed_nodes = _discover_and_remediate(graph)
        for attack in attack_paths:
            predicted.update(attack.permissions_used)
        return MethodOutput(
            predicted_risky_perms=predicted,
            removed_edges=removed_edges,
            removed_nodes=removed_nodes,
        )


class SignatureCounterfactualMethod:
    """Signature-gated counterfactual detection + the SAME remediation as heuristic.

    Only the scorer differs from :class:`HeuristicMethod`, so the path-break
    column is identical by construction and the detection metrics isolate the
    scorer's contribution. Blind to escalation actions outside its hardcoded
    ASSUME/PRIVESC vocabulary (see the novel-technique benchmark).
    """

    name = "signature_cf"

    def run(self, graph: nx.DiGraph, budgets: Optional[Dict[str, int]] = None) -> MethodOutput:
        predicted = _risky_from_scorer(SignatureCounterfactualScorer(graph))
        attack_paths, removed_edges, removed_nodes = _discover_and_remediate(graph)
        for attack in attack_paths:
            predicted.update(attack.permissions_used)
        return MethodOutput(
            predicted_risky_perms=predicted,
            removed_edges=removed_edges,
            removed_nodes=removed_nodes,
        )


class ReachabilityMethod:
    """Structural-reachability counterfactual detection + the SAME remediation.

    Detection follows real trust-edge reachability to sensitive targets, so it
    generalises to escalation actions absent from any hardcoded list. Shares
    remediation with the heuristic, so its path-break column is identical and
    the detection metrics isolate the scorer.
    """

    name = "reachability_cf"

    def run(self, graph: nx.DiGraph, budgets: Optional[Dict[str, int]] = None) -> MethodOutput:
        predicted = _risky_from_scorer(ReachabilityRiskScorer(graph))
        attack_paths, removed_edges, removed_nodes = _discover_and_remediate(graph)
        for attack in attack_paths:
            predicted.update(attack.permissions_used)
        return MethodOutput(
            predicted_risky_perms=predicted,
            removed_edges=removed_edges,
            removed_nodes=removed_nodes,
        )


class RandomMethod:
    """Uniform-random flagging and edge cutting with an optional matched budget."""

    name = "random"

    def __init__(self, seed: int = 0):
        self.seed = seed

    def run(self, graph: nx.DiGraph, budgets: Optional[Dict[str, int]] = None) -> MethodOutput:
        rng = random.Random(self.seed)

        perms = _permission_nodes(graph)
        edges = _removable_edges(graph)

        if budgets and "risky" in budgets:
            risky_budget = budgets["risky"]
        else:
            risky_budget = round(0.30 * len(perms))
        if budgets and "edges" in budgets:
            edge_budget = budgets["edges"]
        else:
            edge_budget = round(0.05 * len(edges))

        risky_budget = max(0, min(risky_budget, len(perms)))
        edge_budget = max(0, min(edge_budget, len(edges)))

        predicted_risky = set(rng.sample(perms, risky_budget)) if risky_budget else set()
        removed_edges = set(rng.sample(edges, edge_budget)) if edge_budget else set()

        return MethodOutput(
            predicted_risky_perms=predicted_risky,
            removed_edges=removed_edges,
            removed_nodes=set(),
        )


def default_methods(random_seed: int = 0) -> List[object]:
    """The method roster run_eval evaluates, in table order."""
    return [
        HeuristicMethod(),
        SignatureCounterfactualMethod(),
        ReachabilityMethod(),
        RandomMethod(seed=random_seed),
    ]
