"""Detection/remediation methods under evaluation.

Every method takes an IAM graph and returns a :class:`MethodOutput`:

    * ``predicted_risky_perms`` -- permission node ids the method calls risky.
    * ``removed_edges`` / ``removed_nodes`` -- what its remediation strips out.

Two methods are provided:

    * :class:`HeuristicMethod` -- the project's actual pipeline (RedAgent +
      BlueAgent + CausalRiskScorer). This is the baseline we want to beat.
    * :class:`RandomMethod` -- flags/cuts uniformly at random. To make the
      comparison about *targeting quality* rather than budget, run_eval feeds
      it the heuristic's counts so both spend the same number of flags/cuts.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx

from src.adversarial.blue_agent import BlueAgent
from src.adversarial.red_agent import RedAgent
from src.causal.risk_scorer import CausalRiskScorer, RiskLevel

Edge = Tuple[str, str]


@dataclass
class MethodOutput:
    predicted_risky_perms: Set[str] = field(default_factory=set)
    removed_edges: Set[Edge] = field(default_factory=set)
    removed_nodes: Set[str] = field(default_factory=set)


def _permission_nodes(graph: nx.DiGraph) -> List[str]:
    return [n for n, d in graph.nodes(data=True) if d.get("label") == "Permission"]


def _removable_edges(graph: nx.DiGraph) -> List[Edge]:
    """HAS_ROLE and GRANTS edges -- the edges remediation could plausibly cut."""
    return [(u, v) for u, v in graph.edges()]


class HeuristicMethod:
    """The current if/else pipeline: RedAgent -> BlueAgent, plus the scorer."""

    name = "heuristic"

    def run(self, graph: nx.DiGraph, budgets: Optional[Dict[str, int]] = None) -> MethodOutput:
        # --- detection: which permissions does the project call risky? ------
        scorer = CausalRiskScorer(graph)
        scores = scorer.score_all_permissions()
        predicted_risky: Set[str] = {
            s.permission_id for s in scores
            if s.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
        }

        # --- attack discovery + remediation ---------------------------------
        red = RedAgent(graph)
        attack_paths = red.find_escalation_paths(max_paths=50)

        # Permissions the attacker actually leaned on count as "risky" too.
        for attack in attack_paths:
            predicted_risky.update(attack.permissions_used)

        blue = BlueAgent(graph)  # copies the graph internally
        strategy = blue.generate_defenses(attack_paths)
        hardened, _ = blue.apply_defenses(strategy)

        original_edges = set(graph.edges())
        hardened_edges = set(hardened.edges())
        removed_edges = original_edges - hardened_edges

        original_nodes = set(graph.nodes())
        hardened_nodes = set(hardened.nodes())
        removed_nodes = original_nodes - hardened_nodes

        return MethodOutput(
            predicted_risky_perms=predicted_risky,
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
    return [HeuristicMethod(), RandomMethod(seed=random_seed)]
