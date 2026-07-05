"""Counterfactual attack-path risk scoring for IAM permissions.

This module answers a causal-sounding question honestly: *if we removed this
permission grant, how much reachable escalation risk would actually disappear?*

On a deterministic access graph that question has a deterministic answer -- you
delete the edge and recompute reachability -- so there is no genuine
uncertainty for a probabilistic structural causal model (dowhy) to reason about.
Wrapping deterministic graph math in an SCM would be ceremony, so we don't. We
compute the counterfactual directly:

    do(grant = removed)  ==>  routes_broken = |routes(G)| - |routes(G - grant)|

A permission's risk is the number of reachable escalation routes that removing
it breaks. Permissions on many routes score high; permissions that break
nothing (sensitive-but-unreachable, or destructive-but-not-escalating) score
zero. This replaces the previous weighted-sum heuristic, which is retained as
:class:`HeuristicRiskScorer` only so the evaluation harness can compare against
it.

``CausalRiskScorer`` is kept as a backwards-compatible alias for
:class:`CounterfactualRiskScorer` (the name is historical; the behaviour is now
counterfactual, not a structural causal model).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Tuple

import networkx as nx


Edge = Tuple[str, str]


# --------------------------------------------------------------------------
# Domain knowledge: which AWS actions enable privilege escalation.
# Curated from the well-known IAM-privesc catalogue (Rhino Security Labs et al).
# These are *escalation* actions -- they let a principal grant themselves more
# access or assume more powerful roles. Destructive actions (s3:DeleteObject,
# kms:Decrypt, ec2:TerminateInstances) are deliberately NOT here: they are
# high-impact but they do not escalate privilege, so they must not be treated
# as escalation steps.
# --------------------------------------------------------------------------
PRIVESC_ACTIONS = {
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachRolePolicy",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:PutRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:UpdateAssumeRolePolicy",
    "iam:PassRole",
    "iam:CreateUser",
    "iam:CreatePolicy",
    "iam:AddUserToGroup",
    "sts:AssumeRole",
    "iam:*",
    "*:*",
    "*",
}

# Actions that let a principal pivot into another role.
ASSUME_ACTIONS = {"sts:AssumeRole", "iam:*", "*:*", "*"}


class RiskLevel(Enum):
    """Risk levels for permissions."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class PermissionRiskScore:
    """Risk score for a single permission."""
    permission_id: str
    action: str
    risk_level: RiskLevel
    risk_score: float          # 0-10 scale
    causal_strength: float     # 0-1 share of counterfactual contribution
    exposure_count: int        # how many users can reach this permission
    is_sensitive: bool
    justification: str
    routes_broken: int = 0     # counterfactual: routes removed if grant deleted


# ==========================================================================
# Route model + counterfactual core (module-level, deterministic, testable)
# ==========================================================================

def _nodes_with_label(graph: nx.DiGraph, label: str) -> List[str]:
    return [n for n, d in graph.nodes(data=True) if d.get("label") == label]


def _role_permissions(graph: nx.DiGraph, role: str) -> List[str]:
    return [
        p for p in graph.successors(role)
        if graph.nodes[p].get("label") == "Permission"
    ]


def _user_roles(graph: nx.DiGraph, user: str) -> List[str]:
    return [
        r for r in graph.successors(user)
        if graph.nodes[r].get("label") == "Role"
    ]


def _action(graph: nx.DiGraph, perm: str) -> str:
    return graph.nodes[perm].get("action", "")


def _is_sensitive(graph: nx.DiGraph, perm: str) -> bool:
    return bool(graph.nodes[perm].get("is_sensitive", False))


def _role_profiles(graph: nx.DiGraph) -> Dict[str, dict]:
    """Precompute per-role escalation properties used by route enumeration."""
    profiles: Dict[str, dict] = {}
    for role in _nodes_with_label(graph, "Role"):
        perms = _role_permissions(graph, role)
        sts_perms = [p for p in perms if _action(graph, p) in ASSUME_ACTIONS]
        privesc_perms = [p for p in perms if _action(graph, p) in PRIVESC_ACTIONS]
        # A "payload" is a permission worth reaching once you land on this role:
        # anything sensitive or itself an escalation action.
        payloads = [
            p for p in perms
            if _is_sensitive(graph, p) or _action(graph, p) in PRIVESC_ACTIONS
        ]
        profiles[role] = {
            "perms": perms,
            "sts_perms": sts_perms,
            "is_pivot": bool(sts_perms),
            "is_target": bool(privesc_perms),
            "payloads": payloads,
        }
    return profiles


def enumerate_route_edges(graph: nx.DiGraph) -> Tuple[Dict[Edge, int], int]:
    """Enumerate reachable escalation routes; credit each edge they traverse.

    Two route families are modelled:

    * **Assume-pivot routes** ``user -> pivot_role -(sts)-> target_role -> payload``:
      a user who holds a role granting ``sts:AssumeRole`` can pivot into any
      privilege-escalation-capable target role and use its sensitive payloads.
    * **Direct-technique routes** ``user -> role -> privesc_permission``: a user
      who directly holds a role granting an escalation action.

    Returns ``(edge_credit, total_routes)`` where ``edge_credit[e]`` is the
    number of routes traversing edge ``e``. Because a route is a fixed set of
    edges and removing an edge deletes exactly the routes through it (and
    creates none), ``edge_credit[e]`` equals the counterfactual
    ``|routes(G)| - |routes(G - e)|`` -- see :func:`count_attack_paths`.
    """
    profiles = _role_profiles(graph)
    target_roles = [r for r, p in profiles.items() if p["is_target"]]

    edge_credit: Dict[Edge, int] = defaultdict(int)
    total = 0

    for user in _nodes_with_label(graph, "User"):
        held_roles = _user_roles(graph, user)

        # --- assume-pivot routes ---
        pivot_roles = [r for r in held_roles if profiles[r]["is_pivot"]]
        for pivot in pivot_roles:
            for sts_perm in profiles[pivot]["sts_perms"]:
                for target in target_roles:
                    if target == pivot:
                        continue
                    for payload in profiles[target]["payloads"]:
                        total += 1
                        edge_credit[(user, pivot)] += 1
                        edge_credit[(pivot, sts_perm)] += 1
                        edge_credit[(target, payload)] += 1

        # --- direct-technique routes ---
        for role in held_roles:
            for perm in profiles[role]["perms"]:
                if _action(graph, perm) in PRIVESC_ACTIONS:
                    total += 1
                    edge_credit[(user, role)] += 1
                    edge_credit[(role, perm)] += 1

    return dict(edge_credit), total


def count_attack_paths(graph: nx.DiGraph) -> int:
    """Total number of reachable escalation routes in ``graph``.

    Recomputed from scratch, so callers can verify the counterfactual honestly
    by comparing ``count_attack_paths(G)`` with ``count_attack_paths(G - edge)``.
    """
    return enumerate_route_edges(graph)[1]


# ==========================================================================
# Counterfactual scorer
# ==========================================================================

class CounterfactualRiskScorer:
    """Scores permissions by the escalation routes their removal would break."""

    def __init__(self, graph: nx.DiGraph):
        self.graph = graph
        self.edge_credit, self.total_routes = enumerate_route_edges(graph)

    # -- counterfactual primitives ----------------------------------------

    def routes_broken_by_removing_grant(self, role_id: str, perm_id: str) -> int:
        """Counterfactual for one grant edge: routes broken by ``do(grant=removed)``."""
        return self.edge_credit.get((role_id, perm_id), 0)

    def _permission_routes(self, permission_id: str) -> int:
        """Routes broken by removing this permission (all its incoming grants)."""
        total = 0
        for role in self.graph.predecessors(permission_id):
            if self.graph.nodes[role].get("label") == "Role":
                total += self.edge_credit.get((role, permission_id), 0)
        return total

    def _count_user_exposures(self, permission_id: str) -> int:
        count = 0
        for role in self.graph.predecessors(permission_id):
            if self.graph.nodes[role].get("label") != "Role":
                continue
            count += sum(
                1 for u in self.graph.predecessors(role)
                if self.graph.nodes[u].get("label") == "User"
            )
        return count

    # -- public scoring API ------------------------------------------------

    def score_permission_risk(self, permission_id: str) -> PermissionRiskScore:
        if not self.graph.has_node(permission_id):
            raise ValueError(f"Permission {permission_id} not found in graph")

        node = self.graph.nodes[permission_id]
        action = node.get("action", "unknown")
        is_sensitive = bool(node.get("is_sensitive", False))

        routes = self._permission_routes(permission_id)
        max_routes = self._max_permission_routes()

        # 0-10 score relative to the riskiest permission in the graph.
        risk_score = round(10.0 * routes / max_routes, 2) if max_routes else 0.0
        causal_strength = round(routes / max_routes, 4) if max_routes else 0.0
        risk_level = self._route_count_to_level(routes, max_routes)
        exposure = self._count_user_exposures(permission_id)

        return PermissionRiskScore(
            permission_id=permission_id,
            action=action,
            risk_level=risk_level,
            risk_score=risk_score,
            causal_strength=causal_strength,
            exposure_count=exposure,
            is_sensitive=is_sensitive,
            justification=self._justify(action, routes, exposure, is_sensitive),
            routes_broken=routes,
        )

    def score_all_permissions(self) -> List[PermissionRiskScore]:
        perms = _nodes_with_label(self.graph, "Permission")
        scores = [self.score_permission_risk(p) for p in perms]
        scores.sort(key=lambda s: (s.routes_broken, s.risk_score), reverse=True)
        return scores

    def generate_risk_report(self) -> Dict:
        all_scores = self.score_all_permissions()
        return {
            "total_permissions": len(all_scores),
            "total_attack_routes": self.total_routes,
            "permissions_by_risk_level": self._group_by_risk_level(all_scores),
            "top_10_riskiest": [
                {
                    "action": s.action,
                    "risk_level": s.risk_level.value,
                    "risk_score": s.risk_score,
                    "routes_broken": s.routes_broken,
                    "exposure_count": s.exposure_count,
                    "justification": s.justification,
                }
                for s in all_scores[:10]
            ],
            "causal_attribution": self._counterfactual_attribution(all_scores),
            "recommendations": self._recommendations(all_scores),
        }

    # -- internals ---------------------------------------------------------

    def _max_permission_routes(self) -> int:
        if not self.edge_credit:
            return 0
        best = 0
        for perm in _nodes_with_label(self.graph, "Permission"):
            best = max(best, self._permission_routes(perm))
        return best

    @staticmethod
    def _route_count_to_level(routes: int, max_routes: int) -> RiskLevel:
        # A permission whose removal breaks no reachable route is not a live
        # escalation risk, regardless of how "sensitive" it is flagged.
        if routes <= 0:
            return RiskLevel.LOW
        if max_routes and routes >= 0.5 * max_routes:
            return RiskLevel.CRITICAL
        return RiskLevel.HIGH

    def _justify(self, action: str, routes: int, exposure: int,
                 is_sensitive: bool) -> str:
        if routes <= 0:
            if is_sensitive:
                return "sensitive but on no reachable escalation route"
            return "not on any reachable escalation route"
        reasons = [f"removing it breaks {routes} reachable escalation route(s)"]
        if action in PRIVESC_ACTIONS:
            reasons.append("privilege-escalation action")
        if exposure:
            reasons.append(f"reachable by {exposure} user(s)")
        return "; ".join(reasons)

    @staticmethod
    def _group_by_risk_level(scores: List[PermissionRiskScore]) -> Dict:
        grouped = {level.value: [] for level in RiskLevel}
        for s in scores:
            grouped[s.risk_level.value].append(s.action)
        return {k: v for k, v in grouped.items() if v}

    def _counterfactual_attribution(self, scores: List[PermissionRiskScore]) -> Dict:
        total = sum(s.routes_broken for s in scores)
        if total == 0:
            return {}
        attribution: Dict[str, float] = {}
        for s in scores[:5]:
            attribution[s.action] = round(s.routes_broken / total * 100, 1)
        return attribution

    def _recommendations(self, scores: List[PermissionRiskScore]) -> List[str]:
        recs: List[str] = []
        critical = [s for s in scores if s.risk_level == RiskLevel.CRITICAL]
        if critical:
            actions = list(dict.fromkeys(s.action for s in critical))[:3]
            recs.append(
                f"URGENT: these permissions sit on the most escalation routes: "
                f"{', '.join(actions)}"
            )
        top = scores[0] if scores else None
        if top and top.routes_broken > 0:
            recs.append(
                f"Removing '{top.action}' would break {top.routes_broken} "
                f"escalation route(s) -- highest counterfactual impact."
            )
        unreachable_sensitive = [
            s for s in scores if s.is_sensitive and s.routes_broken == 0
        ]
        if unreachable_sensitive:
            recs.append(
                f"{len(unreachable_sensitive)} sensitive permission(s) are on no "
                f"reachable escalation route -- lower priority than raw "
                f"sensitivity suggests."
            )
        recs.append(
            "Apply Blue AI defenses to cut the highest-counterfactual grants first."
        )
        return recs


# ==========================================================================
# Legacy heuristic scorer (retained ONLY for eval-harness baseline comparison)
# ==========================================================================

class HeuristicRiskScorer:
    """Previous weighted-sum scorer. Kept so the eval harness can show that the
    counterfactual scorer beats it. Not used in production scoring anymore.
    """

    SENSITIVE_PERMISSION_BASELINE = {
        "iam:CreateUser": 9.5,
        "iam:AttachRolePolicy": 9.0,
        "iam:PassRole": 8.5,
        "sts:AssumeRole": 8.0,
        "iam:UpdateAssumeRolePolicy": 8.0,
        "iam:PutUserPolicy": 7.5,
        "kms:Decrypt": 7.0,
        "s3:DeleteObject": 6.5,
        "ec2:TerminateInstances": 6.0,
    }

    def __init__(self, graph: nx.DiGraph):
        self.graph = graph

    def score_permission_risk(self, permission_id: str) -> PermissionRiskScore:
        if not self.graph.has_node(permission_id):
            raise ValueError(f"Permission {permission_id} not found in graph")

        perm_node = self.graph.nodes[permission_id]
        action = perm_node.get("action", "unknown")
        is_sensitive = perm_node.get("is_sensitive", False)

        base_risk = self.SENSITIVE_PERMISSION_BASELINE.get(action, 3.0)
        exposure_count = self._count_user_exposures(permission_id)
        multiplier = self._calculate_exposure_multiplier(exposure_count)
        escalation_potential = self._calculate_escalation_potential(permission_id)
        causal_strength = self._compute_causal_strength(
            permission_id, base_risk, escalation_potential
        )
        risk_score = min(10.0, base_risk * multiplier + escalation_potential * 0.5)
        risk_level = self._score_to_level(risk_score)
        justification = self._generate_justification(
            action, exposure_count, escalation_potential, is_sensitive
        )
        return PermissionRiskScore(
            permission_id=permission_id,
            action=action,
            risk_level=risk_level,
            risk_score=round(risk_score, 2),
            causal_strength=round(causal_strength, 2),
            exposure_count=exposure_count,
            is_sensitive=is_sensitive,
            justification=justification,
        )

    def score_all_permissions(self) -> List[PermissionRiskScore]:
        perms = [
            n for n, d in self.graph.nodes(data=True)
            if d.get("label") == "Permission"
        ]
        scores = []
        for perm_id in perms:
            try:
                scores.append(self.score_permission_risk(perm_id))
            except Exception as e:
                print(f"Error scoring {perm_id}: {e}")
                continue
        scores.sort(key=lambda x: x.risk_score, reverse=True)
        return scores

    def generate_risk_report(self) -> Dict:
        all_scores = self.score_all_permissions()
        return {
            "total_permissions": len(all_scores),
            "permissions_by_risk_level": self._group_by_risk_level(all_scores),
            "top_10_riskiest": [
                {
                    "action": score.action,
                    "risk_level": score.risk_level.value,
                    "risk_score": score.risk_score,
                    "exposure_count": score.exposure_count,
                    "justification": score.justification,
                }
                for score in all_scores[:10]
            ],
            "causal_attribution": self._compute_causal_attribution(all_scores),
            "recommendations": self._generate_recommendations(all_scores),
        }

    def _count_user_exposures(self, permission_id: str) -> int:
        count = 0
        parent_roles = [
            n for n in self.graph.predecessors(permission_id)
            if self.graph.nodes[n].get("label") == "Role"
        ]
        for role in parent_roles:
            users = [
                n for n in self.graph.predecessors(role)
                if self.graph.nodes[n].get("label") == "User"
            ]
            count += len(users)
        return count

    def _calculate_exposure_multiplier(self, exposure_count: int) -> float:
        if exposure_count == 0:
            return 0.5
        elif exposure_count <= 2:
            return 1.0
        elif exposure_count <= 5:
            return 1.3
        elif exposure_count <= 10:
            return 1.6
        else:
            return 2.0

    def _calculate_escalation_potential(self, permission_id: str) -> float:
        potential = 0.0
        if self._enables_role_assumption(permission_id):
            potential += 3.0
        connected_sensitive = self._count_connected_sensitive_perms(permission_id)
        potential += connected_sensitive * 0.5
        return min(3.0, potential)

    def _enables_role_assumption(self, permission_id: str) -> bool:
        return self.graph.nodes[permission_id].get("action") == "sts:AssumeRole"

    def _count_connected_sensitive_perms(self, permission_id: str) -> int:
        count = 0
        visited = set()
        queue = [(permission_id, 0)]
        while queue:
            node, depth = queue.pop(0)
            if node in visited or depth > 2:
                continue
            visited.add(node)
            if (node != permission_id and self.graph.nodes[node].get("label") == "Permission"
                    and self.graph.nodes[node].get("is_sensitive", False)):
                count += 1
            if depth < 2:
                for neighbor in self.graph.successors(node):
                    if neighbor not in visited:
                        queue.append((neighbor, depth + 1))
        return count

    def _compute_causal_strength(self, permission_id: str, base_risk: float,
                                 escalation_potential: float) -> float:
        exposure = self._count_user_exposures(permission_id)
        exposure_factor = min(1.0, exposure / 10.0)
        escalation_factor = escalation_potential / 3.0
        is_sensitive = self.graph.nodes[permission_id].get("is_sensitive", False)
        sensitivity_factor = 1.0 if is_sensitive else 0.5
        causal_strength = (
            (base_risk / 10.0 * 0.4)
            + (exposure_factor * 0.3)
            + (escalation_factor * 0.2)
            + (sensitivity_factor * 0.1)
        )
        return min(1.0, causal_strength)

    def _score_to_level(self, risk_score: float) -> RiskLevel:
        if risk_score >= 8.0:
            return RiskLevel.CRITICAL
        elif risk_score >= 6.0:
            return RiskLevel.HIGH
        elif risk_score >= 3.5:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def _generate_justification(self, action: str, exposure_count: int,
                                escalation_potential: float, is_sensitive: bool) -> str:
        reasons = []
        if is_sensitive:
            reasons.append("marked as sensitive")
        if exposure_count > 5:
            reasons.append(f"exposed to {exposure_count} users")
        elif exposure_count > 0:
            reasons.append(f"exposed to {exposure_count} user(s)")
        if escalation_potential > 2.0:
            reasons.append("high escalation potential")
        elif escalation_potential > 1.0:
            reasons.append("moderate escalation potential")
        if action in ["iam:PassRole", "sts:AssumeRole"]:
            reasons.append("enables privilege escalation")
        return "; ".join(reasons) if reasons else "baseline permission risk"

    def _group_by_risk_level(self, scores: List[PermissionRiskScore]) -> Dict:
        grouped = {level.value: [] for level in RiskLevel}
        for score in scores:
            grouped[score.risk_level.value].append(score.action)
        return {k: v for k, v in grouped.items() if v}

    def _compute_causal_attribution(self, scores: List[PermissionRiskScore]) -> Dict:
        total_causal_strength = sum(s.causal_strength for s in scores)
        if total_causal_strength == 0:
            return {}
        attribution = {}
        for score in scores[:5]:
            pct = (score.causal_strength / total_causal_strength) * 100
            attribution[score.action] = round(pct, 1)
        return attribution

    def _generate_recommendations(self, scores: List[PermissionRiskScore]) -> List[str]:
        recommendations = []
        critical = [s for s in scores if s.risk_level == RiskLevel.CRITICAL]
        if critical:
            actions = [s.action for s in critical]
            recommendations.append(
                f"URGENT: Restrict or audit access to: {', '.join(actions[:3])}"
            )
        high_exposure = [s for s in scores if s.exposure_count > 5]
        if high_exposure:
            top = high_exposure[0]
            recommendations.append(
                f"Permission '{top.action}' is exposed to {top.exposure_count} users - "
                f"consider role splits for least privilege"
            )
        escalation_prone = [s for s in scores if "escalation" in s.justification.lower()]
        if escalation_prone:
            recommendations.append(
                f"Monitor escalation-prone permissions: "
                f"{', '.join([s.action for s in escalation_prone[:2]])}"
            )
        recommendations.append(
            "Apply Blue AI defenses to remove high-risk permissions from over-permissive roles"
        )
        return recommendations


# Backwards-compatible alias. Historically named "causal"; the implementation
# is now counterfactual attack-path analysis, not a probabilistic SCM.
CausalRiskScorer = CounterfactualRiskScorer
