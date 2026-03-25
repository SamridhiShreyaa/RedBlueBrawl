"""
Causal Risk Scorer for IAM Permissions.

Uses structural causal models and counterfactual reasoning to determine
which specific permissions contribute to increased security risk.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Set, Tuple

import networkx as nx
import numpy as np
import pandas as pd


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
    risk_score: float  # 0-10 scale
    causal_strength: float  # How strongly this permission causes risk
    exposure_count: int  # How many users are exposed
    is_sensitive: bool
    justification: str


class CausalRiskScorer:
    """
    Determines which permissions causally increase IAM vulnerability.
    
    Uses structural analysis, frequency analysis, and privilege escalation
    potential to score permissions without relying on heuristics alone.
    """

    # Known sensitive actions and their baseline risk
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
        """
        Initialize the causal risk scorer.
        
        Args:
            graph: IAM graph from builder
        """
        self.graph = graph
        self._build_causal_model()

    def _build_causal_model(self):
        """Build internal causal model from graph structure."""
        self.permission_data = self._extract_permission_features()

    def score_permission_risk(self, permission_id: str) -> PermissionRiskScore:
        """
        Compute causal risk score for a single permission.
        
        Args:
            permission_id: The permission node ID
            
        Returns:
            PermissionRiskScore with full risk attribution
        """
        if not self.graph.has_node(permission_id):
            raise ValueError(f"Permission {permission_id} not found in graph")

        perm_node = self.graph.nodes[permission_id]
        action = perm_node.get("action", "unknown")
        is_sensitive = perm_node.get("is_sensitive", False)

        # Calculate base risk from action type
        base_risk = self.SENSITIVE_PERMISSION_BASELINE.get(action, 3.0)

        # Adjust based on graph structural features
        exposure_count = self._count_user_exposures(permission_id)
        multiplier = self._calculate_exposure_multiplier(exposure_count)

        # Calculate escalation potential (how many hops to high-value targets)
        escalation_potential = self._calculate_escalation_potential(permission_id)

        # Compute causal strength: how much this permission directly enables attacks
        causal_strength = self._compute_causal_strength(
            permission_id, base_risk, escalation_potential
        )

        # Final risk score
        risk_score = min(10.0, base_risk * multiplier + escalation_potential * 0.5)

        # Determine risk level
        risk_level = self._score_to_level(risk_score)

        # Generate justification
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
        """
        Score all permissions in the graph.
        
        Returns:
            Sorted list of PermissionRiskScore (highest risk first)
        """
        perms = [
            n for n, d in self.graph.nodes(data=True)
            if d.get("label") == "Permission"
        ]

        scores = []
        for perm_id in perms:
            try:
                score = self.score_permission_risk(perm_id)
                scores.append(score)
            except Exception as e:
                print(f"Error scoring {perm_id}: {e}")
                continue

        # Sort by risk score descending
        scores.sort(key=lambda x: x.risk_score, reverse=True)
        return scores

    def generate_risk_report(self) -> Dict:
        """
        Generate comprehensive risk report for all permissions.
        
        Returns:
            Dictionary with risk summary and recommendations
        """
        all_scores = self.score_all_permissions()

        report = {
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

        return report

    # ==================== INTERNAL HELPERS ====================

    def _extract_permission_features(self) -> Dict:
        """Extract structural features for each permission."""
        features = {}

        perms = [
            n for n, d in self.graph.nodes(data=True)
            if d.get("label") == "Permission"
        ]

        for perm in perms:
            features[perm] = {
                "exposure": self._count_user_exposures(perm),
                "escalation_potential": self._calculate_escalation_potential(perm),
            }

        return features

    def _count_user_exposures(self, permission_id: str) -> int:
        """Count how many users have access to this permission."""
        count = 0

        # Find all roles with this permission
        parent_roles = [
            n for n in self.graph.predecessors(permission_id)
            if self.graph.nodes[n].get("label") == "Role"
        ]

        # Find all users with those roles
        for role in parent_roles:
            users = [
                n for n in self.graph.predecessors(role)
                if self.graph.nodes[n].get("label") == "User"
            ]
            count += len(users)

        return count

    def _calculate_exposure_multiplier(self, exposure_count: int) -> float:
        """
        Permissions exposed to more users increase risk.
        
        Multiplier: more exposure = higher multiplier
        """
        if exposure_count == 0:
            return 0.5  # Orphaned permission, low risk
        elif exposure_count <= 2:
            return 1.0  # Single/few users, standard risk
        elif exposure_count <= 5:
            return 1.3  # Medium exposure
        elif exposure_count <= 10:
            return 1.6  # High exposure
        else:
            return 2.0  # Very high exposure (broad access)

    def _calculate_escalation_potential(self, permission_id: str) -> float:
        """
        How easily can this permission be leveraged for escalation?
        
        Metric: shortest path to high-privilege roles or resources
        """
        potential = 0.0

        # Check if permission leads to role assumption
        if self._enables_role_assumption(permission_id):
            potential += 3.0

        # Check connectivity to other sensitive permissions
        connected_sensitive = self._count_connected_sensitive_perms(permission_id)
        potential += connected_sensitive * 0.5

        return min(3.0, potential)  # Cap at 3.0

    def _enables_role_assumption(self, permission_id: str) -> bool:
        """Check if this permission is sts:AssumeRole."""
        perm_node = self.graph.nodes[permission_id]
        return perm_node.get("action") == "sts:AssumeRole"

    def _count_connected_sensitive_perms(self, permission_id: str) -> int:
        """Count other sensitive permissions reachable via role chains."""
        count = 0
        visited = set()

        # BFS to find connected sensitive permissions via role hops
        queue = [(permission_id, 0)]  # (node_id, depth)

        while queue:
            node, depth = queue.pop(0)

            if node in visited or depth > 2:
                continue

            visited.add(node)

            # If this is a sensitive permission, count it
            if (node != permission_id and self.graph.nodes[node].get("label") == "Permission"
                    and self.graph.nodes[node].get("is_sensitive", False)):
                count += 1

            # Explore via roles
            if depth < 2:
                for neighbor in self.graph.successors(node):
                    if neighbor not in visited:
                        queue.append((neighbor, depth + 1))

        return count

    def _compute_causal_strength(
        self,
        permission_id: str,
        base_risk: float,
        escalation_potential: float,
    ) -> float:
        """
        Compute how much this permission causally increases risk.
        
        Combines base risk, exposure, and escalation potential into 
        a causal strength metric (0-1 scale).
        """
        exposure = self._count_user_exposures(permission_id)
        exposure_factor = min(1.0, exposure / 10.0)  # Normalize to 0-1

        escalation_factor = escalation_potential / 3.0  # Normalize

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
        """Convert numeric risk score to risk level."""
        if risk_score >= 8.0:
            return RiskLevel.CRITICAL
        elif risk_score >= 6.0:
            return RiskLevel.HIGH
        elif risk_score >= 3.5:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def _generate_justification(
        self,
        action: str,
        exposure_count: int,
        escalation_potential: float,
        is_sensitive: bool,
    ) -> str:
        """Generate human-readable justification for risk score."""
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
        """Group permissions by risk level."""
        grouped = {level.value: [] for level in RiskLevel}

        for score in scores:
            grouped[score.risk_level.value].append(score.action)

        return {k: v for k, v in grouped.items() if v}

    def _compute_causal_attribution(self, scores: List[PermissionRiskScore]) -> Dict:
        """
        Compute causal attribution: which permissions contribute most to overall risk?
        """
        total_causal_strength = sum(s.causal_strength for s in scores)

        if total_causal_strength == 0:
            return {}

        attribution = {}
        for score in scores[:5]:  # Top 5
            pct = (score.causal_strength / total_causal_strength) * 100
            attribution[score.action] = round(pct, 1)

        return attribution

    def _generate_recommendations(self, scores: List[PermissionRiskScore]) -> List[str]:
        """Generate actionable recommendations based on causal analysis."""
        recommendations = []

        # Find permissions in CRITICAL risk level
        critical = [s for s in scores if s.risk_level == RiskLevel.CRITICAL]
        if critical:
            actions = [s.action for s in critical]
            recommendations.append(
                f"URGENT: Restrict or audit access to: {', '.join(actions[:3])}"
            )

        # Find over-exposed permissions
        high_exposure = [s for s in scores if s.exposure_count > 5]
        if high_exposure:
            top = high_exposure[0]
            recommendations.append(
                f"Permission '{top.action}' is exposed to {top.exposure_count} users - "
                f"consider role splits for least privilege"
            )

        # Find permissions with escalation potential
        escalation_prone = [
            s for s in scores
            if "escalation" in s.justification.lower()
        ]
        if escalation_prone:
            recommendations.append(
                f"Monitor escalation-prone permissions: "
                f"{', '.join([s.action for s in escalation_prone[:2]])}"
            )

        # General recommendation
        recommendations.append(
            "Apply Blue AI defenses to remove high-risk permissions from over-permissive roles"
        )

        return recommendations
