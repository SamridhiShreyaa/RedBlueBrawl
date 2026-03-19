from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from src.graph.queries import (
    get_high_privilege_roles,
    get_low_privilege_users,
    get_user_roles,
    get_role_permissions,
)


SENSITIVE_ACTIONS = {
    "iam:CreateUser",
    "iam:AttachRolePolicy",
    "iam:PassRole",
    "sts:AssumeRole",
    "kms:Decrypt",
    "ec2:TerminateInstances",
    "s3:DeleteObject",
}


@dataclass
class AttackPath:
    nodes: list[str]
    permissions_used: list[str]
    risk_score: float
    description: str
    attack_type: str


class RedAgent:
    """Deterministic attacker for fast privilege-escalation discovery."""

    def __init__(self, graph: nx.DiGraph):
        self.graph = graph

    def find_escalation_paths(self, max_paths: int = 10) -> list[AttackPath]:
        paths: list[AttackPath] = []

        low_priv_users = get_low_privilege_users(self.graph, max_roles=2)
        high_priv_roles = get_high_privilege_roles(self.graph, min_permissions=5)

        # Direct pathing to risky roles only works if those roles are reachable in the graph.
        for user in low_priv_users[:40]:
            for role in high_priv_roles[:20]:
                try:
                    node_path = nx.shortest_path(self.graph, source=user, target=role)
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue
                if len(node_path) < 3:
                    continue
                paths.append(self._build_attack_path(node_path, attack_type="direct_graph_path"))

        # Inferred escalation using sts:AssumeRole from low-priv roles into admin-like roles.
        paths.extend(self._find_assume_role_escalations(high_priv_roles))

        paths.sort(key=lambda item: item.risk_score, reverse=True)
        return self._dedupe_paths(paths)[:max_paths]

    def _find_assume_role_escalations(self, high_priv_roles: list[str]) -> list[AttackPath]:
        results: list[AttackPath] = []

        sts_perm_nodes = [
            n for n, attrs in self.graph.nodes(data=True)
            if attrs.get("label") == "Permission"
            and attrs.get("action") == "sts:AssumeRole"
        ]

        for sts_perm in sts_perm_nodes:
            pivot_roles = [
                role for role in self.graph.predecessors(sts_perm)
                if self.graph.nodes[role].get("label") == "Role"
            ]
            for pivot_role in pivot_roles:
                users = [
                    user for user in self.graph.predecessors(pivot_role)
                    if self.graph.nodes[user].get("label") == "User"
                ]
                for user in users:
                    for target_role in high_priv_roles[:5]:
                        if target_role == pivot_role:
                            continue

                        # Calculate dynamic risk floor based on target role power
                        dynamic_floor = self._calculate_target_role_power(target_role)
                        
                        node_path = [user, pivot_role, sts_perm, target_role]
                        attack = self._build_attack_path(
                            node_path,
                            attack_type="assume_role_inference",
                            risk_floor=dynamic_floor,
                            user_id=user,
                        )
                        results.append(attack)

        return results

    def _build_attack_path(
        self,
        node_path: list[str],
        attack_type: str,
        risk_floor: float = 0.0,
        user_id: str = None,
    ) -> AttackPath:
        permissions_used = [
            node_id
            for node_id in node_path
            if self.graph.nodes[node_id].get("label") == "Permission"
        ]

        sensitive_hits = sum(1 for perm in permissions_used if self._is_sensitive_permission(perm))
        risk_score = (
            sensitive_hits * 3.0
            + len(permissions_used) * 0.5
            + (10.0 / max(len(node_path), 1))
        )
        
        # Apply path length bonus (shorter paths are easier attacks)
        path_length_bonus = self._calculate_path_length_bonus(node_path)
        risk_score += path_length_bonus
        
        # Apply user insider-threat scoring bonus
        if user_id:
            threat_bonus = self._calculate_user_threat_score(user_id)
            risk_score += threat_bonus
        
        risk_score = max(risk_score, risk_floor)

        return AttackPath(
            nodes=node_path,
            permissions_used=permissions_used,
            risk_score=round(risk_score, 2),
            description=self._describe(node_path, permissions_used, attack_type),
            attack_type=attack_type,
        )

    def _calculate_target_role_power(self, role_id: str) -> float:
        """
        Dynamic risk floor based on target role permissions.
        Higher privilege target = higher base floor.
        """
        target_perms = get_role_permissions(self.graph, role_id)
        # Base: 6.0 + bonus per permission (0.3 per perm)
        return 6.0 + (len(target_perms) * 0.3)

    def _calculate_user_threat_score(self, user_id: str) -> float:
        """
        Insider-threat scoring: users with existing high privilege are more suspicious.
        Higher existing roles = higher threat multiplier.
        """
        user_roles = get_user_roles(self.graph, user_id)
        # Base threat: 0.1 per existing role (max ~2 roles = +0.2 bonus)
        return len(user_roles) * 0.1

    def _calculate_path_length_bonus(self, node_path: list[str]) -> float:
        """
        Shorter paths are easier attacks (direct escalation = higher risk).
        Three or fewer nodes gets a +0.5 bonus.
        """
        return 0.5 if len(node_path) <= 3 else 0.0

    def _describe(self, nodes: list[str], perms: list[str], attack_type: str) -> str:
        start_user = self.graph.nodes[nodes[0]].get("username", nodes[0])
        target = self.graph.nodes[nodes[-1]].get("name", nodes[-1])
        perm_actions = [self.graph.nodes[p].get("action", p) for p in perms]
        perm_str = ", ".join(perm_actions[:3]) if perm_actions else "no explicit permissions"
        return (
            f"{attack_type}: user '{start_user}' can reach '{target}' "
            f"via {len(nodes) - 2} intermediate nodes using {perm_str}"
        )

    def _is_sensitive_permission(self, perm_id: str) -> bool:
        attrs = self.graph.nodes[perm_id]
        action = attrs.get("action", "")
        return attrs.get("is_sensitive", False) or action in SENSITIVE_ACTIONS

    @staticmethod
    def _dedupe_paths(paths: list[AttackPath]) -> list[AttackPath]:
        seen: set[tuple[str, ...]] = set()
        unique: list[AttackPath] = []
        for path in paths:
            key = tuple(path.nodes)
            if key in seen:
                continue
            seen.add(key)
            unique.append(path)
        return unique
