from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Set, Tuple

import networkx as nx

from src.graph.queries import (
    get_role_permissions,
    get_user_roles,
    get_roles,
    get_users,
)


class DefenseActionType(Enum):
    """Types of defensive actions Blue AI can take."""
    REMOVE_PERMISSION = "remove_permission"
    REVOKE_ROLE = "revoke_role"
    SPLIT_ROLE = "split_role"
    RESTRICT_ROLE = "restrict_role"


@dataclass
class DefenseAction:
    """Represents a single defense action."""
    action_type: DefenseActionType
    target_id: str  # role_id or user_id or permission_id
    details: Dict = field(default_factory=dict)
    justification: str = ""
    risk_reduction: float = 0.0


@dataclass
class DefenseStrategy:
    """Collection of defense actions to harden IAM."""
    actions: List[DefenseAction] = field(default_factory=list)
    total_risk_reduction: float = 0.0
    permissive_roles_targeted: int = 0
    perms_removed: int = 0


class BlueAgent:
    """Defensive optimizer that hardens IAM by fixing vulnerabilities found by Red AI."""

    def __init__(self, graph: nx.DiGraph):
        self.graph = graph.copy()  # Work on a copy to preserve original
        self.original_graph = graph
        self.defense_history: List[DefenseAction] = []

    def generate_defenses(self, attack_paths: List) -> DefenseStrategy:
        """
        Analyze attack paths and generate defensive actions.
        
        Args:
            attack_paths: List of AttackPath objects from RedAgent
            
        Returns:
            DefenseStrategy with recommended actions
        """
        strategy = DefenseStrategy()
        targeted_permissions: Set[str] = set()
        targeted_roles: Set[str] = set()
        
        # Extract high-risk permissions and roles from attack paths
        for attack in attack_paths:
            for perm in attack.permissions_used:
                targeted_permissions.add(perm)
            
            # Target roles with high-risk permissions in the attack path
            for node in attack.nodes:
                if self.graph.nodes[node].get("label") == "Role":
                    targeted_roles.add(node)

        # Strategy 1: Remove sensitive permissions from overly permissive roles
        for role_id in targeted_roles:
            perms = get_role_permissions(self.graph, role_id)
            sensitive_perms = [
                p for p in perms 
                if p in targeted_permissions
            ]
            
            if sensitive_perms:
                # Remove each sensitive permission
                for perm in sensitive_perms:
                    action = DefenseAction(
                        action_type=DefenseActionType.REMOVE_PERMISSION,
                        target_id=perm,
                        details={"role_id": role_id},
                        justification=f"Remove {perm} from {role_id} - sensitive permission in attack paths",
                        risk_reduction=2.0,
                    )
                    strategy.actions.append(action)
                    strategy.perms_removed += 1

        # Strategy 2: Split overly permissive roles
        heavy_roles = [
            role for role in targeted_roles 
            if len(get_role_permissions(self.graph, role)) >= 5
        ]
        
        for role_id in heavy_roles:
            action = DefenseAction(
                action_type=DefenseActionType.SPLIT_ROLE,
                target_id=role_id,
                details={
                    "new_roles": [f"{role_id}_restricted", f"{role_id}_sensitive"]
                },
                justification=f"Split {role_id} into restricted and sensitive roles for least privilege",
                risk_reduction=3.5,
            )
            strategy.actions.append(action)
            strategy.permissive_roles_targeted += 1

        # Strategy 3: Restrict low-value, high-risk assume-role permissions
        assume_role_perms = [
            n for n, attrs in self.graph.nodes(data=True)
            if attrs.get("label") == "Permission" 
            and attrs.get("action") == "sts:AssumeRole"
        ]
        
        for asm_perm in assume_role_perms:
            # Find roles with assume_role permission
            roles_with_assume = [
                role for role in self.graph.predecessors(asm_perm)
                if self.graph.nodes[role].get("label") == "Role"
            ]
            
            for role in roles_with_assume:
                users = [u for u in self.graph.predecessors(role) 
                        if self.graph.nodes[u].get("label") == "User"]
                
                # If only 1-2 users have this role with assume_role, can revoke
                if len(users) <= 2 and role in targeted_roles:
                    action = DefenseAction(
                        action_type=DefenseActionType.REVOKE_ROLE,
                        target_id=role,
                        details={"affected_users": users},
                        justification=f"Revoke assumption-capable role {role} from {len(users)} user(s)",
                        risk_reduction=2.5,
                    )
                    strategy.actions.append(action)

        # Calculate total risk reduction
        strategy.total_risk_reduction = sum(a.risk_reduction for a in strategy.actions)
        
        return strategy

    def apply_defenses(self, strategy: DefenseStrategy) -> Tuple[nx.DiGraph, int]:
        """
        Apply defensive actions to the IAM graph.
        
        Args:
            strategy: DefenseStrategy with actions to apply
            
        Returns:
            Tuple of (modified_graph, actions_applied_count)
        """
        applied_count = 0
        
        for action in strategy.actions:
            try:
                if action.action_type == DefenseActionType.REMOVE_PERMISSION:
                    # Remove edge: role -> permission
                    role_id = action.details.get("role_id")
                    perm_id = action.target_id
                    if self.graph.has_edge(role_id, perm_id):
                        self.graph.remove_edge(role_id, perm_id)
                        self.defense_history.append(action)
                        applied_count += 1
                
                elif action.action_type == DefenseActionType.REVOKE_ROLE:
                    # Remove edges: user -> role
                    role_id = action.target_id
                    users = action.details.get("affected_users", [])
                    for user in users:
                        if self.graph.has_edge(user, role_id):
                            self.graph.remove_edge(user, role_id)
                            applied_count += 1
                    self.defense_history.append(action)
                
                elif action.action_type == DefenseActionType.SPLIT_ROLE:
                    # Split a role into two: one restricted, one sensitive
                    role_id = action.target_id
                    new_roles = action.details.get("new_roles", [])
                    
                    if not self.graph.has_node(role_id):
                        continue
                    
                    all_perms = get_role_permissions(self.graph, role_id)
                    sensitive_perms = [p for p in all_perms if 
                        self.graph.nodes[p].get("is_sensitive", False)]
                    
                    # Create restricted role (non-sensitive permissions only)
                    if new_roles:
                        restricted_role = new_roles[0]
                        self.graph.add_node(restricted_role, label="Role", 
                                          name=restricted_role, is_overpermissive=False)
                        
                        for perm in all_perms:
                            if perm not in sensitive_perms:
                                self.graph.add_edge(restricted_role, perm, relation="GRANTS")
                        
                        # Reassign users to restricted role
                        users = [u for u in self.graph.predecessors(role_id)
                                if self.graph.nodes[u].get("label") == "User"]
                        
                        for user in users:
                            if self.graph.has_edge(user, role_id):
                                self.graph.remove_edge(user, role_id)
                                self.graph.add_edge(user, restricted_role, relation="HAS_ROLE")
                    
                    self.defense_history.append(action)
                    applied_count += 1
                
            except Exception as e:
                print(f"Error applying action {action.action_type}: {e}")
                continue
        
        return self.graph, applied_count

    def compute_metrics(self) -> Dict:
        """
        Compute metrics showing improvement after applying defenses.
        
        Returns:
            Dictionary with before/after metrics
        """
        original_edges = self.original_graph.number_of_edges()
        current_edges = self.graph.number_of_edges()
        edges_removed = original_edges - current_edges
        
        # Calculate risky permission exposure
        original_risky_perms = self._count_risky_exposures(self.original_graph)
        current_risky_perms = self._count_risky_exposures(self.graph)
        
        # Compute average permissions per role
        original_avg_perms_per_role = self._avg_perms_per_role(self.original_graph)
        current_avg_perms_per_role = self._avg_perms_per_role(self.graph)
        
        return {
            "edges_removed": edges_removed,
            "original_edges": original_edges,
            "current_edges": current_edges,
            "original_risky_permission_exposures": original_risky_perms,
            "current_risky_permission_exposures": current_risky_perms,
            "risky_exposures_reduced": original_risky_perms - current_risky_perms,
            "original_avg_perms_per_role": round(original_avg_perms_per_role, 2),
            "current_avg_perms_per_role": round(current_avg_perms_per_role, 2),
            "least_privilege_improvement": round(
                ((original_avg_perms_per_role - current_avg_perms_per_role) / 
                 max(original_avg_perms_per_role, 0.1)) * 100, 
                2
            ),
            "actions_applied": len(self.defense_history),
        }

    def _count_risky_exposures(self, graph: nx.DiGraph) -> int:
        """Count how many users are exposed to sensitive permissions."""
        count = 0
        users = [n for n, d in graph.nodes(data=True) if d.get("label") == "User"]
        
        for user in users:
            roles = [r for r in graph.successors(user) 
                    if graph.nodes[r].get("label") == "Role"]
            
            for role in roles:
                perms = [p for p in graph.successors(role)
                        if graph.nodes[p].get("label") == "Permission"]
                
                for perm in perms:
                    if graph.nodes[perm].get("is_sensitive", False):
                        count += 1
        
        return count

    def _avg_perms_per_role(self, graph: nx.DiGraph) -> float:
        """Calculate average number of permissions per role."""
        roles = [n for n, d in graph.nodes(data=True) if d.get("label") == "Role"]
        
        if not roles:
            return 0.0
        
        total_perms = 0
        for role in roles:
            perms = get_role_permissions(graph, role)
            total_perms += len(perms)
        
        return total_perms / len(roles)

    def get_defense_report(self) -> str:
        """Generate a human-readable defense report."""
        if not self.defense_history:
            return "No defenses applied yet."
        
        report = "=== BLUE AI DEFENSE REPORT ===\n"
        report += f"Total Actions: {len(self.defense_history)}\n\n"
        
        by_type = {}
        for action in self.defense_history:
            action_type = action.action_type.value
            by_type[action_type] = by_type.get(action_type, 0) + 1
        
        for action_type, count in by_type.items():
            report += f"  {action_type}: {count}\n"
        
        report += "\n=== ACTIONS DETAIL ===\n"
        for i, action in enumerate(self.defense_history, 1):
            report += f"{i}. {action.action_type.value} on {action.target_id}\n"
            report += f"   Risk Reduction: {action.risk_reduction}\n"
            report += f"   Justification: {action.justification}\n"
        
        return report
