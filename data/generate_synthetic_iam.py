import json
import os
import random
import hashlib
from faker import Faker

fake = Faker()

SENSITIVE_ACTIONS = {
    "iam:CreateUser",
    "iam:AttachRolePolicy",
    "iam:PassRole",
    "sts:AssumeRole",
    "kms:Decrypt",
    "ec2:TerminateInstances",
    "s3:DeleteObject",
}

DEPARTMENTS = ["Engineering", "Finance", "HR", "DevOps", "Security"]

PERMISSIONS = [
    "s3:GetObject",
    "s3:PutObject",
    "s3:DeleteObject",
    "ec2:StartInstances",
    "ec2:TerminateInstances",
    "iam:CreateUser",
    "iam:AttachRolePolicy",
    "iam:PassRole",
    "sts:AssumeRole",
    "kms:Decrypt"
]


def generate_dataset(num_users=200, num_roles=40):

    permissions = [
        {
            "id": f"perm_{i}",
            "action": p,
            "is_sensitive": p in SENSITIVE_ACTIONS,
        }
        for i, p in enumerate(PERMISSIONS)
    ]

    roles = []
    for i in range(num_roles):
        # Create variation in role permissions for better scoring differentiation
        # Some light roles (2-3 perms), some medium (4-6), some heavy (7-10)
        role_tier = i % 3
        if role_tier == 0:
            perm_count = random.randint(2, 3)  # Light roles
        elif role_tier == 1:
            perm_count = random.randint(4, 6)  # Medium roles
        else:
            perm_count = random.randint(7, 10)  # Heavy/admin roles
        
        roles.append({
            "id": f"role_{i}",
            "name": f"role_{i}",
            "permissions": random.sample(
                [p["id"] for p in permissions],
                min(perm_count, len(permissions))
            ),
            "is_overpermissive": perm_count >= 5,
        })

    # Deterministic escalation seed: varying privilege levels for differentiation
    roles.append({
        "id": "role_escalation_pivot",
        "name": "role_escalation_pivot",
        "permissions": ["perm_8"],  # sts:AssumeRole (low privilege)
        "is_overpermissive": False,
    })
    roles.append({
        "id": "role_admin_low",
        "name": "role_admin_low",
        "permissions": ["perm_5", "perm_6"],  # 2 perms → floor = 6.6
        "is_overpermissive": False,
    })
    roles.append({
        "id": "role_admin_medium",
        "name": "role_admin_medium",
        "permissions": ["perm_5", "perm_6", "perm_7", "perm_9"],  # 4 perms → floor = 7.2
        "is_overpermissive": True,
    })
    roles.append({
        "id": "role_admin_high",
        "name": "role_admin_high",
        "permissions": ["perm_5", "perm_6", "perm_7", "perm_9", "perm_4", "perm_3", "perm_2"],  # 7 perms → floor = 8.1
        "is_overpermissive": True,
    })

    users = []
    for i in range(num_users):
        # Create variation in user roles for threat scoring
        user_tier = i % 3
        if user_tier == 0:
            num_roles = 1  # Fresh users (no threat bonus)
        elif user_tier == 1:
            num_roles = 2  # Medium users (+0.2 threat bonus)
        else:
            num_roles = 3  # Suspicious power users (+0.3 threat bonus)
        
        users.append({
            "id": f"user_{i}",
            "username": fake.user_name(),
            "department": random.choice(DEPARTMENTS),
            "roles": random.sample(
                [r["id"] for r in roles],
                min(num_roles, len(roles))
            )
        })

    # Seed users with different threat levels
    users.append({
        "id": "user_low_threat",
        "username": "jane.new",
        "department": "DevOps",
        "roles": ["role_escalation_pivot"],  # Light user (no threat bonus)
    })
    users.append({
        "id": "user_med_threat",
        "username": "bob.experienced",
        "department": "DevOps",
        "roles": ["role_escalation_pivot", "role_1"],  # Medium user (+0.1 threat bonus)
    })
    users.append({
        "id": "user_high_threat",
        "username": "alice.admin",
        "department": "DevOps",
        "roles": ["role_escalation_pivot", "role_2", "role_3"],  # Suspicious user (+0.3 threat bonus)
    })

    dataset = {
        "users": users,
        "roles": roles,
        "permissions": permissions
    }

    # Compute a stable fingerprint so we can verify which dataset is loaded in Neo4j.
    canonical_payload = json.dumps(
        {
            "users": dataset["users"],
            "roles": dataset["roles"],
            "permissions": dataset["permissions"],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    dataset_id = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()[:16]
    dataset["metadata"] = {
        "dataset_id": dataset_id,
        "user_count": len(users),
        "role_count": len(roles),
        "permission_count": len(permissions),
    }

    os.makedirs("data", exist_ok=True)
    with open("data/iam_dataset.json", "w") as f:
        json.dump(dataset, f, indent=2)

    print(f"Dataset generated successfully! dataset_id={dataset_id}")


if __name__ == "__main__":
    generate_dataset()