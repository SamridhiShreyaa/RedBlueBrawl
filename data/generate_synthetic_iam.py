import json
import random
from faker import Faker

fake = Faker()

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

    permissions = [{"id": f"perm_{i}", "action": p} for i, p in enumerate(PERMISSIONS)]

    roles = []
    for i in range(num_roles):
        roles.append({
            "id": f"role_{i}",
            "name": f"role_{i}",
            "permissions": random.sample(
                [p["id"] for p in permissions],
                random.randint(1, 5)
            )
        })

    users = []
    for i in range(num_users):
        users.append({
            "id": f"user_{i}",
            "username": fake.user_name(),
            "department": random.choice(DEPARTMENTS),
            "roles": random.sample(
                [r["id"] for r in roles],
                random.randint(1, 2)
            )
        })

    dataset = {
        "users": users,
        "roles": roles,
        "permissions": permissions
    }

    with open("data/iam_dataset.json", "w") as f:
        json.dump(dataset, f, indent=2)

    print("Dataset generated successfully!")


if __name__ == "__main__":
    generate_dataset()