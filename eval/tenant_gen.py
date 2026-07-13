"""Deterministic synthetic-tenant generation with planted privesc chains.

Given a fixed seed and difficulty knobs, :func:`generate_tenant` produces an
IAM graph in which a handful of named AWS privilege-escalation chains are
buried among benign distractor roles/users. The exact planted paths and the
edges whose removal breaks them are recorded as ground truth on the returned
:class:`~eval.tenant.Tenant`.

Difficulty axes:
    * ``chain_length`` (2..5): number of role hops from entry user to admin.
    * ``density`` ("low"/"medium"/"high"): how many benign distractor roles
      and users surround the planted chains.

Design choices that make grading unambiguous:
    * Every permission grant is its own node (id ``"<role>::<action>"``), so a
      permission node is risky iff it sits on a planted chain -- no aliasing
      between a chain's ``iam:PassRole`` and a distractor's.
    * Privilege-escalation *technique* actions appear ONLY on planted chains.
      Distractor roles may hold destructive-but-not-escalating sensitive
      actions (``s3:DeleteObject`` etc.) to create realistic false-positive
      pressure: "sensitive" is not the same as "exploitable escalation".
"""

from __future__ import annotations

import random
from typing import Dict, List, Tuple

import networkx as nx

from eval.tenant import PlantedChain, Tenant

Edge = Tuple[str, str]

# Named AWS privilege-escalation techniques. These appear ONLY on planted
# chains, cycled per hop so a length-4 chain reads as a real escalation story
# (e.g. CreatePolicyVersion -> AttachRolePolicy -> PassRole -> admin).
TECHNIQUE_ACTIONS: List[str] = [
    "iam:CreatePolicyVersion",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:PassRole",
    "iam:CreateAccessKey",
    "iam:UpdateAssumeRolePolicy",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy",
]

# Admin sink: >=5 permissions so RedAgent flags it as a high-privilege target.
ADMIN_ACTIONS: List[str] = [
    "iam:*",
    "sts:AssumeRole",
    "iam:CreateUser",
    "iam:AttachRolePolicy",
    "iam:PassRole",
    "iam:PutRolePolicy",
]

# Genuinely harmless actions used to pad distractor roles.
BENIGN_ACTIONS: List[str] = [
    "s3:GetObject",
    "s3:PutObject",
    "logs:CreateLogStream",
    "cloudwatch:PutMetricData",
    "ec2:DescribeInstances",
    "dynamodb:GetItem",
    "sqs:SendMessage",
    "sns:Publish",
]

# Sensitive but NOT privilege-escalating. A method that flags "anything
# sensitive" will trip over these and lose precision -- which is the point.
DISTRACTOR_SENSITIVE_ACTIONS: List[str] = [
    "s3:DeleteObject",
    "kms:Decrypt",
    "ec2:TerminateInstances",
]

ASSUME_ACTION = "sts:AssumeRole"

# A wide pool of plausible, non-escalating AWS actions used ONLY to build
# planted near-duplicate roles for the role-mining benchmark. Deliberately
# disjoint from TECHNIQUE/ADMIN/ASSUME and mostly from BENIGN, so a planted
# duplicate pair (which shares ~6 of these) stands out from ordinary
# distractors (which draw from the small BENIGN pool) and cannot be confused
# with a privilege-escalation role.
CONSOLIDATION_ACTIONS: List[str] = [
    "ec2:StartInstances",
    "ec2:StopInstances",
    "rds:DescribeDBInstances",
    "lambda:InvokeFunction",
    "cloudformation:DescribeStacks",
    "secretsmanager:GetSecretValue",
    "ssm:GetParameter",
    "route53:ListHostedZones",
    "elasticloadbalancing:DescribeLoadBalancers",
    "autoscaling:DescribeAutoScalingGroups",
    "cloudtrail:LookupEvents",
    "athena:StartQueryExecution",
    "glue:GetTable",
    "redshift:DescribeClusters",
    "stepfunctions:StartExecution",
    "apigateway:GET",
]

# A common action every planted duplicate role also holds, so the
# role-permission projection stays a single connected component (node2vec's
# separation collapses on disconnected components). It is an ordinary benign
# action, shared with distractors, so it adds no redundancy signal of its own.
CONSOLIDATION_ANCHOR = "s3:GetObject"

# Functional groups for the FUNCTIONAL-similarity benchmark: families of
# related actions such that two roles drawn from the same group "do the same
# job" even when their exact action strings barely overlap. Pools are disjoint
# from every other action list above so group membership is unambiguous.
# A planted functional pair takes two partial samples from one group; the
# schedule below forces some pairs to share few or even ZERO exact actions --
# exactly the case Jaccard-on-permission-sets is structurally blind to.
FUNCTIONAL_GROUPS: Dict[str, List[str]] = {
    "s3_data_access": [
        "s3:ListBucket",
        "s3:GetObjectVersion",
        "s3:GetObjectTagging",
        "s3:PutObjectTagging",
        "s3:GetBucketLocation",
        "s3:ListBucketVersions",
        "s3:GetObjectAcl",
        "s3:RestoreObject",
    ],
    "ec2_operations": [
        "ec2:StartInstancesFleet",
        "ec2:StopInstancesFleet",
        "ec2:RebootInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:CreateTags",
        "ec2:DescribeVolumes",
        "ec2:AttachVolume",
        "ec2:DescribeSnapshots",
    ],
    "observability": [
        "logs:GetLogEvents",
        "logs:FilterLogEvents",
        "logs:DescribeLogGroups",
        "cloudwatch:GetMetricData",
        "cloudwatch:ListMetrics",
        "cloudwatch:DescribeAlarms",
        "xray:GetTraceSummaries",
        "xray:BatchGetTraces",
    ],
    "data_analytics": [
        "athena:StartQueryRun",
        "athena:GetQueryResults",
        "glue:GetTableVersion",
        "glue:GetDatabase",
        "glue:GetPartitions",
        "redshift:GetClusterCredentials",
        "redshift-data:ExecuteStatement",
        "lakeformation:GetDataAccess",
    ],
}

# Exact-overlap schedule for planted functional pairs, cycled per pair: how
# many group actions pair k's two roles share. The 0 entry is the point of the
# benchmark -- a same-function pair with NO shared exact action, invisible to
# any set-overlap metric by construction.
FUNCTIONAL_OVERLAP_CYCLE: Tuple[int, ...] = (2, 1, 0, 1)

# How many actions (from the group pool) each functional role carries, and how
# many cohort roles per group provide the co-occurrence structure.
FUNCTIONAL_ROLE_SIZE = 4
FUNCTIONAL_COHORTS_PER_GROUP = 3

# A plausible-but-unlisted AWS-style escalation action used by the
# novel-technique benchmark. It is deliberately absent from the scorer's
# ASSUME_ACTIONS and PRIVESC_ACTIONS sets, so any method that recognises
# escalation by action-name membership is structurally blind to it. A
# reachability method that follows trust edges must catch it from structure.
NOVEL_ASSUME_ACTION = "iam:SwapRoleCredentials"

DENSITY_PRESETS: Dict[str, Dict[str, int]] = {
    "low": {"distractor_roles": 8, "distractor_users": 15},
    "medium": {"distractor_roles": 25, "distractor_users": 50},
    "high": {"distractor_roles": 60, "distractor_users": 120},
}


def _perm_id(role_id: str, action: str, suffix: str = "") -> str:
    return f"{role_id}::{action}{suffix}"


def _add_permission(graph: nx.DiGraph, role_id: str, action: str,
                    is_sensitive: bool, suffix: str = "") -> str:
    """Create a per-grant permission node and the GRANTS edge from ``role_id``."""
    perm_id = _perm_id(role_id, action, suffix)
    graph.add_node(perm_id, label="Permission", action=action,
                   is_sensitive=is_sensitive)
    graph.add_edge(role_id, perm_id, relation="GRANTS")
    return perm_id


def _add_trust_edge(graph: nx.DiGraph, src: str, dst: str, enabling_perm: str) -> None:
    """Record a role->role assume/trust relationship as graph-level metadata.

    Trust edges are stored on ``graph.graph["trust_edges"]`` rather than as
    DiGraph edges, so RedAgent/BlueAgent and the signature scorer (which only
    traverse HAS_ROLE/GRANTS) see exactly the same graph as before. Only a
    reachability-aware scorer that reads this metadata will materialise the
    role->role edges. Each trust edge names the permission grant that enables
    it, so removing that grant severs the edge -- this is what lets the
    counterfactual attribute escalation risk to the *enabling* permission,
    regardless of that permission's action name.
    """
    graph.graph.setdefault("trust_edges", []).append(
        {"src": src, "dst": dst, "enabling_perm": enabling_perm}
    )


def _plant_chain(graph: nx.DiGraph, chain_index: int, chain_length: int,
                 rng: random.Random, assume_action: str = ASSUME_ACTION) -> PlantedChain:
    """Bury one escalation chain of ``chain_length`` role hops into ``graph``.

    ``assume_action`` is the action granted at each hop to enable assuming the
    next role. The original benchmark uses ``sts:AssumeRole``; the
    novel-technique benchmark passes :data:`NOVEL_ASSUME_ACTION` so the
    escalation is driven by an action absent from any hardcoded privesc list.
    Either way a role->role trust edge (enabled by that hop's assume grant) is
    recorded so a reachability scorer can traverse the chain structurally.
    """
    cid = f"c{chain_index}"
    entry_user = f"u_{cid}_entry"
    graph.add_node(entry_user, label="User", username=entry_user)

    nodes: List[str] = [entry_user]
    edges: List[Edge] = []
    breaking_edges: List[Edge] = []
    risky_perms: List[str] = []
    roles: List[str] = []
    techniques: List[str] = []
    hop_assume: List[Tuple[str, str]] = []  # (role_id, assume_perm) per pivot hop

    # chain_length counts roles: (chain_length - 1) pivot hops + 1 admin sink.
    n_pivots = max(1, chain_length - 1)

    for hop in range(n_pivots):
        role_id = f"r_{cid}_h{hop}"
        graph.add_node(role_id, label="Role", name=role_id, is_overpermissive=True)
        roles.append(role_id)
        nodes.append(role_id)

        # Entry user holds only the first hop; deeper hops are reached by
        # assuming, so they stay "buried" (no direct user ownership).
        if hop == 0:
            graph.add_edge(entry_user, role_id, relation="HAS_ROLE")
            edges.append((entry_user, role_id))
            breaking_edges.append((entry_user, role_id))

        # The escalation technique for this hop.
        action = TECHNIQUE_ACTIONS[hop % len(TECHNIQUE_ACTIONS)]
        techniques.append(action)
        tech_perm = _add_permission(graph, role_id, action, is_sensitive=True)
        risky_perms.append(tech_perm)
        edges.append((role_id, tech_perm))
        breaking_edges.append((role_id, tech_perm))

        # An assume grant so the next hop is reachable (and so the project's
        # RedAgent assume-role inference has something to follow).
        assume_perm = _add_permission(graph, role_id, assume_action,
                                      is_sensitive=True, suffix="__assume")
        risky_perms.append(assume_perm)
        edges.append((role_id, assume_perm))
        breaking_edges.append((role_id, assume_perm))
        hop_assume.append((role_id, assume_perm))

    # Admin sink at the end of the chain.
    admin_role = f"r_{cid}_admin"
    graph.add_node(admin_role, label="Role", name=admin_role, is_overpermissive=True)
    roles.append(admin_role)
    nodes.append(admin_role)
    for action in ADMIN_ACTIONS:
        admin_perm = _add_permission(graph, admin_role, action, is_sensitive=True)
        risky_perms.append(admin_perm)
        # Admin's own grants participate in the chain (not collateral if cut)
        # but do NOT gate reachability, so they are not breaking edges.
        edges.append((admin_role, admin_perm))

    # Record role->role trust edges: hop h can assume hop h+1 (last hop -> admin),
    # each enabled by that hop's assume grant.
    hop_role_ids = [r for r in roles if r != admin_role]
    for i, (src_role, assume_perm) in enumerate(hop_assume):
        dst_role = hop_role_ids[i + 1] if i + 1 < len(hop_role_ids) else admin_role
        _add_trust_edge(graph, src_role, dst_role, assume_perm)

    return PlantedChain(
        chain_id=cid,
        technique_actions=techniques,
        nodes=nodes,
        edges=edges,
        breaking_edges=breaking_edges,
        risky_perms=risky_perms,
        roles=roles,
    )


def _add_distractors(graph: nx.DiGraph, n_roles: int, n_users: int,
                     rng: random.Random) -> Tuple[List[str], Dict[str, List[str]]]:
    """Populate the tenant with benign roles/users.

    Returns ``(distractor_role_ids, role_to_benign_perms)`` where the second
    value maps each distractor role to the benign permission grants on it (used
    to seed realistic benign trust relationships).
    """
    distractor_roles: List[str] = []
    role_benign_perms: Dict[str, List[str]] = {}
    for i in range(n_roles):
        role_id = f"r_d{i}"
        graph.add_node(role_id, label="Role", name=role_id, is_overpermissive=False)
        distractor_roles.append(role_id)
        role_benign_perms[role_id] = []

        n_perms = rng.randint(2, 6)
        for _ in range(n_perms):
            # Mostly benign, occasionally a sensitive-but-not-escalating action.
            if rng.random() < 0.25:
                action = rng.choice(DISTRACTOR_SENSITIVE_ACTIONS)
                sensitive = True
            else:
                action = rng.choice(BENIGN_ACTIONS)
                sensitive = False
            perm_id = _add_permission(graph, role_id, action, is_sensitive=sensitive,
                                      suffix=f"__{rng.randrange(1_000_000)}")
            if not sensitive:
                role_benign_perms[role_id].append(perm_id)

    for i in range(n_users):
        user_id = f"u_d{i}"
        graph.add_node(user_id, label="User", username=user_id)
        if distractor_roles:
            k = rng.randint(1, min(3, len(distractor_roles)))
            for role_id in rng.sample(distractor_roles, k):
                graph.add_edge(user_id, role_id, relation="HAS_ROLE")

    return distractor_roles, role_benign_perms


def _add_benign_trust_edges(graph: nx.DiGraph, distractor_roles: List[str],
                            role_benign_perms: Dict[str, List[str]],
                            rng: random.Random) -> None:
    """Plant benign role->role trust relationships among distractors as noise.

    These model harmless "role A may assume role B" links. They give the
    reachability scorer decoy trust paths that must be followed and found to
    NOT reach a sensitive escalation target -- so it cannot simply treat "has a
    trust edge" as risky. Each benign trust edge is enabled by an existing
    benign permission on the source role (no new nodes, so every other method
    sees an unchanged graph).
    """
    sources = [r for r in distractor_roles if role_benign_perms.get(r)]
    n_edges = len(distractor_roles) // 4
    for _ in range(n_edges):
        if not sources or len(distractor_roles) < 2:
            break
        src = rng.choice(sources)
        dst = rng.choice(distractor_roles)
        if dst == src:
            continue
        enabling_perm = rng.choice(role_benign_perms[src])
        _add_trust_edge(graph, src, dst, enabling_perm)


def _plant_duplicate_roles(graph: nx.DiGraph, n_pairs: int,
                           rng: random.Random) -> List[Tuple[str, str]]:
    """Bury ``n_pairs`` deliberately near-duplicate benign role pairs.

    Each pair is a base role and a partner that grants the *same* action set
    with 1-2 edits (one removal and/or one addition), i.e. Jaccard >= ~0.75 --
    the textbook "these two roles are redundant, merge them" signal that real
    role mining exists to find. Both roles also hold :data:`CONSOLIDATION_ANCHOR`
    so the role-permission graph stays connected. Each gets a holder user so it
    is not a structurally isolated pair. Returns the list of planted
    ``(base_role, partner_role)`` pairs (role-mining ground truth).
    """
    pairs: List[Tuple[str, str]] = []
    for k in range(n_pairs):
        core = set(rng.sample(CONSOLIDATION_ACTIONS, 6))
        base_actions = core | {CONSOLIDATION_ANCHOR}

        # Partner: drop one core action, add a different one -> 1-2 grant delta.
        partner_actions = set(base_actions)
        drop = rng.choice(sorted(core))
        partner_actions.discard(drop)
        remaining = [a for a in CONSOLIDATION_ACTIONS if a not in partner_actions]
        if remaining:
            partner_actions.add(rng.choice(sorted(remaining)))

        base_id = f"r_dup{k}_a"
        partner_id = f"r_dup{k}_b"
        for role_id, actions in ((base_id, base_actions), (partner_id, partner_actions)):
            graph.add_node(role_id, label="Role", name=role_id,
                           is_overpermissive=False, is_planted_duplicate=True)
            for action in sorted(actions):
                _add_permission(graph, role_id, action, is_sensitive=False,
                                suffix=f"__{rng.randrange(1_000_000)}")
            holder = f"u_dup{k}_{role_id[-1]}"
            graph.add_node(holder, label="User", username=holder)
            graph.add_edge(holder, role_id, relation="HAS_ROLE")

        pairs.append((base_id, partner_id))
    return pairs


def _plant_functional_pairs(
    graph: nx.DiGraph, n_pairs: int, rng: random.Random,
) -> Tuple[List[Tuple[str, str]], List[str]]:
    """Bury ``n_pairs`` functionally-similar role pairs plus group cohorts.

    Generator design (stated explicitly so the benchmark is auditable):

    * Pair k draws from functional group ``k % len(FUNCTIONAL_GROUPS)``. Both
      roles take :data:`FUNCTIONAL_ROLE_SIZE` actions from that group's pool:
      ``FUNCTIONAL_OVERLAP_CYCLE[k % 4]`` shared actions, the rest disjoint.
      The cycle includes 0 -- a same-function pair with **no** shared exact
      action, which no set-overlap metric can pair with its partner even in
      principle (both roles then share only the connectivity anchor, exactly
      like an unrelated cross-group pair).
    * Every functional role also holds :data:`CONSOLIDATION_ANCHOR` so the
      role-permission projection stays one connected component.
    * Each group used gets :data:`FUNCTIONAL_COHORTS_PER_GROUP` cohort roles
      (random group samples). Cohorts are the co-occurrence structure that
      makes a functional group a *group* in the graph -- without them, a
      zero-overlap pair is structurally disconnected inside its group and NO
      method could pair it. They are scaffolding, recorded separately and
      excluded from the benchmark's pair universe.

    Returns ``(pairs, cohort_role_ids)``.
    """
    pairs: List[Tuple[str, str]] = []
    cohorts: List[str] = []
    group_names = sorted(FUNCTIONAL_GROUPS)
    groups_used: List[str] = []

    def add_functional_role(role_id: str, actions: set, group: str,
                            is_cohort: bool) -> None:
        graph.add_node(role_id, label="Role", name=role_id,
                       is_overpermissive=False, functional_group=group,
                       is_planted_functional=not is_cohort,
                       is_functional_cohort=is_cohort)
        for action in sorted(actions | {CONSOLIDATION_ANCHOR}):
            _add_permission(graph, role_id, action, is_sensitive=False,
                            suffix=f"__{rng.randrange(1_000_000)}")
        holder = f"u_{role_id}"
        graph.add_node(holder, label="User", username=holder)
        graph.add_edge(holder, role_id, relation="HAS_ROLE")

    for k in range(n_pairs):
        group = group_names[k % len(group_names)]
        pool = FUNCTIONAL_GROUPS[group]
        overlap = FUNCTIONAL_OVERLAP_CYCLE[k % len(FUNCTIONAL_OVERLAP_CYCLE)]

        shared = rng.sample(sorted(pool), overlap)
        rest = [a for a in pool if a not in shared]
        rng.shuffle(rest)
        n_private = FUNCTIONAL_ROLE_SIZE - overlap
        a_actions = set(shared) | set(rest[:n_private])
        b_actions = set(shared) | set(rest[n_private:2 * n_private])

        role_a, role_b = f"r_fn{k}_a", f"r_fn{k}_b"
        add_functional_role(role_a, a_actions, group, is_cohort=False)
        add_functional_role(role_b, b_actions, group, is_cohort=False)
        pairs.append((role_a, role_b))

        if group not in groups_used:
            groups_used.append(group)
            for c in range(FUNCTIONAL_COHORTS_PER_GROUP):
                cohort_id = f"r_fnco_{group}_{c}"
                cohort_actions = set(rng.sample(sorted(pool), FUNCTIONAL_ROLE_SIZE))
                add_functional_role(cohort_id, cohort_actions, group, is_cohort=True)
                cohorts.append(cohort_id)

    return pairs, cohorts


def generate_tenant(seed: int, chain_length: int = 3, density: str = "low",
                    n_chains: int = 3, novel_technique: bool = False,
                    n_duplicate_pairs: int = 0,
                    n_functional_pairs: int = 0) -> Tenant:
    """Deterministically build a tenant with ``n_chains`` planted escalations.

    Args:
        seed: RNG seed; identical (seed, params) always yield an identical graph.
        chain_length: Number of role hops per chain (2..5 recommended).
        density: One of ``"low"``, ``"medium"``, ``"high"`` (distractor volume).
        n_chains: How many independent escalation chains to plant.
        novel_technique: If True, chains escalate via :data:`NOVEL_ASSUME_ACTION`
            (absent from every hardcoded privesc list) instead of
            ``sts:AssumeRole``. The trust-edge structure is identical, so a
            reachability scorer still traverses the chain while a signature
            scorer goes blind.
        n_duplicate_pairs: How many deliberately near-duplicate benign role
            pairs to plant (role-mining ground truth). Defaults to 0, in which
            case generation is byte-identical to before this feature: the
            duplicate roles are added last, and only when this is > 0, so the
            privesc benchmark is unaffected.
        n_functional_pairs: How many functionally-similar role pairs to plant
            (same functional group, partial -- sometimes zero -- exact overlap;
            see :func:`_plant_functional_pairs` for the auditable design).
            Defaults to 0 and is likewise added last, so existing benchmarks
            stay byte-identical.

    Returns:
        A :class:`~eval.tenant.Tenant` carrying the graph and ground truth. The
        graph carries role->role trust relationships on
        ``graph.graph["trust_edges"]`` (see :func:`_add_trust_edge`). If
        ``n_duplicate_pairs > 0`` the tenant's ``duplicate_role_pairs`` records
        the planted near-duplicate role pairs.
    """
    if density not in DENSITY_PRESETS:
        raise ValueError(
            f"density must be one of {sorted(DENSITY_PRESETS)}, got {density!r}"
        )
    if chain_length < 2:
        raise ValueError("chain_length must be >= 2")

    rng = random.Random(seed)
    graph = nx.DiGraph()
    graph.graph["trust_edges"] = []

    assume_action = NOVEL_ASSUME_ACTION if novel_technique else ASSUME_ACTION

    chains: List[PlantedChain] = []
    for ci in range(n_chains):
        chains.append(_plant_chain(graph, ci, chain_length, rng, assume_action))

    preset = DENSITY_PRESETS[density]
    distractor_roles, role_benign_perms = _add_distractors(
        graph, preset["distractor_roles"], preset["distractor_users"], rng
    )

    # Sprinkle each chain's entry user into the benign population so the
    # escalation entry points are not trivially isolated. (Done before benign
    # trust edges so the DiGraph is identical to the pre-trust-edge generator;
    # trust edges are additive metadata only.)
    for chain in chains:
        entry_user = chain.nodes[0]
        if distractor_roles:
            role_id = rng.choice(distractor_roles)
            if not graph.has_edge(entry_user, role_id):
                graph.add_edge(entry_user, role_id, relation="HAS_ROLE")

    _add_benign_trust_edges(graph, distractor_roles, role_benign_perms, rng)

    # Role-mining ground truth. Added LAST and only when requested, so a tenant
    # with n_duplicate_pairs=0 / n_functional_pairs=0 is byte-identical to the
    # pre-feature generator.
    duplicate_pairs: List[Tuple[str, str]] = []
    if n_duplicate_pairs > 0:
        duplicate_pairs = _plant_duplicate_roles(graph, n_duplicate_pairs, rng)

    functional_pairs: List[Tuple[str, str]] = []
    functional_cohorts: List[str] = []
    if n_functional_pairs > 0:
        functional_pairs, functional_cohorts = _plant_functional_pairs(
            graph, n_functional_pairs, rng)

    suffix = "_novel" if novel_technique else ""
    if n_duplicate_pairs > 0:
        suffix += f"_dup{n_duplicate_pairs}"
    if n_functional_pairs > 0:
        suffix += f"_fn{n_functional_pairs}"
    tenant_id = f"seed{seed}_len{chain_length}_{density}_n{n_chains}{suffix}"
    return Tenant(tenant_id=tenant_id, graph=graph, chains=chains,
                  duplicate_role_pairs=duplicate_pairs,
                  functional_role_pairs=functional_pairs,
                  functional_cohort_roles=functional_cohorts)
