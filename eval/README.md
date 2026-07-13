# Evaluation Harness

Measures how well RedBlueBrawl actually **detects** risky permissions and
**remediates** privilege-escalation paths, against tenants where the ground
truth is known because we planted it.

## How it works

1. **`tenant_gen.py`** deterministically builds a synthetic IAM graph and buries
   `n_chains` named AWS escalation chains (e.g. `iam:CreatePolicyVersion` →
   `iam:AttachRolePolicy` → admin) among benign distractor roles/users. For each
   chain it records, as ground truth:
   - the permission nodes on the chain (risky positives), and
   - the exact edges whose removal breaks the escalation route.

   Every permission grant is its own node, so a permission is risky *iff* it sits
   on a planted chain. Distractors carry some sensitive-but-not-escalating actions
   (`s3:DeleteObject`, `kms:Decrypt`, …) on purpose — "sensitive" ≠ "exploitable".

2. **`methods.py`** runs each method on the graph and returns which permissions it
   flags and which edges/nodes its remediation removes:
   - `HeuristicMethod` — the legacy weighted-sum scorer (`HeuristicRiskScorer`) for
     detection, RedAgent + BlueAgent for remediation. The baseline.
   - `SignatureCounterfactualMethod` — counterfactual detection, but pivots/targets are
     identified by action-name membership in hardcoded `ASSUME_ACTIONS` / `PRIVESC_ACTIONS`
     sets (`SignatureCounterfactualScorer`).
   - `ReachabilityMethod` — counterfactual detection driven by **real trust-edge
     reachability** to structurally-defined sensitive targets (`ReachabilityRiskScorer`).
     No action-name lists, so it generalises to escalation techniques whose action strings
     are in no list.
   - `RandomMethod` — uniform random, given the heuristic's **matched budget** so the
     comparison is about targeting quality, not how much each method is allowed to cut.

   The three non-random methods share RedAgent+BlueAgent remediation, so their path-break
   columns are identical by construction and every detection difference is the scorer.

3. **`metrics.py`** scores each run against ground truth:
   - `precision` / `recall` / `f1` / `fpr` on risky-permission detection,
   - `pct_paths_broken` — % of planted chains severed after remediation,
   - `benign_edges_cut` — edges removed that belong to no planted chain (collateral).

## Two benchmarks

The harness runs every method on **both**:

- **original** — chains escalate via `sts:AssumeRole` (an action in the signature lists).
- **novel** — chains escalate via `iam:SwapRoleCredentials`, an invented AWS-style action
  **deliberately absent from both `ASSUME_ACTIONS` and `PRIVESC_ACTIONS`**. The trust-edge
  *structure* is identical; only the action name differs. This is the generalization test:
  can a scorer catch an escalation whose name it has never seen?

Every tenant also carries explicit role→role **trust edges** on `graph.graph["trust_edges"]`
(who may assume whom, and which permission grant enables it), plus benign decoy trust edges
among distractors. These are metadata only — RedAgent/BlueAgent and the signature scorer see
an unchanged graph; only the reachability scorer traverses them.

## Running

```bash
python eval/run_eval.py            # both benchmarks, full grid
python eval/run_eval.py --quick    # fast sanity grid
```

Outputs to `eval/results/`: `raw_results.csv` (one row per method×tenant×benchmark),
`summary.csv` (per benchmark×length×density), `summary_by_method.csv` (headline table),
and `comparison.png` (F1 by method, one panel per benchmark).

## Reading the committed results

Headline table (mean over the full grid, `summary_by_method.csv`):

| benchmark | method          | precision | recall |   f1   |  fpr  | pct_paths_broken |
| --------- | --------------- | :-------: | :----: | :----: | :---: | :--------------: |
| original  | signature_cf    |   1.000   | 1.000  | 1.000  | 0.000 |      100.0       |
| original  | reachability_cf |   0.778   | 0.905  | 0.825  | 0.065 |      100.0       |
| original  | heuristic       |   0.166   | 0.095  | 0.106  | 0.220 |      100.0       |
| original  | random          |   0.223   | 0.141  | 0.149  | 0.203 |       37.8       |
| **novel** | **signature_cf**    | **1.000** | **0.095** | **0.173** | 0.000 | 0.0 |
| **novel** | **reachability_cf** | **0.778** | **0.905** | **0.825** | 0.065 | 0.0 |
| novel     | heuristic       |   0.000   | 0.000  | 0.000  | 0.220 |       0.0        |
| novel     | random          |   0.217   | 0.118  | 0.126  | 0.172 |       0.0        |

**The headline finding.** `signature_cf` scores a perfect **1.0** on the original benchmark
but **collapses to F1 0.17 (recall 0.095)** on the novel one — it is structurally blind to
an escalation action it does not recognise by name. `reachability_cf` scores **0.825 on
*both* benchmarks, identically**, because it never inspects an action string: it follows
trust edges to sensitive targets and scores permissions by counterfactual route-breaking.
Same structure, different name → same answer. That is the generalization the signature
approach cannot give.

**Honest trade-off — reported, not hidden.** On the *original* benchmark reachability
(0.825) scores **lower** than the signature scorer (1.0). Two reasons, both real: (a) it
excludes directly-held escalation perms on the entry role that are never reached *via* an
assume hop (escalation semantics = "you had to assume into something"), costing ~one
technique perm per chain in recall (0.905); (b) benign decoy trust edges occasionally reach
a sensitive distractor perm, costing precision (0.778). The point of this feature is
generalization, not topping the original leaderboard — and reachability is the only method
that does not fall apart when the technique is unnamed.

**Why the original signature 1.0 was misleading.** It matched two hardcoded lists — the
scorer's `PRIVESC_ACTIONS` and the generator's technique vocabulary — that overlap because
both draw from the same real-world privesc catalogue. The novel benchmark removes that
overlap, and the 1.0 immediately becomes 0.17.

**A note on remediation.** On the novel benchmark **every** method breaks **0%** of paths.
That is not a detection failure — it is because RedAgent/BlueAgent *also* recognise pivots
by `sts:AssumeRole`, so the remediation layer has the very same signature blind spot. Making
remediation reachability-driven is the natural follow-up; this feature fixes detection.

## Which scorer runs in production

The eval methods construct their scorers directly (that is the whole point — to compare
them). The **pipeline** instead selects one through `make_risk_scorer(graph)`, driven by the
`RISK_SCORER_METHOD` env var (`signature` default, `reachability` opt-in — see the main
README). Reachability requires trust-edge data and fails loudly without it. It becomes the
recommended default once real IAM ingestion with trust-policy data lands (Feature 9): a
config change, not a re-architecture, precisely because this eval already shows it
generalises where the signature scorer does not.

## Role-mining benchmarks

A separate harness (`eval/role_mining_eval.py`) grades the *other* README claim — "role
mining using graph algorithms" — on **two** pair-level benchmarks with planted ground truth:

- **exact** — near-duplicate pairs (same permission set ± 1-2 grants, via
  `generate_tenant(..., n_duplicate_pairs=k)`). Measures exact redundancy.
- **functional** — same-job pairs drawn from one **functional group** (e.g. two "S3
  data-access" roles) whose exact action overlap is partial and, for some pairs, **zero**
  (`n_functional_pairs=k`). Measures whether a method can pair roles that do the same job
  via related-but-not-identical permissions — the case a set-overlap metric cannot see
  *directly* by construction.

```bash
python eval/role_mining_eval.py                 # both benchmarks, 5 seeds x {low,medium}
```

Three methods are compared at the **pair level** (`src/graph/role_mining.py`):

- **`node2vec`** — embed each role over a role-permission **bipartite projection** (grants
  collapsed to their action, so two roles granting the same actions become adjacent through
  shared action nodes; per-grant nodes in the raw graph are role-scoped and would look
  unrelated), then cluster the embeddings. This is the graph-algorithm the README promised.
- **`jaccard`** — cluster roles on exact Jaccard overlap of their permission sets. The
  strong, obvious baseline node2vec must actually beat to earn its keep.
- **`count`** — the legacy permission-count threshold (`queries.get_high_privilege_roles`).
  It pairs any two big roles regardless of overlap; a floor, not a competitor.

### Functional generator design (auditable, defined on its own terms)

Four disjoint functional groups of 8 related actions each (`FUNCTIONAL_GROUPS` in
`tenant_gen.py`: s3 data access, ec2 operations, observability, data analytics). Pair *k*
takes two 4-action samples from one group with an exact-overlap schedule of **2, 1, 0, 1**
shared actions — the 0 is the point: a same-function pair with no shared exact action, which
no set-overlap metric can pair with its partner *directly* (both roles then share only the
connectivity anchor, exactly like an unrelated cross-group pair). Each group also gets 3
**cohort roles** (random group samples): the co-occurrence structure that makes a group a
group in the graph — without them a zero-overlap pair is informationally invisible to *any*
method. Cohorts are scaffolding, recorded separately, excluded from scoring.

**Scoring universes** (applied identically to every method): exact scores over non-chain
roles; functional scores over the **planted functional-pair roles** — the question is
discrimination (match your same-function partner, refuse cross-function roles). Cohort pairs
are excluded because pairing a role with its group's cohort is functionally correct but
unplanted; distractor–distractor pairs are excluded because the small benign action pool
makes random distractors *genuine* exact near-duplicates, which the exact benchmark already
measures.

**Operating points**: functional pairs sit in a looser similarity band (cosine ~0.45–0.75)
than exact duplicates (~0.85+), so each method got its own **symmetrically swept** threshold
per benchmark (best mean F1, same procedure for both): node2vec cosine distance 0.15 exact /
0.50 functional; jaccard distance 0.30 exact / 0.80 functional. Sweep tables are in
`src/graph/role_mining.py` comments.

### Headline result — both benchmarks side by side

Mean over the grid (`results/role_mining_summary.csv`):

| benchmark  | method   | precision | recall |   f1   |
| ---------- | -------- | :-------: | :----: | :----: |
| exact      | jaccard  |   0.800   | 1.000  | **0.877** |
| exact      | node2vec |   0.495   | 0.900  |   0.619   |
| exact      | count    |   0.086   | 1.000  |   0.157   |
| functional | jaccard  |   1.000   | 1.000  | **1.000** |
| functional | node2vec |   1.000   | 1.000  | **1.000** |
| functional | count    |   0.143   | 1.000  |   0.250   |

**Exact: Jaccard wins clearly** (0.877 vs 0.619 — node2vec over-merges
structurally-similar-but-distinct roles, costing precision).

**Functional: a tie, not the expected node2vec win.** The hypothesis was that Jaccard,
blind to zero-exact-overlap pairs, would cede recall to node2vec here. The benchmark
falsified it: **average-linkage clustering reaches zero-overlap pairs *transitively*** —
both roles overlap their group's cohort roles, and the clustering merges the pair through
those bridges. That is the same co-occurrence channel node2vec's random walks exploit, so
given shared clustering machinery, plain Jaccard extracts the same signal. Both methods are
perfect across the full grid (verified through high density and across their threshold
bands: jaccard holds F1 1.0 for distance 0.75–0.85, node2vec for 0.40–0.55).

**Verdict — node2vec is not earning its dependency.** It *loses* exact (0.62 vs 0.88) and
only *ties* functional; there is no benchmark where the embedding beats
Jaccard-plus-clustering. Per the pre-registered decision rule ("if node2vec doesn't beat
Jaccard even on functional similarity, drop it"), node2vec is dropped in the commit after
the one that lands this evidence — check out that evidence commit to reproduce the node2vec
rows in the committed CSVs.
