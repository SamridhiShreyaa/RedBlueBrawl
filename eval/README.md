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

## Role-mining benchmark

A separate harness (`eval/role_mining_eval.py`) grades the *other* README claim — "role
mining using graph algorithms" — rather than privesc detection. It plants deliberately
**near-duplicate role pairs** (same permission set ± 1-2 grants, via
`generate_tenant(..., n_duplicate_pairs=k)`) and measures whether each method recovers those
exact pairs.

```bash
python eval/role_mining_eval.py                 # 5 seeds x {low,medium}, 4 planted pairs each
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

**Scoring universe.** Planted escalation chains create structurally-identical roles across
chains (a different experiment), so scoring is restricted to **non-chain** roles
(`Tenant.chain_roles`); tenants are generated with `n_chains=1` so there is no cross-chain
duplication to begin with.

**Headline result** (mean over the grid, `results/role_mining_summary.csv`):

| method   | precision | recall |   f1   |
| -------- | :-------: | :----: | :----: |
| jaccard  |   0.800   | 1.000  | **0.877** |
| node2vec |   0.473   | 0.875  |   0.594   |
| count    |   0.086   | 1.000  |   0.157   |

**The honest finding — node2vec does not beat Jaccard here.** node2vec is *real* role mining
and crushes the count threshold (0.59 vs 0.16 F1), which is what the README's "graph
algorithms" phrasing actually needed. But the simple Jaccard-on-permission-sets baseline
(0.88) clearly beats it. node2vec's clustering **over-merges** structurally-similar-but-
distinct roles, so its precision (0.47) trails Jaccard's (0.80); a threshold sweep confirms
its best-case F1 (~0.57 at cosine distance 0.15) still loses to Jaccard's (~0.88 at Jaccard
distance 0.30). Where an embedding *would* earn its keep is fuzzy / transitive similarity
(roles that are redundant without sharing exact action strings) — but that is not the exact-
overlap case this benchmark measures, and reporting node2vec as a win here would mean
choosing a weaker baseline on purpose. Both real methods are shipped so the pipeline can use
whichever fits; for exact near-duplicate detection, `jaccard` is the recommendation.
