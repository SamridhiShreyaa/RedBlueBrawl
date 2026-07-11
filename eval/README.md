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
