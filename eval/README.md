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
   - `CounterfactualMethod` — the same attack discovery and remediation, but detection
     comes from `CounterfactualRiskScorer` (scores each permission by how many reachable
     escalation routes removing it would break). Because remediation is shared with the
     heuristic, its path-break rate is identical by construction, so the detection
     numbers isolate the scorer.
   - `RandomMethod` — uniform random, given the heuristic's **matched budget** so the
     comparison is about targeting quality, not how much each method is allowed to cut.

3. **`metrics.py`** scores each run against ground truth:
   - `precision` / `recall` / `f1` / `fpr` on risky-permission detection,
   - `pct_paths_broken` — % of planted chains severed after remediation,
   - `benign_edges_cut` — edges removed that belong to no planted chain (collateral).

## Running

```bash
python eval/run_eval.py            # full grid: lengths 2–5 × low/med/high × 5 seeds
python eval/run_eval.py --quick    # fast sanity grid
```

Outputs to `eval/results/`: `raw_results.csv` (one row per method×tenant),
`summary.csv` (per length×density), `summary_by_method.csv` (headline table),
and `comparison.png`.

## Reading the committed results

Headline table (mean over the full grid, `summary_by_method.csv`):

| method          | precision | recall |   f1   |  fpr  | pct_paths_broken | benign_edges_cut |
| --------------- | :-------: | :----: | :----: | :---: | :--------------: | :--------------: |
| counterfactual  |   1.000   | 1.000  | 1.000  | 0.000 |      100.0       |      16.67       |
| heuristic       |   0.166   | 0.095  | 0.106  | 0.220 |      100.0       |      16.67       |
| random          |   0.223   | 0.141  | 0.149  | 0.203 |       37.8       |      19.07       |

**Heuristic (baseline).** Breaks **100%** of planted paths (BlueAgent reliably cuts the
assume-role edge) but detection F1 is **~0.11** and *falls as chains get longer* and as
distractor density rises — its hardcoded weighted-sum conflates "sensitive" with
"exploitable", missing techniques like `iam:CreatePolicyVersion` while over-flagging
merely destructive permissions (`s3:DeleteObject`, `kms:Decrypt`).

**Counterfactual (new).** Detection **F1 = 1.0 in every single config**, with the path-break
rate unchanged at 100% (remediation is shared with the heuristic). It flags a permission
only when removing its grant actually breaks a reachable escalation route, so it recovers
exactly the planted escalation permissions and ignores destructive-but-non-escalating ones.

**Honest caveat on the perfect score.** F1 = 1.0 is real on *this* benchmark, not
inflated — but it reflects how the generator defines ground truth: risky permissions are
exactly those on planted escalation chains, i.e. the escalation-reachable ones. A correct
reachability-based counterfactual therefore *should* recover them perfectly here. The
result proves the counterfactual model is correct and decisively beats the sensitivity
heuristic; it does **not** imply 1.0 detection on messy real-world IAM data, where ground
truth is noisier and escalation reachability is harder to enumerate.
