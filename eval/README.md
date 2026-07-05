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
   - `HeuristicMethod` — the project pipeline (RedAgent + BlueAgent + CausalRiskScorer).
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

The heuristic breaks **100%** of planted paths (BlueAgent reliably cuts the
assume-role edge) but has **low detection F1** that *falls as chains get longer*
and precision that *falls as distractor density rises* — its hardcoded risk
baseline misses techniques like `iam:CreatePolicyVersion` and over-flags merely
destructive permissions. The budget-matched random baseline breaks far fewer
paths (~38%), confirming the heuristic's remediation targeting beats chance even
where its labeling is weak. This gap is the harness's headline finding and the
motivation for a learned detector/remediator.
