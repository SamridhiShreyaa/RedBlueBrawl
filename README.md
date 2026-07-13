# 
# Self-Healing IAM Role Mining using Graph Analysis

## Overview

This project builds an intelligent **Identity and Access Management (IAM) analysis system** that detects and fixes risky access permissions automatically.
By modeling IAM relationships as a **graph**, the system identifies anomalies, excessive permissions, and potential security risks.

The platform also includes a **self-healing component** that can recommend or automatically apply safer permission configurations.

## Problem

Organizations often face:

* **Over-permissioned IAM roles**
* **Unused or risky access privileges**
* **Manual and slow permission audits**

These issues increase the risk of **security breaches and privilege escalation**.

## Solution

Our system:

1. Converts IAM data into a **graph structure**
2. Uses **graph analysis and role mining** to detect abnormal access patterns
3. Identifies **least-privilege violations**
4. Provides **self-healing recommendations** to fix permissions automatically

## Key Features

* IAM relationship graph modeling
* **Role mining** — near-duplicate/redundant roles are found by clustering
  roles on **Jaccard similarity of their permission sets** (average-linkage
  agglomerative clustering), then surfacing consolidation suggestions
  (`src/graph/role_mining.py`). A node2vec embedding variant was built,
  benchmarked head-to-head on planted ground truth, and **dropped after never
  beating this simpler method** — see *Role mining* below and `eval/` for both
  benchmarks (exact duplicates and functional similarity).
* Detection of excessive privileges
* **Counterfactual attack-path risk scoring** — permissions are ranked by how many
  reachable privilege-escalation routes their removal would break (`do(grant = removed)`,
  computed as deterministic graph recomputation, not a probabilistic causal model). Two
  scorers: a signature-gated baseline, and a **structural-reachability scorer**
  (`ReachabilityRiskScorer`, recommended) that follows real role→role trust edges to
  sensitive targets and so generalises to escalation techniques whose action names appear
  in no hardcoded list (see `eval/` for the novel-technique generalization benchmark)
* Self-healing permission recommendations
* Visual role-access insights

## Tech Stack

* **Python**
* **Neo4j / NetworkX** for graph modeling
* **Pandas** for data processing
* **Scikit-learn / Graph algorithms** for role mining
* **Streamlit or Flask** for visualization dashboard

## Local Setup

**1. Configure connection settings.** Copy the example env file and adjust if needed:

```bash
cp .env.example .env
```

All Neo4j connection settings live in one place (`src/config.py`) and are read
from these environment variables (defaults shown):

| Variable              | Default                  | Purpose                              |
| --------------------- | ------------------------ | ------------------------------------ |
| `NEO4J_URI`           | `bolt://localhost:7687`  | Bolt endpoint                        |
| `NEO4J_USER`          | `neo4j`                  | Username                             |
| `NEO4J_PASSWORD`      | `changeme`               | Password                             |
| `RISK_SCORER_METHOD`  | `signature`              | Which risk scorer the pipeline uses  |

### Choosing the risk scorer

The pipeline builds its scorer through `make_risk_scorer(graph)`, which reads
`RISK_SCORER_METHOD` (via `src/config.py`):

* **`signature`** (default) — `SignatureCounterfactualScorer`. Identifies
  escalation by action-name membership in hardcoded lists. Works on any graph,
  including the current synthetic Neo4j dataset, which exposes only action names.
* **`reachability`** — `ReachabilityRiskScorer`. Follows real role→role **trust
  edges** to structurally-sensitive targets, so it generalises to escalation
  techniques whose action names are in no list (see `eval/` for the
  novel-technique benchmark). It **requires trust-edge data** on the graph; if
  you select it on a graph without any, `make_risk_scorer` raises immediately
  with a clear message rather than silently returning all-zero scores.

The default stays `signature` today because the synthetic Neo4j dataset carries
no trust/AssumeRolePolicy structure. **Reachability becomes the recommended
default once real IAM ingestion with trust-policy data lands (Feature 9)** — at
that point it is a one-line config change (`RISK_SCORER_METHOD=reachability`),
not a re-architecture.

### Role mining (finding redundant roles)

`src/graph/role_mining.py` implements the actual role-mining technique from the
literature: cluster roles by the **set of permissions they grant** and surface
groups whose sets overlap enough to merge. (The legacy
`queries.get_high_privilege_roles` only thresholds a role's permission *count* —
it says nothing about which roles are redundant with each other.)

```python
from src.graph.role_mining import consolidation_suggestions, find_near_duplicate_roles

# roles whose permission sets overlap enough to merge, most-redundant first
for s in consolidation_suggestions(graph):
    print(s.roles, "shared:", s.shared_actions, "tightness:", s.mean_jaccard)

pairs = find_near_duplicate_roles(graph)                    # exact near-duplicates
loose = find_near_duplicate_roles(graph, distance_threshold=0.80)  # + functional similarity
```

The method is **Jaccard clustering**: average-linkage agglomerative clustering
on Jaccard distance of role permission sets. The legacy `count` threshold is
kept as a baseline. A **node2vec** embedding variant was implemented and
benchmarked honestly against tenants with planted ground truth
(`python eval/role_mining_eval.py`) on two benchmarks — **exact** duplicates
(same set ± 1-2 grants) and **functional** similarity (same-job roles with
partial or *zero* exact overlap, built specifically to showcase an embedding's
edge).

**Honest result (mean over the benchmark grid, both benchmarks; node2vec rows
recorded before it was dropped):**

| benchmark  | method   | precision | recall |   f1   |
| ---------- | -------- | :-------: | :----: | :----: |
| exact      | jaccard  |   0.80    |  1.00  | **0.88** |
| exact      | node2vec |   0.50    |  0.90  |   0.62   |
| exact      | count    |   0.09    |  1.00  |   0.16   |
| functional | jaccard  |   1.00    |  1.00  | **1.00** |
| functional | node2vec |   1.00    |  1.00  | **1.00** |
| functional | count    |   0.14    |  1.00  |   0.25   |

node2vec **lost the exact benchmark** (over-merging costs precision) and only
**tied the functional one**: agglomerative clustering lets plain Jaccard reach
zero-overlap pairs *transitively* through group cohorts — the same
co-occurrence signal node2vec's random walks exploit. With no benchmark where
the embedding wins, it was **dropped along with its dependency**; the full
implementation and reproducible comparison live at evidence commit `25a2c2c`.
Full analysis: [`eval/README.md`](eval/README.md#role-mining-benchmarks).

**2. Start Neo4j with one command:**

```bash
docker compose up -d
```

This launches Neo4j on Bolt (`7687`) and the browser UI (`7474`) using the
credentials above, with a healthcheck and a named volume for persistence. Stop
it with `docker compose down` (add `-v` to also wipe the data volume).

**3. Install dependencies and load the sample data:**

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt   # test tooling (pytest, pytest-cov)
python scripts/run_graph.py           # loads data/iam_dataset.json into Neo4j
```

**4. Run the tests:**

```bash
pytest tests/
```

Graph-backed tests connect to Neo4j and seed the sample dataset automatically;
they skip cleanly if no database is reachable. CI (`.github/workflows/ci.yml`)
runs the full suite against a Neo4j service container on every push and PR.

## Workflow

1. Load IAM dataset
2. Build access relationship graph
3. Run role mining algorithms
4. Detect anomalies and risky permissions
5. Generate self-healing recommendations

## Use Cases

* Enterprise IAM auditing
* Least privilege enforcement
* Security compliance monitoring
* Automated IAM governance

## Future Improvements

* Real-time IAM monitoring
* Machine learning based anomaly detection
* Integration with cloud IAM systems (AWS, Azure, GCP)

## Authors

Hackathon Team – IAM Security Project
