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
* Role mining using graph algorithms
* Detection of excessive privileges
* **Counterfactual attack-path risk scoring** — permissions are ranked by how many
  reachable privilege-escalation routes their removal would break (`do(grant = removed)`,
  computed as deterministic graph recomputation, not a probabilistic causal model)
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

| Variable         | Default                  | Purpose                     |
| ---------------- | ------------------------ | --------------------------- |
| `NEO4J_URI`      | `bolt://localhost:7687`  | Bolt endpoint               |
| `NEO4J_USER`     | `neo4j`                  | Username                    |
| `NEO4J_PASSWORD` | `changeme`               | Password                    |

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
