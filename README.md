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
* Self-healing permission recommendations
* Visual role-access insights

## Tech Stack

* **Python**
* **Neo4j / NetworkX** for graph modeling
* **Pandas** for data processing
* **Scikit-learn / Graph algorithms** for role mining
* **Streamlit or Flask** for visualization dashboard

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
