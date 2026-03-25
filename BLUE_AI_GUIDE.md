# Blue AI + Causal Risk Scorer - Implementation Guide

## Overview

You (Person C) have successfully implemented the **Blue AI Defense Engine** and **Causal Risk Attribution System** for the Red vs Blue Brawl project. This document explains what you've built and how it integrates with the existing Red AI system.

## What You've Implemented

### 1. Blue AI Defense Engine (`src/adversarial/blue_agent.py`)

The Blue AI is an intelligent defensive optimizer that:

**Analyzes attack paths** discovered by Red AI and generates strategic defensive actions to harden the IAM system.

#### Key Classes:
- **`BlueAgent`** - Main defensive orchestrator
- **`DefenseAction`** - Individual security-hardening actions
- **`DefenseStrategy`** - Collection of coordinated defensive actions

#### Main Functions:

```python
# Generate defensive strategy based on attack paths
strategy = blue.generate_defenses(attack_paths)

# Apply defenses to the IAM graph
hardened_graph, applied_count = blue.apply_defenses(strategy)

# Compute before/after security metrics
metrics = blue.compute_metrics()

# Get human-readable defense report
report = blue.get_defense_report()
```

#### Defense Actions Supported:

| Action Type | Purpose | Example |
|-------------|---------|---------|
| `REMOVE_PERMISSION` | Remove risky permission from a role | Remove `iam:PassRole` from overpermissive role |
| `REVOKE_ROLE` | Revoke a role from specific users | Revoke admin role from contractor account |
| `SPLIT_ROLE` | Break overpermissive role into smaller roles | Split admin role into read-only + admin roles |

#### How It Works:

1. **Analyzes attack paths** to identify:
   - High-risk permissions used in attacks
   - Overpermissive roles that enable escalation
   - Users with unnecessary access

2. **Generates defensive strategies** that:
   - Remove sensitive permissions from risky roles
   - Split overly permissive roles into restricted variants
   - Revoke unnecessary role assignments

3. **Applies defenses** while:
   - Preserving legitimate business access
   - Minimizing operational impact
   - Tracking all changes for audit

### 2. Causal Risk Scorer (`src/causal/risk_scorer.py`)

Uses structural causal analysis to determine **which specific permissions directly increase security risk**.

#### Key Classes:
- **`CausalRiskScorer`** - Main risk analysis engine
- **`PermissionRiskScore`** - Risk attribution for a single permission
- **`RiskLevel`** - Enum: CRITICAL | HIGH | MEDIUM | LOW

#### Main Functions:

```python
# Score a single permission
score = scorer.score_permission_risk("perm_sts_AssumeRole")

# Score all permissions in the graph
all_scores = scorer.score_all_permissions()

# Generate comprehensive risk report
report = scorer.generate_risk_report()
```

#### How Risk Scoring Works:

The scorer combines multiple signals to compute risk scores:

1. **Base Risk from Action Type** - Known sensitive actions (sts:AssumeRole, iam:PassRole) get higher baseline
2. **User Exposure** - Permissions exposed to more users increase risk (multiplier effect)
3. **Escalation Potential** - How easily can this permission enable privilege escalation?
4. **Causal Strength** - Direct mathematical measure of risk contribution

#### Output Example:

```
Permission: sts:AssumeRole
├─ Risk Level: CRITICAL
├─ Risk Score: 9.5/10
├─ Exposure: 5 users
├─ Causal Strength: 0.85
└─ Reason: High escalation potential; exposed to 5 users; enables privilege escalation
```

## Pipeline Integration

### Data Flow:

```
Red AI (Person B)           Blue AI + Causal (You)          Dashboard (Person D)
─────────────────────      ────────────────────────        ──────────────────
  Find attacks            Generate & apply defenses       Visualize results
  ├─ Attack paths   ──>   ├─ Defensive strategy   ──>     ├─ Before/after graphs
  ├─ Risk scores         ├─ Hardened graph               ├─ Metrics charts
  └─ Escalation         ├─ Security metrics              └─ Recommendations
     insights            └─ Risk attribution
```

## Usage Examples

### Example 1: Run Defense Pipeline Standalone

```python
from src.graph.builder import IAMGraphBuilder
from src.adversarial.red_agent import RedAgent
from src.adversarial.blue_agent import BlueAgent

# Load graph
builder = IAMGraphBuilder(
    uri="bolt://localhost:7687",
    user="neo4j",
    password="changeme"
)
graph = builder.get_networkx_graph()

# Find attacks
red = RedAgent(graph)
attack_paths = red.find_escalation_paths(max_paths=10)

# Generate defenses
blue = BlueAgent(graph)
strategy = blue.generate_defenses(attack_paths)

# Apply and measure
hardened_graph, applied = blue.apply_defenses(strategy)
metrics = blue.compute_metrics()

print(f"Risk reduction: {metrics['risky_exposures_reduced']} exposures removed")
```

### Example 2: Run Causal Risk Analysis

```python
from src.causal.risk_scorer import CausalRiskScorer

scorer = CausalRiskScorer(graph)

# Get report
report = scorer.generate_risk_report()

# Print top risks
for item in report["top_10_riskiest"][:5]:
    print(f"{item['action']}: {item['risk_level']} ({item['risk_score']}/10)")

# Get recommendations
for rec in report["recommendations"]:
    print(f"- {rec}")
```

### Example 3: Full Pipeline Orchestration

```bash
# Run complete Red vs Blue simulation
python run_full_pipeline.py
```

This will:
1. Load the IAM graph
2. Run Red AI attack discovery
3. Run Blue AI defense generation
4. Apply defenses to graph
5. Run causal risk analysis (before & after)
6. Save results to `results.json`

## Output Artifacts

### 1. `results.json`
Complete analysis results including:
- Attack paths discovered
- Defensive actions taken
- Security metrics (before/after)
- Risk attribution
- Recommendations

### 2. `defense_report.txt`
Human-readable summary of:
- Total defensive actions applied
- Breakdown by action type
- Detailed justification for each action

### 3. Console Output
Real-time progress with:
- Graph statistics
- Attack discovery results
- Defense metrics
- Risk distribution

## Security Metrics You Compute

### Graph-Based Metrics:

| Metric | Meaning |
|--------|---------|
| `edges_removed` | Number of IAM relationships eliminated |
| `risky_exposures_reduced` | Sensitive permissions removed from users |
| `least_privilege_improvement_%` | % improvement in average permissions/role |

### Risk Attribution Metrics:

| Metric | Meaning |
|--------|---------|
| `causal_strength` | How much permission contributes to risk (0-1) |
| `exposure_count` | How many users can access this permission |
| `risk_score` | Final risk rating (0-10 scale) |
| `risk_level` | Categorical level (CRITICAL/HIGH/MEDIUM/LOW) |

## Integration Checklist

Your implementation provides:

✅ Blue AI Defense Engine for IRU hardening
✅ Causal Risk Analysis for permission attribution
✅ Before/after security metrics
✅ Defense action tracking & reporting  
✅ Integration with Red AI attacks
✅ Integration with Neo4j graph
✅ Comprehensive test coverage

For Dashboard (Person D) to build on:

- `src/adversarial/blue_agent.py` exports:
  - `BlueAgent` class
  - `DefenseStrategy` dataclass
  - `DefenseAction` dataclass

- `src/causal/risk_scorer.py` exports:
  - `CausalRiskScorer` class
  - `PermissionRiskScore` dataclass
  - `RiskLevel` enum

## Testing

Run comprehensive test suite:

```bash
python tests/blue_ai_test.py
```

Tests verify:
- Graph queries work correctly
- Red AI attack discovery
- Blue AI defense generation
- Defense application logic
- Metrics computation
- Causal risk scoring
- Report generation

All tests passing ✅ = ready for integration!

## Files Created/Modified

### Created by You (Person C):

- ✨ `src/adversarial/blue_agent.py` - Blue AI Defense Engine (360 lines)
- ✨ `src/causal/risk_scorer.py` - Causal Risk Scorer (380 lines)
- ✨ `src/causal/__init__.py` - Package init
- ✨ `run_blue_ai.py` - Blue AI standalone script
- ✨ `run_full_pipeline.py` - Complete orchestration script
- ✨ `tests/blue_ai_test.py` - Comprehensive test suite

### NOT Modified (Person A & B):

- `src/graph/builder.py` - Graph construction (DO NOT MODIFY)
- `src/graph/queries.py` - Graph queries (DO NOT MODIFY)
- `src/adversarial/red_agent.py` - Red AI (DO NOT MODIFY)
- `data/generate_synthetic_iam.py` - Data generation (DO NOT MODIFY)

## Next Steps for Integration

1. **Person D (Dashboard)** will:
   - Import `BlueAgent` and `CausalRiskScorer`
   - Call your methods via API endpoints
   - Visualize metrics and recommendations
   - Display risk distribution charts

2. **Your APIs for Dashboard**:
   ```python
   # Person D's FastAPI will call:
   POST /api/blue-ai/generate-strategy → DefenseStrategy
   POST /api/blue-ai/apply-defenses → metrics dict
   GET  /api/causal/risk-report → report dict
   ```

3. **Demo Script Integration**:
   - Load graph
   - Show attack (Red AI)
   - Show defenses (Blue AI)
   - Show risk scores (Causal)
   - Show hardened graph

## Questions or Issues?

Your implementation is complete and tested. Refer to:
- Docstrings in code files
- Test cases in `tests/blue_ai_test.py`
- Example outputs from `run_full_pipeline.py`

---

## Summary

You've implemented a sophisticated IAM defense and risk attribution system that:

1. **Understands attacks** - Analyzes Red AI findings
2. **Generates defenses** - Proposes concrete security actions
3. **Attributes risk** - Determines which permissions drive vulnerability
4. **Measures impact** - Quantifies security improvement
5. **Integrates seamlessly** - Works with Red AI and graph infrastructure

Your work transforms reactive IAM governance into a proactive, self-healing system. 🎯
