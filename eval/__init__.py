"""Evaluation harness for RedBlueBrawl.

Generates synthetic IAM tenants with *known* planted privilege-escalation
chains, runs detection/remediation methods against them, and scores each
method against ground truth (precision/recall/F1 on risky-permission
detection, fraction of planted attack paths broken after remediation,
false-positive rate, and benign edges wrongly cut).
"""
