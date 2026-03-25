"""Shared utilities for dashboard pages."""

import json
from pathlib import Path
from datetime import datetime
import pandas as pd

ROOT_DIR = Path(__file__).resolve().parent.parent
DATASET_PATH = ROOT_DIR / "data" / "iam_dataset.json"
RESULTS_PATH = ROOT_DIR / "results.json"
REPORT_PATH = ROOT_DIR / "defense_report.txt"


def read_json(path: Path) -> dict:
    """Safely read JSON file."""
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def get_dataset() -> dict:
    """Load IAM dataset."""
    return read_json(DATASET_PATH)


def get_results() -> dict:
    """Load pipeline results."""
    return read_json(RESULTS_PATH)


def load_graph():
    """Load NetworkX graph from pipeline (simplified)."""
    try:
        from src.graph.builder import IAMGraphBuilder
        import os
        builder = IAMGraphBuilder(
            uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            user=os.getenv("NEO4J_USER", "neo4j"),
            password=os.getenv("NEO4J_PASSWORD", "changeme"),
        )
        graph = builder.get_networkx_graph()
        builder.close()
        return graph
    except Exception as e:
        return None


def get_file_exists(path: Path) -> bool:
    """Check if file exists."""
    return path.exists()


def get_defense_report() -> str:
    """Load defense report."""
    if not REPORT_PATH.exists():
        return ""
    return REPORT_PATH.read_text(encoding="utf-8")
