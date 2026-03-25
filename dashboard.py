from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st


ROOT_DIR = Path(__file__).resolve().parent
DATASET_PATH = ROOT_DIR / "data" / "iam_dataset.json"
RESULTS_PATH = ROOT_DIR / "results.json"
REPORT_PATH = ROOT_DIR / "defense_report.txt"


st.set_page_config(
    page_title="RedBlueBrawl Dashboard",
    page_icon="RB",
    layout="wide",
)


def _read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _count_unique(frame: pd.DataFrame, candidate_columns: list[str]) -> int:
    normalized = {col.lower(): col for col in frame.columns}
    for candidate in candidate_columns:
        if candidate in normalized:
            return int(frame[normalized[candidate]].dropna().nunique())
    return 0


def _dataset_summary(dataset: dict) -> dict:
    users = dataset.get("users", [])
    roles = dataset.get("roles", [])
    permissions = dataset.get("permissions", [])

    return {
        "users": len(users),
        "roles": len(roles),
        "permissions": len(permissions),
    }


def _department_frame(dataset: dict) -> pd.DataFrame:
    users = dataset.get("users", [])
    if not users:
        return pd.DataFrame(columns=["department", "count"])

    departments = pd.Series([item.get("department", "Unknown") for item in users])
    counts = departments.value_counts().rename_axis("department").reset_index(name="count")
    return counts


def _risk_distribution_frame(results: dict, key: str) -> pd.DataFrame:
    risk = results.get("risk_analysis", {}).get(key, {})
    if not risk:
        return pd.DataFrame(columns=["risk_level", "permissions"])

    rows = []
    for key, value in risk.items():
        rows.append({"risk_level": key, "permissions": len(value)})
    return pd.DataFrame(rows)


def _show_header() -> None:
    st.title("Red vs Blue IAM Security Dashboard")
    st.caption("Operational view for IAM graph posture, attack findings, and quick dataset checks")


def _show_dataset_tab(dataset: dict) -> None:
    st.subheader("IAM Dataset Overview")

    summary = _dataset_summary(dataset)
    col1, col2, col3 = st.columns(3)
    col1.metric("Users", summary["users"])
    col2.metric("Roles", summary["roles"])
    col3.metric("Permissions", summary["permissions"])

    dept_frame = _department_frame(dataset)
    if dept_frame.empty:
        st.info("No dataset found yet. Add data at data/iam_dataset.json")
        return

    left, right = st.columns([1.2, 1.0])
    with left:
        chart = px.bar(
            dept_frame,
            x="department",
            y="count",
            color="department",
            title="Users by Department",
        )
        chart.update_layout(showlegend=False, xaxis_title="Department", yaxis_title="Users")
        st.plotly_chart(chart, use_container_width=True)

    with right:
        st.dataframe(dept_frame, hide_index=True)


def _show_upload_tab() -> None:
    st.subheader("Quick CSV Analyzer")
    st.write("Upload IAM-style CSV to get immediate user, role, and permission counts.")

    uploaded = st.file_uploader("Upload CSV", type=["csv"])
    if not uploaded:
        st.info("Choose a CSV file to analyze.")
        return

    frame = pd.read_csv(uploaded)
    st.success(f"Loaded {len(frame)} rows and {len(frame.columns)} columns")

    users = _count_unique(frame, ["user", "users", "username", "user_id"])
    roles = _count_unique(frame, ["role", "roles", "role_name"])
    permissions = _count_unique(frame, ["permission", "permissions", "perm"])

    col1, col2, col3 = st.columns(3)
    col1.metric("Number of users", users)
    col2.metric("Number of roles", roles)
    col3.metric("Number of permissions", permissions)

    with st.expander("Preview uploaded data", expanded=False):
        st.dataframe(frame.head(30), use_container_width=True)


def _show_pipeline_tab(results: dict) -> None:
    st.subheader("Red vs Blue AI Simulation Results")
    if not results:
        st.warning("No results.json found. Run run_full_pipeline.py to generate analysis output.")
        return

    summary = results.get("summary", {})
    red_findings = results.get("red_ai_findings", {})
    blue_actions = results.get("blue_ai_actions", {})
    metrics = results.get("metrics", {})

    # ===== EXECUTIVE SUMMARY =====
    st.markdown("## Executive Summary")
    col1, col2, col3 = st.columns(3)
    col1.metric("🔴 Attack paths discovered", summary.get("attack_paths_discovered", 0))
    col2.metric("🔵 Defensive actions generated", summary.get("defensive_actions_generated", 0))
    col3.metric("✅ Actions applied", summary.get("defensive_actions_applied", 0))

    # ===== GRAPH OVERVIEW =====
    st.markdown("## Graph Overview")
    graph_col1, graph_col2, graph_col3 = st.columns(3)
    graph_col1.metric("Total nodes", summary.get("total_nodes", 0))
    graph_col2.metric("Total edges", summary.get("total_edges", 0))
    graph_col3.metric("Estimated risk reduction", f"{blue_actions.get('estimated_risk_reduction', 0):.1f}")

    # ===== RED AI SECTION =====
    st.markdown("## 🔴 Red AI - Attack Paths")
    red_attacks = red_findings.get("attacks", [])
    if red_attacks:
        st.write(f"**Found {len(red_attacks)} attack path(s)**")
        attack_df = pd.DataFrame(red_attacks)
        st.dataframe(attack_df, hide_index=True)
    else:
        st.info("No Red AI attack records found")

    # ===== BLUE AI SECTION =====
    st.markdown("## 🔵 Blue AI - Defensive Strategy")
    blue_col1, blue_col2, blue_col3, blue_col4 = st.columns(4)
    blue_col1.metric("Total actions", blue_actions.get("total_actions", 0))
    blue_col2.metric("Roles split", blue_actions.get("roles_split", 0))
    blue_col3.metric("Permissions removed", blue_actions.get("permissions_removed", 0))
    blue_col4.metric("Risk reduction", f"{blue_actions.get('estimated_risk_reduction', 0):.1f}")

    # ===== SECURITY METRICS COMPARISON =====
    st.markdown("## Security Metrics - Before vs After")
    
    metrics_col1, metrics_col2 = st.columns(2)
    
    with metrics_col1:
        st.markdown("### 📊 Graph Edges")
        edges_data = {
            "State": ["Original", "Hardened"],
            "Edges": [
                metrics.get("original_edges", 0),
                metrics.get("hardened_edges", 0),
            ],
        }
        edges_df = pd.DataFrame(edges_data)
        chart = px.bar(
            edges_df,
            x="State",
            y="Edges",
            color="State",
            title="Graph Edges Comparison",
        )
        chart.update_layout(showlegend=False)
        st.plotly_chart(chart, use_container_width=True)
    
    with metrics_col2:
        st.markdown("### 📊 Risky Exposures")
        exposure_data = {
            "State": ["Original", "Hardened"],
            "Exposures": [
                metrics.get("original_risky_exposures", 0),
                metrics.get("hardened_risky_exposures", 0),
            ],
        }
        exposure_df = pd.DataFrame(exposure_data)
        chart = px.bar(
            exposure_df,
            x="State",
            y="Exposures",
            color="State",
            title="Risky Exposures Comparison",
        )
        chart.update_layout(showlegend=False)
        st.plotly_chart(chart, use_container_width=True)

    # ===== IMPROVEMENT METRICS =====
    st.markdown("## Improvement Summary")
    improve_col1, improve_col2, improve_col3 = st.columns(3)
    improve_col1.metric(
        "Edges removed",
        metrics.get("edges_removed", 0),
    )
    improve_col2.metric(
        "Risky exposures reduced",
        metrics.get("hardened_risky_exposures", 0) - metrics.get("original_risky_exposures", 0),
    )
    improve_col3.metric(
        "Least privilege improvement (%)",
        f"{metrics.get('least_privilege_improvement_pct', 0):.2f}%",
    )

    # ===== CAUSAL RISK ANALYSIS =====
    st.markdown("## Risk Analysis - Original vs Hardened")
    
    risk_col1, risk_col2 = st.columns(2)

    original_risk_frame = _risk_distribution_frame(results, "original_risk_distribution")
    with risk_col1:
        st.markdown("### Original Risk Distribution")
        if not original_risk_frame.empty:
            chart = px.pie(
                original_risk_frame,
                values="permissions",
                names="risk_level",
                title="Original Permissions by Risk Level",
                color_discrete_sequence=px.colors.sequential.RdYlGn_r,
            )
            st.plotly_chart(chart, use_container_width=True)
        else:
            st.info("Original risk distribution not available")

    hardened_risk_frame = _risk_distribution_frame(results, "hardened_risk_distribution")
    with risk_col2:
        st.markdown("### Hardened Risk Distribution")
        if not hardened_risk_frame.empty:
            chart = px.pie(
                hardened_risk_frame,
                values="permissions",
                names="risk_level",
                title="Hardened Permissions by Risk Level",
                color_discrete_sequence=px.colors.sequential.RdYlGn_r,
            )
            st.plotly_chart(chart, use_container_width=True)
        else:
            st.info("Hardened risk distribution not available")

    # ===== TOP RISKIEST PERMISSIONS =====
    st.markdown("## Top Riskiest Permissions (Causal Attribution)")
    top_riskiest = results.get("risk_analysis", {}).get("top_riskiest_permissions", [])
    if top_riskiest:
        top_risk_df = pd.DataFrame(top_riskiest)
        st.dataframe(top_risk_df, hide_index=True)
    else:
        st.info("No top riskiest permissions data available")

    # ===== DOWNLOAD REPORT =====
    st.markdown("---")
    if REPORT_PATH.exists():
        st.download_button(
            label="📥 Download Full Defense Report",
            data=REPORT_PATH.read_text(encoding="utf-8"),
            file_name="defense_report.txt",
            mime="text/plain",
        )
    else:
        st.info("Defense report not yet generated. Run the pipeline to create it.")


def main() -> None:
    _show_header()

    dataset = _read_json(DATASET_PATH)
    results = _read_json(RESULTS_PATH)

    tab1, tab2, tab3 = st.tabs(["Dataset", "Upload Analyzer", "Pipeline Output"])

    with tab1:
        _show_dataset_tab(dataset)

    with tab2:
        _show_upload_tab()

    with tab3:
        _show_pipeline_tab(results)


if __name__ == "__main__":
    main()
