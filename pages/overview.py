"""Overview page - 10-second context of entire system."""

import streamlit as st
from datetime import datetime

try:
    from .utils import get_dataset, get_results, DATASET_PATH, RESULTS_PATH
except ImportError:
    from pages.utils import get_dataset, get_results, DATASET_PATH, RESULTS_PATH

def render():
    st.title("📊 System Overview")
    st.caption("Current IAM posture and threat analysis status")
    
    dataset = get_dataset()
    results = get_results()
    summary = results.get("summary", {})
    
    # Status cards
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Users", len(dataset.get("users", [])))
    with col2:
        st.metric("Total Roles", len(dataset.get("roles", [])))
    with col3:
        st.metric("Total Permissions", len(dataset.get("permissions", [])))
    with col4:
        st.metric("Total Graph Nodes", summary.get("total_nodes", "N/A"))
    
    # Graph metrics
    col5, col6, col7 = st.columns(3)
    with col5:
        st.metric("Graph Edges", summary.get("total_edges", "N/A"))
    with col6:
        dataset_id = dataset.get("metadata", {}).get("dataset_id", "Unknown")
        st.metric("Dataset ID", dataset_id)
    with col7:
        st.metric("Pipeline Run", "✅ Complete" if results else "⏳ Pending")
    
    # System info
    st.divider()
    st.subheader("System Environment")
    
    col_info1, col_info2 = st.columns(2)
    
    with col_info1:
        st.write("**Data Files:**")
        st.write(f"- Dataset: {DATASET_PATH.name} {'✅' if dataset else '❌'}")
        st.write(f"- Results: {RESULTS_PATH.name} {'✅' if results else '❌'}")
    
    with col_info2:
        st.write("**Neo4j Status:**")
        try:
            from src.graph.builder import IAMGraphBuilder
            builder = IAMGraphBuilder.from_env()
            stats = builder.get_graph_stats()
            builder.close()
            st.write(f"- ✅ Connected")
            st.write(f"- Nodes: {stats.get('total_nodes', 0)}")
            st.write(f"- Edges: {stats.get('total_edges', 0)}")
        except Exception as e:
            st.write(f"- ⚠️ Not connected (run demo to load): {str(e)[:50]}")
    
    # Quick facts
    st.divider()
    st.subheader("Quick Facts")
    
    if results:
        col_facts1, col_facts2, col_facts3 = st.columns(3)
        with col_facts1:
            st.success(f"🔴 Red AI found {summary.get('attack_paths_discovered', 0)} attack paths")
        with col_facts2:
            st.info(f"🔵 Blue AI proposed {summary.get('defensive_actions_generated', 0)} defenses")
        with col_facts3:
            metrics = results.get("metrics", {})
            st.metric("Improvement", f"+{metrics.get('least_privilege_improvement_pct', 0):.1f}%")
    else:
        st.warning("⏳ Run the full demo to populate all sections")
