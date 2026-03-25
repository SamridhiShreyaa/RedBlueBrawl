"""IAM Graph page - Person A: Graph modeling & visualization."""

import streamlit as st
import pandas as pd

try:
    from .utils import load_graph, get_dataset
except ImportError:
    from pages.utils import load_graph, get_dataset

def render():
    st.title("📈 IAM Graph Visualization")
    st.caption("Identity and access relationship mapping")
    
    dataset = get_dataset()
    graph = load_graph()
    
    # Filter controls
    st.subheader("Graph Filters & Search")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        show_users = st.checkbox("Show Users", value=True)
    with col2:
        show_roles = st.checkbox("Show Roles", value=True)
    with col3:
        show_perms = st.checkbox("Show Permissions", value=True)
    
    search_term = st.text_input("Search by node ID/name/action (partial match)")
    
    # Node counts panel
    st.divider()
    st.subheader("Graph Statistics")
    
    col_stats1, col_stats2, col_stats3, col_stats4 = st.columns(4)
    
    users = dataset.get("users", [])
    roles = dataset.get("roles", [])
    perms = dataset.get("permissions", [])
    
    with col_stats1:
        st.metric("Users", len(users))
    with col_stats2:
        st.metric("Roles", len(roles))
    with col_stats3:
        st.metric("Permissions", len(perms))
    with col_stats4:
        total_edges = (
            len([u for u in users for _ in u.get("roles", [])]) +  # HAS_ROLE edges
            len([r for r in roles for _ in r.get("permissions", [])])  # GRANTS edges
        )
        st.metric("Edges (approx)", total_edges)
    
    # Relationship breakdown
    st.divider()
    st.subheader("Edge Types Breakdown")
    
    has_role_edges = sum(len(u.get("roles", [])) for u in users)
    grants_edges = sum(len(r.get("permissions", [])) for r in roles)
    
    edge_data = pd.DataFrame({
        "Relation Type": ["HAS_ROLE", "GRANTS"],
        "Count": [has_role_edges, grants_edges]
    })
    
    col_edges1, col_edges2 = st.columns(2)
    with col_edges1:
        st.dataframe(edge_data, hide_index=True)
    
    with col_edges2:
        try:
            import plotly.express as px
            fig = px.pie(
                edge_data,
                values="Count",
                names="Relation Type",
                title="Edge Type Distribution"
            )
            st.plotly_chart(fig, use_container_width=True)
        except Exception as e:
            st.warning(f"Could not render edge chart: {str(e)[:50]}")
    
    # Graph visualization
    st.divider()
    st.subheader("Interactive Graph Visualization")
    
    if graph:
        st.info("Graph loaded from Neo4j. Use filters above to customize view.")
        
        # Apply filters
        filtered_nodes = []
        if show_users:
            filtered_nodes.extend([n for n, d in graph.nodes(data=True) if d.get("label") == "User"])
        if show_roles:
            filtered_nodes.extend([n for n, d in graph.nodes(data=True) if d.get("label") == "Role"])
        if show_perms:
            filtered_nodes.extend([n for n, d in graph.nodes(data=True) if d.get("label") == "Permission"])
        
        # Apply search filter
        if search_term:
            filtered_nodes = [
                n for n in filtered_nodes 
                if search_term.lower() in str(n).lower() or 
                   search_term.lower() in str(graph.nodes[n].get("action", "")).lower() or
                   search_term.lower() in str(graph.nodes[n].get("username", "")).lower()
            ]
        
        st.write(f"**Showing {len(filtered_nodes)} nodes**")
        
        # Node list
        with st.expander(f"View filtered nodes ({len(filtered_nodes)})"):
            node_list_data = []
            for node_id in filtered_nodes[:50]:  # Limit to first 50 for display
                attrs = graph.nodes[node_id]
                node_list_data.append({
                    "ID": node_id,
                    "Type": attrs.get("label", "Unknown"),
                    "Name/Action": attrs.get("username") or attrs.get("name") or attrs.get("action", "N/A")
                })
            if node_list_data:
                st.dataframe(pd.DataFrame(node_list_data), hide_index=True)
    else:
        st.warning("⚠️ Graph not loaded. Run demo or ensure Neo4j is connected.")
    
    # Graph visualization with pyvis
    st.divider()
    st.subheader("Full Graph View (if available)")
    
    try:
        if graph:
            from pyvis.network import Network
            import tempfile
            import os
            
            # Create filtered subgraph
            subgraph = graph.subgraph(filtered_nodes) if filtered_nodes else graph
            
            net = Network(height="750px", directed=True, physics=True)
            net.from_nx(subgraph)
            
            # Color nodes by type
            for node in net.nodes:
                node_id = node["id"]
                node_type = graph.nodes[node_id].get("label", "Unknown")
                if node_type == "User":
                    node["color"] = "#FF6B6B"  # Red
                elif node_type == "Role":
                    node["color"] = "#4ECDC4"  # Teal
                elif node_type == "Permission":
                    node["color"] = "#FFE66D"  # Yellow
                else:
                    node["color"] = "#95E1D3"  # Green
            
            # Save and display
            with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as f:
                net.show(f.name)
                with open(f.name, "r") as graph_file:
                    st.components.v1.html(graph_file.read(), height=800)
                os.unlink(f.name)
    except ImportError:
        st.info("Install pyvis for interactive graph visualization: pip install pyvis")
    except Exception as e:
        st.warning(f"Could not render graph visualization: {str(e)}")
