"""
RedBlueBrawl Dashboard - Multi-Page Application
Showcases contributions from all team members in one integrated UI.
"""

import streamlit as st

st.set_page_config(
    page_title="RedBlueBrawl - Red vs Blue IAM Dashboard",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# 🚫 Hide default Streamlit pages navigation (IMPORTANT FIX)
st.markdown("""
    <style>
        [data-testid="stSidebarNav"] {display: none;}
    </style>
""", unsafe_allow_html=True)

st.sidebar.title("🔐 IAM Security Platform")
st.sidebar.divider()

page = st.sidebar.radio(
    "Navigation",
    [
        "📊 Overview",
        "📈 IAM Graph",
        "🔴 Red AI (Attacker)",
        "🔵 Blue AI (Defender)",
        "📉 Before vs After",
        "⚠️ Risk Analysis",
        "📥 Export & Artifacts",
        "▶️ Run Demo",
    ],
)

st.sidebar.divider()
st.sidebar.markdown("""
### System Components:
- **Graph Analysis**: IAM relationship modeling
- **Threat Simulation**: Attack path discovery
- **Remediation**: Defensive action proposals
- **Risk Attribution**: Causal analysis engine
""")

# Import and render pages dynamically
if page == "📊 Overview":
    from pages import overview
    overview.render()
elif page == "📈 IAM Graph":
    from pages import iam_graph
    iam_graph.render()
elif page == "🔴 Red AI (Attacker)":
    from pages import red_ai
    red_ai.render()
elif page == "🔵 Blue AI (Defender)":
    from pages import blue_ai
    blue_ai.render()
elif page == "📉 Before vs After":
    from pages import before_after
    before_after.render()
elif page == "⚠️ Risk Analysis":
    from pages import risk_analysis
    risk_analysis.render()
elif page == "📥 Export & Artifacts":
    from pages import export_artifacts
    export_artifacts.render()
elif page == "▶️ Run Demo":
    from pages import run_demo
    run_demo.render()