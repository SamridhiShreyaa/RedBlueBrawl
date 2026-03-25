"""Risk Analysis page - Person C: Causal risk engine."""

import streamlit as st
import pandas as pd
from .utils import get_results

def render():
    st.title("⚠️ Risk Analysis")
    st.caption("Permission risk assessment and exposure metrics")
    
    results = get_results()
    risk_analysis = results.get("risk_analysis", {})
    
    if not results:
        st.warning("⏳ Run the full demo to generate risk analysis.")
        return
    
    # Important note
    st.info("""
    📌 **Important:** Risk level reflects the *danger* of each permission type. 
    Hardening reduces *exposure* (how many users can access it), not the intrinsic 
    danger category. CRITICAL permissions may remain CRITICAL, but fewer users can access them.
    """)
    
    # Risk distribution
    st.divider()
    st.subheader("Permission Risk Distribution")
    
    original_dist = risk_analysis.get("original_risk_distribution", {})
    hardened_dist = risk_analysis.get("hardened_risk_distribution", {})
    
    col_orig, col_hard = st.columns(2)
    
    with col_orig:
        st.markdown("### Original Risk Distribution")
        if original_dist:
            try:
                import plotly.express as px
                orig_df = pd.DataFrame([
                    {"Risk Level": k, "Count": len(v)} 
                    for k, v in original_dist.items()
                ])
                fig = px.pie(
                    orig_df,
                    values="Count",
                    names="Risk Level",
                    title="Permissions by Risk Level (Before)"
                )
                st.plotly_chart(fig, use_container_width=True)
            except:
                st.dataframe(pd.DataFrame(list(original_dist.items()), columns=["Level", "Count"]))
    
    with col_hard:
        st.markdown("### Hardened Risk Distribution")
        if hardened_dist:
            try:
                import plotly.express as px
                hard_df = pd.DataFrame([
                    {"Risk Level": k, "Count": len(v)} 
                    for k, v in hardened_dist.items()
                ])
                fig = px.pie(
                    hard_df,
                    values="Count",
                    names="Risk Level",
                    title="Permissions by Risk Level (After)"
                )
                st.plotly_chart(fig, use_container_width=True)
            except:
                st.dataframe(pd.DataFrame(list(hardened_dist.items()), columns=["Level", "Count"]))
    
    # Top riskiest permissions
    st.divider()
    st.subheader("Top Riskiest Permissions (Causal Attribution)")
    
    top_riskiest = risk_analysis.get("top_riskiest_permissions", [])
    
    if top_riskiest:
        perm_data = []
        for item in top_riskiest[:10]:
            perm_data.append({
                "Permission": item.get("action", "Unknown"),
                "Risk Level": item.get("risk_level", "N/A"),
                "Risk Score": item.get("risk_score", 0),
                "Exposure": item.get("exposure_count", 0),
                "Why": item.get("justification", "High-impact system action")[:60] + "..."
            })
        
        perm_df = pd.DataFrame(perm_data)
        st.dataframe(perm_df, use_container_width=True, hide_index=True)
    else:
        st.info("No permission risk data available")
    
    # Risk levels explanation
    st.divider()
    st.subheader("Risk Level Definitions")
    
    risk_defs = pd.DataFrame({
        "Level": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        "Description": [
            "Can modify IAM, access secrets, terminate resources",
            "Can access sensitive data or create resources",
            "Can view resources or perform limited changes",
            "Read-only or very restricted actions"
        ],
        "Examples": [
            "iam:CreateUser, sts:AssumeRole",
            "s3:PutObject, ec2:CreateInstance",
            "logs:GetLogEvents, describe:* actions",
            "LIST operations, GetObject"
        ]
    })
    
    st.dataframe(risk_defs, use_container_width=True, hide_index=True)
    
    # Causal insights
    st.divider()
    st.subheader("Causal Risk Insights")
    
    col_insight1, col_insight2 = st.columns(2)
    
    with col_insight1:
        st.markdown("**What causes high risk?**")
        st.write("""
        - Sensitive permissions (IAM, KMS, RDS)
        - Wide exposure (many users/roles have access)
        - Privilege escalation potential
        - Lack of principal restrictions
        """)
    
    with col_insight2:
        st.markdown("**How Blue AI reduces it:**")
        st.write("""
        - Removes overly-broad permissions
        - Splits privileged roles
        - Enforces least privilege
        - Restricts sensitive permission access
        """)
    
    st.divider()
    st.markdown("""
    ### How Causal Risk Works:
    1. **Risk Scoring**: Each permission gets a danger level (CRITICAL → LOW)
    2. **Exposure Count**: How many users can access each permission
    3. **Justification**: Why a permission is risky (e.g., "Can create IAM users")
    4. **Recommendations**: Reduce exposure, not the permission itself
    """)
