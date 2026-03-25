"""Red AI page - Person B: Attack discovery."""

import streamlit as st
import pandas as pd

try:
    from .utils import get_results
except ImportError:
    from pages.utils import get_results

def render():
    st.title("🔴 Threat Intelligence")
    st.caption("Discovered privilege escalation paths and attack surface analysis")
    
    results = get_results()
    red_findings = results.get("red_ai_findings", {})
    
    if not results:
        st.warning("⏳ No results yet. Run the full demo to discover attack paths.")
        return
    
    attack_count = red_findings.get("attack_count", 0)
    attacks = red_findings.get("attacks", [])
    
    # Summary
    col1, col2 = st.columns(2)
    with col1:
        st.metric("🔴 Attack Paths Found", attack_count)
    with col2:
        if attacks:
            avg_risk = sum(a.get("risk_score", 0) for a in attacks) / len(attacks)
            st.metric("Average Risk Score", f"{avg_risk:.2f}")
    
    # Attack type distribution
    st.divider()
    st.subheader("Attack Type Distribution")
    
    if attacks:
        try:
            import plotly.express as px
            attack_types = {}
            for attack in attacks:
                atype = attack.get("type", "Unknown")
                attack_types[atype] = attack_types.get(atype, 0) + 1
            
            type_df = pd.DataFrame(list(attack_types.items()), columns=["Type", "Count"])
            fig = px.bar(type_df, x="Type", y="Count", title="Attack Type Breakdown")
            st.plotly_chart(fig, use_container_width=True)
        except Exception as e:
            st.warning(f"Could not render attack type chart: {str(e)[:50]}")
    
    # Top attack paths table
    st.divider()
    st.subheader(f"Top Attack Paths (Top {min(10, len(attacks))})")
    
    if attacks:
        display_attacks = []
        for i, attack in enumerate(attacks[:10], 1):
            display_attacks.append({
                "Rank": i,
                "Risk Score": attack.get("risk_score", 0),
                "Type": attack.get("type", "Unknown"),
                "Path Length": attack.get("path_length", 0),
                "Perms Used": attack.get("permissions_used", 0),
            })
        
        attack_df = pd.DataFrame(display_attacks)
        st.dataframe(attack_df, use_container_width=True, hide_index=True)
    else:
        st.info("No attacks found in results.")
    
    # Detailed view
    st.divider()
    st.subheader("Attack Path Details")
    
    if attacks:
        selected_idx = st.selectbox(
            "Select attack path to view details",
            range(min(10, len(attacks))),
            format_func=lambda i: f"Path #{i+1} - Risk {attacks[i].get('risk_score', 0)}"
        )
        
        attack = attacks[selected_idx]
        
        col_detail1, col_detail2 = st.columns(2)
        
        with col_detail1:
            st.write("**Path Metrics:**")
            st.write(f"- Risk Score: {attack.get('risk_score', 0)}")
            st.write(f"- Attack Type: {attack.get('type', 'Unknown')}")
            st.write(f"- Path Length: {attack.get('path_length', 0)} hops")
            st.write(f"- Permissions Used: {attack.get('permissions_used', 0)}")
        
        with col_detail2:
            st.write("**Impact:**")
            st.write("- High-privilege role reachable from low-privilege user")
            st.write("- Can escalate permissions through assumed roles")
            st.write("- Sensitive actions (IAM, S3, EC2) accessible")
    else:
        st.info("Run demo to discover attacks")
    
    st.divider()
    st.markdown("""
    ### How Red AI Works:
    1. Identifies low-privilege users (entry points)
    2. Finds high-privilege roles (targets)
    3. Maps paths through role-permission graph
    4. Scores by risk and path complexity
    5. Detects privilege escalation opportunities
    """)
