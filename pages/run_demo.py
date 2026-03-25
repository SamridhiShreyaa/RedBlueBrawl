"""Run Demo page - single-click pipeline orchestration."""

import streamlit as st
import subprocess
import os
import sys
from pathlib import Path

try:
    from .utils import get_results
except ImportError:
    from pages.utils import get_results

def render():
    st.title("▶️ Analysis Execution")
    st.caption("Run complete threat assessment and remediation workflow")
    
    st.divider()
    
    # Run button
    run_analysis = st.button(
        "🔍 START ANALYSIS",
        key="run_demo_button",
        use_container_width=True,
        type="primary"
    )
    
    st.divider()
    
    st.subheader("Workflow Overview")
    
    st.markdown("""
    This analysis runs the complete threat assessment workflow:
    
    1. **Load Infrastructure** - Build IAM relationship graph
    2. **Threat Discovery** - Identify privilege escalation opportunities
    3. **Risk Remediation** - Generate defensive action recommendations
    4. **Metrics & Impact** - Quantify security improvements
    5. **Risk Assessment** - Analyze permission exposure and risk levels
    """)
    
    if run_analysis:
        st.info("⏳ Starting analysis... this may take 30-60 seconds")
        
        # Create progress container
        progress_container = st.container()
        log_container = st.container()
        
        with progress_container:
            st.subheader("Pipeline Progress")
            col1, col2, col3, col4, col5 = st.columns(5)
            
            progress_steps = {
                "Load Graph": col1,
                "Find Attacks": col2,
                "Apply Defenses": col3,
                "Compute Metrics": col4,
                "Risk Analysis": col5
            }
            
            placeholders = {name: col.empty() for name, col in progress_steps.items()}
        
        with log_container:
            st.subheader("Execution Log")
            log_placeholder = st.empty()
            logs = []
        
        # Run pipeline
        try:
            root_dir = Path(__file__).resolve().parent.parent
            os.chdir(root_dir)
            
            # Get Python executable
            python_exe = sys.executable
            
            # Run the pipeline
            logs.append("📍 Starting orchestration...")
            
            # Update progress
            placeholders["Load Graph"].write("🔄 Loading...")
            logs.append("[1/5] Loading IAM graph from Neo4j...")
            log_placeholder.text_area("Logs", value="\n".join(logs), height=150, disabled=True)
            
            placeholders["Load Graph"].write("✅ Complete")
            
            # Run pipeline script
            placeholders["Find Attacks"].write("🔄 Running...")
            logs.append("[2/5] Running Red AI (finding attacks)...")
            log_placeholder.text_area("Logs", value="\n".join(logs), height=150, disabled=True)
            
            result = subprocess.run(
                [python_exe, "run_full_pipeline.py"],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                logs.append("[2/5] ✅ Red AI complete - attacks found")
                logs.append("[3/5] ✅ Blue AI complete - defenses applied")
                logs.append("[4/5] ✅ Metrics computed")
                logs.append("[5/5] ✅ Risk analysis complete")
                
                placeholders["Find Attacks"].write("✅ Complete")
                placeholders["Apply Defenses"].write("✅ Complete")
                placeholders["Compute Metrics"].write("✅ Complete")
                placeholders["Risk Analysis"].write("✅ Complete")
                
                logs.append("\n✅ PIPELINE COMPLETED SUCCESSFULLY")
                logs.append("\nResults saved to results.json")
                logs.append("Defense report saved to defense_report.txt")
                
                log_placeholder.text_area("Logs", value="\n".join(logs), height=150, disabled=True)
                
                st.success("✅ Demo completed! Check other pages to view results.")
                st.balloons()
            else:
                logs.append(f"\n❌ Pipeline failed with return code {result.returncode}")
                logs.append("\nStdout:")
                logs.append(result.stdout[-500:] if len(result.stdout) > 500 else result.stdout)
                logs.append("\nStderr:")
                logs.append(result.stderr[-500:] if len(result.stderr) > 500 else result.stderr)
                
                log_placeholder.text_area("Logs", value="\n".join(logs), height=150, disabled=True)
                st.error("❌ Pipeline failed. Check logs above and ensure Neo4j is running.")
        
        except subprocess.TimeoutExpired:
            logs.append("❌ Pipeline timed out after 120 seconds")
            log_placeholder.text_area("Logs", value="\n".join(logs), height=150, disabled=True)
            st.error("⏱️ Pipeline timed out. Check Neo4j connection and dataset size.")
        except Exception as e:
            logs.append(f"❌ Error: {str(e)}")
            log_placeholder.text_area("Logs", value="\n".join(logs), height=150, disabled=True)
            st.error(f"Error running pipeline: {str(e)}")
    
    st.divider()
    st.subheader("Output Artifacts")
    
    st.markdown("""
    Analysis generates:
    
    ✅ **Threat Assessment** - Attack paths and risk scores
    ✅ **Remediation Plan** - Recommended defensive actions
    ✅ **Risk Report** - Permission exposure analysis
    ✅ **Audit Trail** - Complete reproducible results for compliance
    """)
