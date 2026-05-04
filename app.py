import streamlit as st
import pandas as pd
from preprocessing.preprocess import preprocess_data
from model.anomaly_model import train_model, detect_anomalies
from agent.threat_agent import agent_decision

# Page config
st.set_page_config(page_title="CyberSentinel", layout="wide")

# Title
st.title("🔐 CyberSentinel - AI Threat Detection System")
st.markdown("### 🚀 Autonomous Security Operations Dashboard")

# Sidebar
st.sidebar.header("⚙️ Settings")
st.sidebar.info("Upload a network log CSV file to begin analysis")

# File uploader
uploaded_file = st.file_uploader("📂 Upload Network Logs CSV", type=["csv"])

if uploaded_file is not None:

    try:
        with st.spinner("🔍 Analyzing network logs..."):

            # Read uploaded file (for preview)
            data = pd.read_csv(uploaded_file)

            st.subheader("📄 Uploaded Data Preview")
            st.dataframe(data.head())

            # Reset file pointer (VERY IMPORTANT)
            uploaded_file.seek(0)

            # Preprocess data
            scaled_data, original_data = preprocess_data(uploaded_file)

            # Train model
            model = train_model(scaled_data)

            # Detect anomalies
            predictions = detect_anomalies(model, scaled_data)

            # Map results
            original_data['threat_status'] = predictions
            original_data['threat_status'] = original_data['threat_status'].map({
                1: "Normal",
                -1: "Suspicious"
            })

            # Agent decisions
            threat_levels = []
            responses = []

            for _, row in original_data.iterrows():
                level, action = agent_decision(row)
                threat_levels.append(level)
                responses.append(action)

            original_data['threat_level'] = threat_levels
            original_data['agent_response'] = responses

        st.success("✅ Analysis Completed Successfully!")

        # ================= KPI METRICS =================
        total = len(original_data)
        normal = (original_data['threat_status'] == "Normal").sum()
        suspicious = (original_data['threat_status'] == "Suspicious").sum()

        col1, col2, col3 = st.columns(3)
        col1.metric("📊 Total Logs", total)
        col2.metric("✅ Normal", normal)
        col3.metric("🚨 Suspicious", suspicious)

        # ================= CHARTS =================
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("📊 Threat Status Distribution")
            st.bar_chart(original_data['threat_status'].value_counts())

        with col2:
            st.subheader("⚠️ Threat Level Distribution")
            st.bar_chart(original_data['threat_level'].value_counts())

        # ================= FILTER =================
        st.subheader("🔍 Filter Results")

        filter_option = st.selectbox(
            "Filter Threats",
            ["All", "Normal", "Suspicious"]
        )

        if filter_option != "All":
            filtered_data = original_data[
                original_data['threat_status'] == filter_option
            ]
        else:
            filtered_data = original_data

        # ================= TABLE =================
        st.subheader("📋 Detailed Results")
        st.dataframe(filtered_data)

        # ================= DOWNLOAD =================
        csv = original_data.to_csv(index=False).encode('utf-8')
        st.download_button(
            "⬇️ Download Results",
            csv,
            "threat_results.csv",
            "text/csv"
        )

    except Exception as e:
        st.error(f"❌ Error: {e}")

else:
    st.warning("⚠️ Please upload a CSV file to start analysis")