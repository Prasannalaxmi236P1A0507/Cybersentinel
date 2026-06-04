import streamlit as st
import plotly.express as px
import pandas as pd

from preprocessing.preprocess import preprocess_data
from model.anomaly_model import train_model, detect_anomalies
from agent.threat_agent import agent_decision

# ================= PAGE CONFIG =================
st.set_page_config(
    page_title="CyberSentinel",
    layout="wide"
)

# Hide streamlit UI elements
st.markdown("""
<style>
#MainMenu {visibility:hidden;}
footer {visibility:hidden;}
header {visibility:hidden;}
[data-testid="stToolbar"] {display:none;}
</style>
""", unsafe_allow_html=True)

# ================= TITLE =================
st.title("🔐 CyberSentinel - AI Threat Detection System")
st.markdown("### 🚀 Autonomous Security Operations Dashboard")

# ================= SIDEBAR =================
st.sidebar.header("⚙️ Settings")
st.sidebar.info("Upload a network log CSV file to begin analysis")

# ================= FILE UPLOAD =================
uploaded_file = st.file_uploader(
    "📂 Upload Network Logs CSV",
    type=["csv"]
)

# ================= MAIN LOGIC =================
if uploaded_file is not None:

    try:
        with st.spinner("🔍 Analyzing network logs..."):

            # Preview uploaded file
            data = pd.read_csv(uploaded_file)

            st.subheader("📄 Uploaded Data Preview")
            st.dataframe(data.head())

            # Reset pointer
            uploaded_file.seek(0)

            # Preprocess data
            scaled_data, original_data = preprocess_data(uploaded_file)

            # Train model
            model = train_model(scaled_data)

            # Detect anomalies
            predictions = detect_anomalies(model, scaled_data)

            # Add prediction labels
            original_data['threat_status'] = predictions
            original_data['threat_status'] = original_data[
                'threat_status'
            ].map({
                1: "Normal",
                -1: "Suspicious"
            })

            # ================= AGENT DECISIONS =================
            threat_levels = []
            responses = []
            attack_types = []

            for _, row in original_data.iterrows():

                level, action, attack = agent_decision(row)

                threat_levels.append(level)
                responses.append(action)
                attack_types.append(attack)

            original_data['threat_level'] = threat_levels
            original_data['agent_response'] = responses
            original_data['attack_type'] = attack_types

        st.success("✅ Analysis Completed Successfully!")

        # ================= KPI METRICS =================
        total = len(original_data)

        normal = (
            original_data['threat_status'] == "Normal"
        ).sum()

        suspicious = (
            original_data['threat_status'] == "Suspicious"
        ).sum()

        col1, col2, col3 = st.columns(3)

        col1.metric("📊 Total Logs", total)
        col2.metric("✅ Normal", normal)
        col3.metric("🚨 Suspicious", suspicious)

        # ================= INTERACTIVE CHARTS =================

        # Threat Status Bar Chart
        st.subheader("📊 Threat Status Distribution")

        threat_counts = (
            original_data['threat_status']
            .value_counts()
            .reset_index()
        )

        threat_counts.columns = ['Threat Status', 'Count']

        fig_bar = px.bar(
            threat_counts,
            x='Threat Status',
            y='Count',
            title='Threat Status Overview',
            text='Count'
        )

        st.plotly_chart(fig_bar, use_container_width=True)

        # Pie Chart
        st.subheader("🥧 Threat Status Pie Chart")

        fig_pie = px.pie(
            names=original_data['threat_status'].value_counts().index,
            values=original_data['threat_status'].value_counts().values,
            title='Threat Distribution'
        )

        st.plotly_chart(fig_pie, use_container_width=True)

        # Threat Level Chart
        st.subheader("⚠️ Threat Level Distribution")

        level_counts = (
            original_data['threat_level']
            .value_counts()
            .reset_index()
        )

        level_counts.columns = ['Threat Level', 'Count']

        fig_level = px.bar(
            level_counts,
            x='Threat Level',
            y='Count',
            title='Threat Level Overview',
            text='Count'
        )

        st.plotly_chart(fig_level, use_container_width=True)

        # Attack Type Chart
        st.subheader("🎯 Attack Type Distribution")

        attack_counts = (
            original_data['attack_type']
            .value_counts()
            .reset_index()
        )

        attack_counts.columns = ['Attack Type', 'Count']

        fig_attack = px.bar(
            attack_counts,
            x='Attack Type',
            y='Count',
            title='Detected Attack Types',
            text='Count'
        )

        st.plotly_chart(fig_attack, use_container_width=True)

        # Packet Trend Chart
        if 'packet_count' in original_data.columns:

            st.subheader("📈 Packet Count Trend")

            fig_line = px.line(
                original_data,
                y='packet_count',
                title='Network Packet Activity'
            )

            st.plotly_chart(fig_line, use_container_width=True)

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