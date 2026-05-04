import streamlit as st
import pandas as pd
from preprocessing.preprocess import preprocess_data
from model.anomaly_model import train_model, detect_anomalies
from agent.threat_agent import agent_decision

# Page configuration
st.set_page_config(page_title="CyberSentinel", layout="wide")

# Title
st.title("🔐 CyberSentinel - AI Threat Detection System")
st.markdown("### 🚀 Autonomous Security Operations Dashboard")

# Sidebar
st.sidebar.header("⚙️ Settings")
st.sidebar.info("Upload a network log CSV file to begin analysis")

# File uploader
uploaded_file = st.file_uploader("📂 Upload Network Logs CSV", type=["csv"])

# Main logic
if uploaded_file is not None:

    # Read uploaded file
    data = pd.read_csv(uploaded_file)

    st.subheader("📄 Uploaded Data Preview")
    st.dataframe(data.head())

    # Preprocessing
    scaled_data, original_data = preprocess_data(uploaded_file)

    # Train ML model
    model = train_model(scaled_data)

    # Detect anomalies
    predictions = detect_anomalies(model, scaled_data)

    # Add results
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

    # Success message
    st.success("✅ Analysis Completed Successfully!")

    # Charts
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📊 Threat Status Distribution")
        st.bar_chart(original_data['threat_status'].value_counts())

    with col2:
        st.subheader("⚠️ Threat Level Distribution")
        st.bar_chart(original_data['threat_level'].value_counts())

    # Final table
    st.subheader("📋 Detailed Results")
    st.dataframe(original_data)

else:
    st.warning("⚠️ Please upload a CSV file to start analysis")