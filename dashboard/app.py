import sys
import os
import random
import time
from datetime import datetime

import pandas as pd
import streamlit as st
import plotly.express as px

# FIX IMPORT PATH
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from agent.agentic_engine import run_agentic_threat_hunt


# PAGE SETTINGS
st.set_page_config(page_title="SOC Dashboard", layout="wide")

# DARK SOC THEME
st.markdown("""
<style>
.stApp{
background-color:#0f172a;
color:white;
}

h1,h2,h3{
color:#38bdf8;
}

.stButton>button{
background-color:#ef4444;
color:white;
font-weight:bold;
}

[data-testid="stMetricValue"]{
color:#22c55e;
font-size:30px;
}
</style>
""", unsafe_allow_html=True)


# TITLE
st.title("🛡 CyberSentinel")
st.write("AI-Driven Threat Monitoring System")


# RUN AGENT BUTTON
if st.button("Run Threat Hunting Agent"):

    df = run_agentic_threat_hunt("data/network_logs.csv")

    st.session_state["data"] = df


# DISPLAY RESULTS
if "data" in st.session_state:

    df = st.session_state["data"]

    # METRICS
    st.subheader("Security Overview")

    col1, col2, col3 = st.columns(3)

    col1.metric("Total IPs Analyzed", len(df))
    col2.metric("Suspicious Activities", len(df[df["threat_level"] != "LOW"]))
    col3.metric("High Risk Threats", len(df[df["threat_level"] == "HIGH"]))


    # ALERT
    high = df[df["threat_level"] == "HIGH"]

    if len(high) > 0:
        st.error("🚨 CRITICAL ALERT: High Risk Threat Detected")
    else:
        st.success("✅ Network Status: Secure")


    # THREAT TABLE
    st.subheader("🔍 Threat Investigation Table")
    st.dataframe(df)


    # CREATE CHART DATA
    threat_counts = df["threat_level"].value_counts().reset_index()
    threat_counts.columns = ["threat_level", "count"]


    fig1 = px.bar(
        threat_counts,
        x="threat_level",
        y="count",
        color="threat_level",
        title="Threat Level Distribution"
    )


    fig2 = px.pie(
        df,
        names="attack_type",
        title="Attack Type Distribution"
    )


    fig3 = px.line(
        df,
        y="packet_count",
        title="Packet Traffic Trend"
    )


    # CHART LAYOUT
    col1, col2 = st.columns(2)

    with col1:
        st.plotly_chart(fig1, use_container_width=True)

    with col2:
        st.plotly_chart(fig2, use_container_width=True)

    st.plotly_chart(fig3, use_container_width=True)


# LIVE ATTACK FEED
st.subheader("🔴 Live Attack Feed")

if "live_attacks" not in st.session_state:
    st.session_state.live_attacks = []


ips = [
"192.168.1.101",
"192.168.1.202",
"192.168.1.150",
"192.168.1.88"
]

attacks = [
"DDoS Attack",
"Brute Force Attack",
"Port Scan",
"Malware Traffic"
]

new_attack = {
"time": datetime.now().strftime("%H:%M:%S"),
"ip": random.choice(ips),
"attack": random.choice(attacks)
}

st.session_state.live_attacks.append(new_attack)

live_df = pd.DataFrame(st.session_state.live_attacks)

st.table(live_df.tail(6))


# AUTO REFRESH
time.sleep(5)
st.rerun()