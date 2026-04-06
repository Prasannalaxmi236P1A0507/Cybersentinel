import pandas as pd
import os
from datetime import datetime

def run_agentic_threat_hunt(data_path):

    os.makedirs("reports", exist_ok=True)

    df = pd.read_csv(data_path)

    threat_levels = []
    responses = []
    explanations = []
    attack_types = []
    timestamps = []

    for _, row in df.iterrows():

        if row["packet_count"] > 5000:
            threat_levels.append("HIGH")
            responses.append("Block IP & Isolate System")
            explanations.append("Extremely high packet traffic detected")
            attack_types.append("Possible DDoS Attack")

        elif row["failed_logins"] > 15:
            threat_levels.append("HIGH")
            responses.append("Block IP & Investigate")
            explanations.append("Multiple failed login attempts detected")
            attack_types.append("Brute Force Attack")

        elif row["packet_count"] > 3000:
            threat_levels.append("MEDIUM")
            responses.append("Monitor Traffic")
            explanations.append("Unusual traffic spike detected")
            attack_types.append("Suspicious Activity")

        else:
            threat_levels.append("LOW")
            responses.append("No Action Needed")
            explanations.append("Normal traffic behaviour")
            attack_types.append("Normal")

        timestamps.append(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    df["threat_level"] = threat_levels
    df["agent_response"] = responses
    df["why_risky"] = explanations
    df["attack_type"] = attack_types
    df["timestamp"] = timestamps

    df.to_csv("reports/threat_report.csv", index=False)

    return df