from preprocessing.preprocess import preprocess_data
from model.anomaly_model import train_model, detect_anomalies
from agent.threat_agent import agent_decision
import pandas as pd

DATA_PATH = "data/network_logs.csv"
OUTPUT_PATH = "output/detected_threats.csv"

# Phase 1: Preprocess
scaled_data, original_data = preprocess_data(DATA_PATH)

# Phase 1: ML Model
model = train_model(scaled_data)
predictions = detect_anomalies(model, scaled_data)

original_data['threat_status'] = predictions
original_data['threat_status'] = original_data['threat_status'].map(
    {1: "Normal", -1: "Suspicious"}
)

# Phase 2: Agentic AI Decisions
threat_levels = []
responses = []

for _, row in original_data.iterrows():
    level, action = agent_decision(row)
    threat_levels.append(level)
    responses.append(action)

original_data['threat_level'] = threat_levels
original_data['agent_response'] = responses

# Save output
original_data.to_csv(OUTPUT_PATH, index=False)

print("\nAgentic AI Threat Hunting Results:\n")
print(original_data)
