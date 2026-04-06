def agent_decision(row):
    """
    Agentic AI decision-making based on ML output + rules
    """

    if row['threat_status'] == "Suspicious":
        if row['failed_logins'] > 15 or row['packet_count'] > 4000:
            return "HIGH", "Block IP & Isolate System"
        elif row['failed_logins'] > 5:
            return "MEDIUM", "Monitor and Alert Admin"
        else:
            return "LOW", "Log Activity"
    else:
        return "NONE", "No Action Needed"
