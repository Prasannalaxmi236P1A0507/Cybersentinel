def agent_decision(row):
    """
    Agentic AI decision-making based on ML output + rules
    (Safe version to avoid column errors)
    """

    # Safe access (prevents KeyError)
    failed_logins = row.get('failed_logins', 0)
    packet_count = row.get('packet_count', 0)

    if row.get('threat_status') == "Suspicious":

        if failed_logins > 15 or packet_count > 4000:
            return "HIGH", "Block IP & Isolate System"

        elif failed_logins > 5:
            return "MEDIUM", "Monitor and Alert Admin"

        else:
            return "LOW", "Log Activity"

    else:
        return "NONE", "No Action Needed"