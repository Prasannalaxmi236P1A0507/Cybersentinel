def agent_decision(row):
    """
    Agentic AI decision-making + Attack type classification
    """

    failed_logins = row.get('failed_logins', 0)
    packet_count = row.get('packet_count', 0)
    data_transfer = row.get('data_transfer', 0)

    attack_type = "Normal"

    if row.get('threat_status') == "Suspicious":

        # Attack classification
        if packet_count > 3000:
            attack_type = "DDoS Attack"

        elif failed_logins > 10:
            attack_type = "Brute Force Attack"

        elif data_transfer > 4000:
            attack_type = "Data Exfiltration"

        else:
            attack_type = "Unknown Threat"

        # Threat levels
        if failed_logins > 15 or packet_count > 4000:
            return "HIGH", "Block IP & Isolate System", attack_type

        elif failed_logins > 5:
            return "MEDIUM", "Monitor and Alert Admin", attack_type

        else:
            return "LOW", "Log Activity", attack_type

    else:
        return "NONE", "No Action Needed", attack_type