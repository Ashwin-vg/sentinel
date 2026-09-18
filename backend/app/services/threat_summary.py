def generate_threat_summary(alerts):

    if not alerts:
        return {
            "threat_level": "LOW",
            "summary": (
                "No known security threats were detected "
                "in the submitted logs."
            ),
            "detected_threats": [],
            "recommended_actions": [
                "Continue monitoring incoming security events.",
                "Review logs periodically for unusual activity."
            ]
        }


    high_count = sum(
        1
        for alert in alerts
        if alert.get("severity") == "HIGH"
    )


    medium_count = sum(
        1
        for alert in alerts
        if alert.get("severity") == "MEDIUM"
    )


    if high_count > 0:
        threat_level = "HIGH"

    elif medium_count > 0:
        threat_level = "MEDIUM"

    else:
        threat_level = "LOW"


    detected_threats = []
    recommended_actions = []


    for alert in alerts:

        alert_type = alert.get(
            "alert_type",
            "Unknown Threat"
        )

        source_ip = alert.get(
            "source_ip",
            "Unknown"
        )


        if alert_type == "SSH Brute Force":

            detected_threats.append(
                f"SSH Brute Force detected from {source_ip}"
            )


            if (
                "Review SSH authentication logs."
                not in recommended_actions
            ):
                recommended_actions.append(
                    "Review SSH authentication logs."
                )


            if (
                "Investigate repeated authentication failures."
                not in recommended_actions
            ):
                recommended_actions.append(
                    "Investigate repeated authentication failures."
                )


        elif (
            alert_type ==
            "Suspicious Login After Failed Attempts"
        ):

            username = alert.get(
                "username",
                "unknown"
            )


            detected_threats.append(
                f"Suspicious login for user {username} "
                f"from {source_ip}"
            )


            if (
                "Verify the suspicious account activity."
                not in recommended_actions
            ):
                recommended_actions.append(
                    "Verify the suspicious account activity."
                )


        elif alert_type == "Port Scan":

            ports = alert.get(
                "ports_scanned",
                0
            )


            detected_threats.append(
                f"Port Scan detected from {source_ip} "
                f"({ports} ports)"
            )


            if (
                "Investigate network reconnaissance activity."
                not in recommended_actions
            ):
                recommended_actions.append(
                    "Investigate network reconnaissance activity."
                )


        else:

            detected_threats.append(
                f"{alert_type} detected from {source_ip}"
            )


    if high_count > 0:

        summary = (
            f"Sentinel detected {len(alerts)} security alert(s), "
            f"including {high_count} high-severity alert(s). "
            "Immediate investigation is recommended."
        )

    else:

        summary = (
            f"Sentinel detected {len(alerts)} security alert(s) "
            "in the submitted logs. "
            "The detected activity should be reviewed "
            "by a security analyst."
        )


    if (
        "Investigate the source IP addresses."
        not in recommended_actions
    ):
        recommended_actions.append(
            "Investigate the source IP addresses."
        )


    return {
        "threat_level": threat_level,
        "summary": summary,
        "detected_threats": detected_threats,
        "recommended_actions": recommended_actions
    }
