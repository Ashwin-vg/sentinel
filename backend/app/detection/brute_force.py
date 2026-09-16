from collections import defaultdict
from datetime import timedelta


def detect_brute_force(events, threshold=3, window_minutes=5):
    alerts = []

    failed_attempts = defaultdict(list)

    for event in events:
        if event.get("event_type") != "authentication_failure":
            continue

        source_ip = event.get("source_ip")

        if not source_ip:
            continue

        failed_attempts[source_ip].append(event)

    for source_ip, attempts in failed_attempts.items():

        attempts.sort(key=lambda x: x["timestamp"])

        for i in range(len(attempts)):

            window_start = attempts[i]["timestamp"]
            window_end = window_start + timedelta(minutes=window_minutes)

            matching_attempts = [
                event
                for event in attempts[i:]
                if event["timestamp"] <= window_end
            ]

            if len(matching_attempts) >= threshold:

                alert = {
                    "alert_type": "SSH Brute Force",
                    "severity": "HIGH",
                    "source_ip": source_ip,
                    "failed_attempts": len(matching_attempts),
                    "window_minutes": window_minutes,
                    "first_seen": matching_attempts[0]["timestamp"],
                    "last_seen": matching_attempts[-1]["timestamp"],
                    "status": "DETECTED"
                }

                alerts.append(alert)

                break

    return alerts
