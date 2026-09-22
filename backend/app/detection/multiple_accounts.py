from collections import defaultdict
from datetime import timedelta


def detect_multiple_account_attempts(
    events,
    account_threshold=3,
    window_minutes=5
):
    alerts = []

    attempts = defaultdict(list)

    for event in events:

        if event.get("event_type") != "authentication_failure":
            continue

        source_ip = event.get("source_ip")
        username = event.get("username")

        if not source_ip or not username:
            continue

        attempts[source_ip].append(event)

    for source_ip, events_for_ip in attempts.items():

        events_for_ip.sort(
            key=lambda x: x["timestamp"]
        )

        for i in range(len(events_for_ip)):

            start_time = events_for_ip[i]["timestamp"]

            end_time = (
                start_time +
                timedelta(minutes=window_minutes)
            )

            window = [
                event
                for event in events_for_ip[i:]
                if event["timestamp"] <= end_time
            ]

            usernames = {
                event["username"]
                for event in window
            }

            if len(usernames) >= account_threshold:

                alerts.append({
                    "alert_type": "Multiple Account Authentication Attempts",
                    "severity": "HIGH",
                    "source_ip": source_ip,
                    "accounts_targeted": len(usernames),
                    "usernames": sorted(usernames),
                    "window_minutes": window_minutes,
                    "first_seen": window[0]["timestamp"],
                    "last_seen": window[-1]["timestamp"],
                    "status": "DETECTED"
                })

                break

    return alerts
