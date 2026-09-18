from datetime import timedelta


def detect_suspicious_login(events, threshold=3, window_minutes=5):
    alerts = []

    failed_attempts = {}

    for event in events:
        if event.get("event_type") != "authentication_failure":
            continue

        ip = event.get("source_ip")

        if not ip:
            continue

        failed_attempts.setdefault(ip, []).append(event)

    for event in events:

        if event.get("event_type") != "authentication_success":
            continue

        ip = event.get("source_ip")

        if ip not in failed_attempts:
            continue

        success_time = event["timestamp"]

        recent_failures = [
            failure
            for failure in failed_attempts[ip]
            if failure["timestamp"] <= success_time
            and success_time - failure["timestamp"]
            <= timedelta(minutes=window_minutes)
        ]

        if len(recent_failures) >= threshold:

            alerts.append({
                "alert_type": "Suspicious Login After Failed Attempts",
                "severity": "HIGH",
                "source_ip": ip,
                "username": event.get("username"),
                "failed_attempts": len(recent_failures),
                "window_minutes": window_minutes,
                "timestamp": success_time,
                "status": "DETECTED"
            })

    return alerts
