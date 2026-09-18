from collections import defaultdict
from datetime import timedelta


def detect_port_scan(events, port_threshold=5, window_seconds=60):
    alerts = []

    connections = defaultdict(list)

    for event in events:
        if event.get("event_type") != "network_connection":
            continue

        source_ip = event.get("source_ip")
        destination_port = event.get("destination_port")

        if not source_ip or not destination_port:
            continue

        connections[source_ip].append(event)

    for source_ip, attempts in connections.items():

        attempts.sort(key=lambda x: x["timestamp"])

        for i in range(len(attempts)):

            start_time = attempts[i]["timestamp"]
            end_time = start_time + timedelta(seconds=window_seconds)

            window = [
                event
                for event in attempts[i:]
                if event["timestamp"] <= end_time
            ]

            unique_ports = {
                event["destination_port"]
                for event in window
            }

            if len(unique_ports) >= port_threshold:

                alerts.append({
                    "alert_type": "Port Scan",
                    "severity": "MEDIUM",
                    "source_ip": source_ip,
                    "ports_scanned": len(unique_ports),
                    "window_seconds": window_seconds,
                    "timestamp": start_time,
                    "status": "DETECTED"
                })

                break

    return alerts
