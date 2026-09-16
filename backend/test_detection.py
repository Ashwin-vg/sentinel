from app.services.log_ingestion import parse_log_line
from app.detection.brute_force import detect_brute_force


events = []

with open("../sample_logs/auth.log", "r") as file:

    for line in file:
        event = parse_log_line(line.strip())

        if event:
            events.append(event)


alerts = detect_brute_force(events)


print("\n=== SENTINEL DETECTION RESULTS ===\n")

for alert in alerts:

    print(f"Alert Type      : {alert['alert_type']}")
    print(f"Severity        : {alert['severity']}")
    print(f"Source IP       : {alert['source_ip']}")
    print(f"Failed Attempts : {alert['failed_attempts']}")
    print(f"Time Window     : {alert['window_minutes']} minutes")
    print(f"Status          : {alert['status']}")
    print()
