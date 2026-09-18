from app.services.log_ingestion import parse_log_line
from app.detection.suspicious_login import detect_suspicious_login


events = []

with open("../sample_logs/suspicious_login.log", "r") as file:
    for line in file:
        event = parse_log_line(line.strip())

        if event:
            events.append(event)


alerts = detect_suspicious_login(events)

print("\n=== SENTINEL SUSPICIOUS LOGIN RESULTS ===\n")

for alert in alerts:
    print(f"Alert Type      : {alert['alert_type']}")
    print(f"Severity        : {alert['severity']}")
    print(f"Source IP       : {alert['source_ip']}")
    print(f"Username        : {alert['username']}")
    print(f"Failed Attempts : {alert['failed_attempts']}")
    print(f"Time Window     : {alert['window_minutes']} minutes")
    print(f"Status          : {alert['status']}")
    print()
