from app.services.log_ingestion import parse_log_line
from app.detection.engine import run_detection_engine


events = []

log_files = [
    "../sample_logs/auth.log",
    "../sample_logs/suspicious_login.log",
    "../sample_logs/network.log"
]


for log_file in log_files:

    with open(log_file, "r") as file:

        for line in file:

            event = parse_log_line(line.strip())

            if event:
                events.append(event)


alerts = run_detection_engine(events)


print("\n=== SENTINEL SECURITY ALERTS ===\n")

print(f"Total Events : {len(events)}")
print(f"Total Alerts : {len(alerts)}")

print("\n----------------------------------------\n")


for index, alert in enumerate(alerts, start=1):

    print(f"ALERT #{index}")
    print(f"Type       : {alert['alert_type']}")
    print(f"Severity   : {alert['severity']}")
    print(f"Source IP  : {alert['source_ip']}")

    if "username" in alert:
        print(f"Username   : {alert['username']}")

    if "ports_scanned" in alert:
        print(f"Ports      : {alert['ports_scanned']}")

    print(f"Status     : {alert['status']}")
    print()
