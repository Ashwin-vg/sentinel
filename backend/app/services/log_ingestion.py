import re
from datetime import datetime


def parse_log_line(line):
    pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) sshd\[(\d+)\]: (.+)"

    match = re.match(pattern, line)

    if not match:
        return None

    timestamp, process_id, message = match.groups()

    event = {
        "timestamp": datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S"),
        "process_id": int(process_id),
        "service": "sshd",
        "message": message,
    }

    failed_match = re.search(
        r"Failed password for (\w+) from ([\d.]+)",
        message
    )

    if failed_match:
        username, source_ip = failed_match.groups()

        event["event_type"] = "authentication_failure"
        event["username"] = username
        event["source_ip"] = source_ip
        event["status"] = "failed"

        return event

    success_match = re.search(
        r"Accepted password for (\w+) from ([\d.]+)",
        message
    )

    if success_match:
        username, source_ip = success_match.groups()

        event["event_type"] = "authentication_success"
        event["username"] = username
        event["source_ip"] = source_ip
        event["status"] = "success"

        return event

    event["event_type"] = "unknown"

    return event
