import re
from datetime import datetime


def parse_log_line(line):

    ssh_pattern = (
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
        r"sshd\[(\d+)\]: (.+)"
    )

    ssh_match = re.match(ssh_pattern, line)

    if ssh_match:

        timestamp, process_id, message = ssh_match.groups()

        event = {
            "timestamp": datetime.strptime(
                timestamp,
                "%Y-%m-%d %H:%M:%S"
            ),
            "process_id": int(process_id),
            "service": "sshd",
            "message": message
        }

        failed_match = re.search(
            r"Failed password for (\w+) from ([\d.]+)",
            message
        )

        if failed_match:

            username, source_ip = failed_match.groups()

            event.update({
                "event_type": "authentication_failure",
                "username": username,
                "source_ip": source_ip,
                "status": "failed"
            })

            return event

        success_match = re.search(
            r"Accepted password for (\w+) from ([\d.]+)",
            message
        )

        if success_match:

            username, source_ip = success_match.groups()

            event.update({
                "event_type": "authentication_success",
                "username": username,
                "source_ip": source_ip,
                "status": "success"
            })

            return event

        event["event_type"] = "unknown"

        return event

    network_pattern = (
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
        r"network: Connection from ([\d.]+) to port (\d+)"
    )

    network_match = re.match(network_pattern, line)

    if network_match:

        timestamp, source_ip, destination_port = network_match.groups()

        return {
            "timestamp": datetime.strptime(
                timestamp,
                "%Y-%m-%d %H:%M:%S"
            ),
            "service": "network",
            "event_type": "network_connection",
            "source_ip": source_ip,
            "destination_port": int(destination_port),
            "status": "connection"
        }

    return None
