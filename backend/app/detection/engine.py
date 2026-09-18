from app.detection.brute_force import detect_brute_force
from app.detection.suspicious_login import detect_suspicious_login
from app.detection.port_scan import detect_port_scan


def run_detection_engine(events):

    alerts = []

    detectors = [
        detect_brute_force,
        detect_suspicious_login,
        detect_port_scan
    ]

    for detector in detectors:

        detected_alerts = detector(events)

        if detected_alerts:
            alerts.extend(detected_alerts)

    return alerts
