from collections import defaultdict
from datetime import timedelta


def detect_failed_login_threshold(
    events,
    threshold=5,
    timeframe_seconds=60,
):
    failed_logins = defaultdict(list)
    alerts = []

    for event in events:
        if event["event_type"] != "ssh_failed_login":
            continue

        source_ip = event["source_ip"]
        timestamp = event["timestamp"]

        if source_ip is None or timestamp is None:
            continue

        failed_logins[source_ip].append(timestamp)

    for source_ip, timestamps in failed_logins.items():
        timestamps.sort()

        for index, start_time in enumerate(timestamps):
            end_time = start_time + timedelta(seconds=timeframe_seconds)

            attempts = [
                timestamp
                for timestamp in timestamps[index:]
                if timestamp <= end_time
            ]

            if len(attempts) >= threshold:
                alerts.append(
                    {
                        "rule_id": "SIEM-SSH-001",
                        "severity": "WARNING",
                        "source_ip": source_ip,
                        "attempts": len(attempts),
                        "timeframe_seconds": timeframe_seconds,
                        "message": (
                            "Multiple failed SSH login attempts detected"
                        ),
                    }
                )

                break

    return alerts