from pathlib import Path

from detection import (
    detect_failed_login_threshold,
    detect_invalid_user,
)
from parser import parse_line


def load_events(logfile):
    path = Path(logfile)

    if not path.exists():
        print(f"[ERROR] Logfile not found: {path}")
        return []

    events = []

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            event = parse_line(line)

            if event["event_type"] != "unknown":
                events.append(event)

    return events


def print_alert(alert):
    print()
    print("=" * 50)
    print("[SECURITY ALERT]")
    print(f"Rule:     {alert['rule_id']}")
    print(f"Severity: {alert['severity']}")
    print(f"Source:   {alert['source_ip']}")

    if "username" in alert:
        print(f"User:     {alert['username']}")

    if "attempts" in alert:
        print(f"Attempts: {alert['attempts']}")

    print(f"Message:  {alert['message']}")
    print("=" * 50)


def main():
    logfile = "/vagrant/tests/sample_logs/ssh_invalid_user.log"

    print("[INFO] Mini-SIEM Security Log Analyzer")
    print(f"[INFO] Reading: {logfile}")

    events = load_events(logfile)

    print(f"[INFO] Parsed events: {len(events)}")

    warning_alerts = detect_failed_login_threshold(
        events=events,
        threshold=5,
        timeframe_seconds=60,
        rule_id="SIEM-SSH-001",
        severity="WARNING",
        message="Multiple failed SSH login attempts detected",
    )

    critical_alerts = detect_failed_login_threshold(
        events=events,
        threshold=10,
        timeframe_seconds=300,
        rule_id="SIEM-SSH-002",
        severity="CRITICAL",
        message="Possible SSH brute-force attack detected",
    )

    invalid_user_alerts = detect_invalid_user(events)


    alerts = warning_alerts + critical_alerts + invalid_user_alerts

    if not alerts:
        print("[INFO] No security alerts detected.")
        return

    for alert in alerts:
        print_alert(alert)


if __name__ == "__main__":
    main()