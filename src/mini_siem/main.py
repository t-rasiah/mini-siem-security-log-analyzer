from pathlib import Path

from detection import detect_failed_login_threshold
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


def main():
    logfile = "/vagrant/tests/sample_logs/ssh_failed.log"

    print("[INFO] Mini-SIEM Security Log Analyzer")
    print(f"[INFO] Reading: {logfile}")

    events = load_events(logfile)

    print(f"[INFO] Parsed events: {len(events)}")

    alerts = detect_failed_login_threshold(events)

    if not alerts:
        print("[INFO] No security alerts detected.")
        return

    for alert in alerts:
        print()
        print("=" * 50)
        print("[SECURITY ALERT]")
        print(f"Rule:     {alert['rule_id']}")
        print(f"Severity: {alert['severity']}")
        print(f"Source:   {alert['source_ip']}")
        print(f"Attempts: {alert['attempts']}")
        print(f"Message:  {alert['message']}")
        print("=" * 50)


if __name__ == "__main__":
    main()