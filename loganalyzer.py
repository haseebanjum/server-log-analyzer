#!/usr/bin/env python3
"""Server log analyzer - nginx / Apache combined access logs.

Usage:
    python loganalyzer.py /var/log/nginx/access.log
    python loganalyzer.py access.log --top 20
    python loganalyzer.py access.log --json > report.json

Reads a combined-format access log and prints a summary: status-code
breakdown, top IPs, top paths, 404s, 5xx errors, hourly traffic, and IPs
with suspicious 404 bursts (possible scanning of your own server).

Only the Python standard library is required. Python 3.8+.
"""

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime

LOG_RE = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d{3}) (\d+|-) "[^"]*" "([^"]*)"'
)
TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"
SUSPICIOUS_404_THRESHOLD = 20


def parse_line(line):
    """Parse one combined-log line. Returns a dict or None if unparseable."""
    m = LOG_RE.match(line)
    if not m:
        return None
    ip, ts, method, path, status, size, ua = m.groups()
    try:
        dt = datetime.strptime(ts, TIME_FMT)
    except ValueError:
        dt = None
    return {
        "ip": ip,
        "time": dt,
        "method": method,
        "path": path.split("?")[0],
        "status": int(status),
        "bytes": 0 if size == "-" else int(size),
        "ua": ua,
    }


def analyze(lines):
    """Aggregate parsed log lines into a report dict."""
    status = Counter()
    status_class = Counter()
    ips = Counter()
    paths = Counter()
    uas = Counter()
    not_found = Counter()
    ip_404 = Counter()
    hourly = Counter()
    error_5xx = []
    total = 0
    skipped = 0
    first_time = None
    last_time = None

    for line in lines:
        line = line.strip()
        if not line:
            continue
        entry = parse_line(line)
        if entry is None:
            skipped += 1
            continue
        total += 1
        status[entry["status"]] += 1
        status_class[f"{entry['status'] // 100}xx"] += 1
        ips[entry["ip"]] += 1
        paths[(entry["method"], entry["path"])] += 1
        uas[entry["ua"]] += 1
        if entry["status"] == 404:
            not_found[entry["path"]] += 1
            ip_404[entry["ip"]] += 1
        if 500 <= entry["status"] <= 599 and len(error_5xx) < 5:
            error_5xx.append(
                f"{entry['ip']} {entry['method']} {entry['path']} -> {entry['status']}"
            )
        if entry["time"] is not None:
            hourly[entry["time"].strftime("%Y-%m-%d %H:00")] += 1
            if first_time is None or entry["time"] < first_time:
                first_time = entry["time"]
            if last_time is None or entry["time"] > last_time:
                last_time = entry["time"]

    suspicious = {
        ip: count
        for ip, count in ip_404.items()
        if count >= SUSPICIOUS_404_THRESHOLD
    }

    return {
        "total_requests": total,
        "skipped_lines": skipped,
        "first_request": first_time.isoformat() if first_time else None,
        "last_request": last_time.isoformat() if last_time else None,
        "status_codes": dict(status),
        "status_classes": dict(status_class),
        "top_ips": ips.most_common(10),
        "top_paths": [
            (f"{method} {path}", count)
            for (method, path), count in paths.most_common(10)
        ],
        "top_user_agents": uas.most_common(5),
        "top_404_paths": not_found.most_common(10),
        "error_5xx_count": status_class.get("5xx", 0),
        "error_5xx_samples": error_5xx,
        "hourly": dict(sorted(hourly.items())),
        "suspicious_ips": suspicious,
    }


def print_report(data, top):
    """Print a human-readable summary."""
    print(f"Total requests: {data['total_requests']}")
    if data["skipped_lines"]:
        print(f"Skipped unparseable lines: {data['skipped_lines']}")
    if data["first_request"]:
        print(f"Time range: {data['first_request']} -> {data['last_request']}")
    print()
    print("Status classes:")
    for cls in ("2xx", "3xx", "4xx", "5xx"):
        if cls in data["status_classes"]:
            print(f"  {cls}: {data['status_classes'][cls]}")
    print()
    print(f"Top {top} IPs:")
    for ip, count in data["top_ips"][:top]:
        print(f"  {count:>6}  {ip}")
    print()
    print(f"Top {top} paths:")
    for path, count in data["top_paths"][:top]:
        print(f"  {count:>6}  {path}")
    print()
    print("Top 404 paths:")
    for path, count in data["top_404_paths"][:top]:
        print(f"  {count:>6}  {path}")
    print()
    print(f"5xx errors: {data['error_5xx_count']}")
    for sample in data["error_5xx_samples"]:
        print(f"  {sample}")
    print()
    print("Requests per hour:")
    for hour, count in data["hourly"].items():
        print(f"  {hour}: {count}")
    print()
    if data["suspicious_ips"]:
        print("Suspicious IPs (20+ 404s, possible scanning):")
        for ip, count in data["suspicious_ips"].items():
            print(f"  {ip}: {count} 404s")
    else:
        print("Suspicious IPs: none")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze nginx / Apache combined access logs."
    )
    parser.add_argument("logfile", help="Path to the access log file")
    parser.add_argument(
        "--top", type=int, default=10, help="How many top entries to show (default: 10)"
    )
    parser.add_argument(
        "--json", action="store_true", help="Output machine-readable JSON instead of text"
    )
    args = parser.parse_args()

    try:
        with open(args.logfile, "r", encoding="utf-8", errors="replace") as f:
            data = analyze(f)
    except FileNotFoundError:
        print(f"Error: file not found: {args.logfile}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"Error reading {args.logfile}: {e}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(data, indent=2, default=str))
    else:
        print_report(data, args.top)


if __name__ == "__main__":
    main()
