#!/usr/bin/env python3
"""
detect_bruteforce.py
Simple script to flag IPs with >3 failed SSH login attempts.
Works with /var/log/auth.log format (Ubuntu/Debian).
Run with sudo if reading /var/log/auth.log, or test with a local copy.
"""

import re
import argparse
from collections import defaultdict
from datetime import datetime
import os

# Regex to match typical OpenSSH "Failed password" lines and capture IP
# Example auth.log line:
# Sep 19 22:10:01 ubuntu sshd[1234]: Failed password for invalid user test from 192.0.2.45 port 54321 ssh2
FAIL_RE = re.compile(r'Failed password for .* from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})')

ALERTS_FILE = "alerts.log"
STATE_FILE = "alerted_ips.txt"

def read_logfile(path):
    """Return lines from logfile (as list)."""
    with open(path, 'r', errors='ignore') as f:
        return f.readlines()

def extract_failed_ips(lines):
    """Return list of IPs extracted from lines that match FAIL_RE."""
    ips = []
    for line in lines:
        m = FAIL_RE.search(line)
        if m:
            ips.append(m.group('ip'))
    return ips

def count_failures(ips):
    """Return dict ip -> count."""
    counts = defaultdict(int)
    for ip in ips:
        counts[ip] += 1
    return counts

def read_alerted_ips():
    """Load previously alerted IPs to avoid duplicate alerts."""
    if not os.path.exists(STATE_FILE):
        return set()
    with open(STATE_FILE, 'r') as f:
        return set(line.strip() for line in f if line.strip())

def save_alerted_ip(ip):
    """Append IP to state file."""
    with open(STATE_FILE, 'a') as f:
        f.write(ip + "\n")

def write_alert(ip, count, sample_time=None):
    """Write alert to ALERTS_FILE with timestamp."""
    ts = sample_time or datetime.utcnow().isoformat()
    line = f"{ts} - ALERT: {ip} - failed_logins={count}\n"
    with open(ALERTS_FILE, 'a') as f:
        f.write(line)
    print(line.strip())

def main(logfile_path, threshold=3, reset_state=False):
    if reset_state and os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)

    lines = read_logfile(logfile_path)
    ips = extract_failed_ips(lines)
    counts = count_failures(ips)
    alerted = read_alerted_ips()

    for ip, cnt in counts.items():
        if cnt > threshold and ip not in alerted:
            # New alert: write to alerts log and persist state
            write_alert(ip, cnt)
            save_alerted_ip(ip)
        # else: either below threshold or already alerted

    # Summary printed to console
    print("Summary (IP -> failures):")
    for ip, cnt in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {ip} -> {cnt}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect brute force by counting failed logins per IP.")
    parser.add_argument("logfile", help="Path to auth.log (or test logfile).")
    parser.add_argument("--threshold", "-t", type=int, default=3, help="Number of failures to trigger alert (default 3).")
    parser.add_argument("--reset", action="store_true", help="Reset alerted IPs state.")
    args = parser.parse_args()

    main(args.logfile, threshold=args.threshold, reset_state=args.reset)
