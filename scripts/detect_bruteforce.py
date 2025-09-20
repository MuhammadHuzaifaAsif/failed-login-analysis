#!/usr/bin/env python3
import re
from collections import defaultdict
import os
from pathlib import Path

# Path to auth log (read-only for regular users; run the script with sudo if needed)
log_file = "/var/log/auth.log"

# Prepare output folder in your home directory
home = str(Path.home())
out_dir = os.path.join(home, "security_lab")
os.makedirs(out_dir, exist_ok=True)
report_path = os.path.join(out_dir, "bruteforce_report.txt")

failed_attempts = defaultdict(int)

# Regex to extract IP addresses from "Failed password" lines
pattern = re.compile(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")

try:
    with open(log_file, "r") as f:
        for line in f:
            match = pattern.search(line)
            if match:
                ip = match.group(1)
                failed_attempts[ip] += 1
except PermissionError:
    print(f"PermissionError: cannot read {log_file}. Run this script with sudo or give read access to the log (not recommended).")
    exit(1)

suspicious = {ip: cnt for ip, cnt in failed_attempts.items() if cnt >= 3}

print("🔍 Suspicious IPs with brute force attempts:")
if suspicious:
    for ip, count in suspicious.items():
        print(f"{ip} → {count} failed attempts")
else:
    print("No IPs with >=3 failed attempts found.")

# Write report
with open(report_path, "w") as report:
    if suspicious:
        report.write("Suspicious IPs with brute force attempts:\n")
        for ip, count in suspicious.items():
            report.write(f"{ip} → {count} failed attempts\n")
    else:
        report.write("No IPs with >=3 failed attempts found.\n")

print(f"\nReport written to: {report_path}")
