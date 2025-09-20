

Author: Muhammad Huzaifa Asif  
Date: 2025-09-18 (example)

# Project summary
This project parses Linux authentication logs (`/var/log/auth.log`) to detect brute force SSH login attempts.  
It counts failed login attempts per source IP and reports any IP with **>= 3** failed attempts. The script writes a report to `~/security_lab/bruteforce_report.txt`.

# Tools & Tech
- Language: Python 3  
- Platform: Ubuntu Linux (VM)  
- Files: `/var/log/auth.log` (source logs)  
- Output: `~/security_lab/bruteforce_report.txt`

# How it works
1. The script searches lines that contain `Failed password` and extracts the source IP with a regex.  
2. It counts failed attempts per IP using a dictionary.  
3. IPs with counts >= 3 are considered suspicious and are printed and written to the report file.

# Usage (safe steps)
>Note: Reading `/var/log/auth.log` requires root privileges. Use `sudo` to run the script, or copy a log to your home directory and run the script without sudo.

```bash
# Run with sudo (recommended)
cd ~/security_lab/scripts
sudo python3 detect_bruteforce.py

# Or, copy auth.log to your home (one-time) and run normally:
sudo cp /var/log/auth.log ~/security_lab/auth.log
sudo chown $USER:$USER ~/security_lab/auth.log
# then edit detect_bruteforce.py to read ~/security_lab/auth.log and run:
python3 detect_bruteforce.py
