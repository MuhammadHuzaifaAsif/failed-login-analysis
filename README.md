```bash
cat > .gitignore <<'GITIGNORE'
# runtime files
alerts.log
alerted_ips.txt

# python cache
__pycache__/
*.pyc

# system files
.DS_Store
GITIGNORE

# brute-force-detector
