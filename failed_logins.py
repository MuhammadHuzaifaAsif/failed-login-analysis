import re
from collections import Counter
logfile = '/var/log/auth.log'
pattern = re.compile(r'Failed password.*from (?P<ip>\d+\.\d+\.\d+\.\d+)')
counter = Counter()
with open(logfile, 'r', errors='ignore') as f:
    for line in f:
        m = pattern.search(line)
        if m:
            counter[m.group('ip')] += 1
print("Total failed login entries:", sum(counter.values()))
print("\nTop source IPs:")
for ip, cnt in counter.most_common(10):
    print(f"{ip} - {cnt}")
