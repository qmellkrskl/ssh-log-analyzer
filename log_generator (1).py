"""
log_generator.py
-----------------
Generates a realistic sample SSH authentication log (similar to /var/log/auth.log
on a Linux server) so log_analyzer.py can be tested without needing access to a
real production server.

The generated log includes:
Normal successful logins from known IPs
A brute-force attack pattern (many failed attempts from one IP in a short time)
A handful of scattered failed attempts from random IPs (background noise)
Some invalid username attempts (a common attack signature)# SSH Log Analyzer & Brute-Force Detector

A Python tool that parses SSH authentication logs (`auth.log` style) and
detects brute-force login attempts and other suspicious activity, then
generates a readable security report.

## Why this project

Servers exposed to the internet are constantly probed by automated bots
trying common usernames and passwords. This tool demonstrates a small but
realistic piece of a security monitoring pipeline: log parsing, pattern
detection, and reporting — the same building blocks used in real SIEM /
intrusion-detection tooling.

## How it works

1. **`log_generator.py`** creates a realistic sample `auth.log` with normal
   traffic, a fast brute-force attack, a slow/low-profile attack, and
   background noise so the analyzer can be tested without a real server.
2. **`log_analyzer.py`**:
   - Parses each log line with regex to extract timestamp, event type,
     username, and source IP.
   - Groups failed login attempts by IP and applies a **sliding time-window**
     check: if an IP has more than N failed attempts within a configurable
     number of minutes, it's flagged as a brute-force source.
   - Flags "invalid user" attempts (a common automated-attack signature).
   - Cross-references flagged IPs against successful logins, to highlight
     if an attacker IP ever succeeded in logging in.
   - Outputs a human-readable report (console and/or file).

## Usage

```bash
# 1. Generate a sample log to test with
python log_generator.py

# 2. Analyze it
python log_analyzer.py sample_auth.log

# 3. Or save the report to a file
python log_analyzer.py sample_auth.log --report report.txt
```



```bash
python log_analyzer.py /var/log/auth.log --report daily_report.txt
```

## Configuration

Two constants at the top of `log_analyzer.py` control sensitivity:

```python
FAILED_ATTEMPT_THRESHOLD = 10   # failed attempts...
TIME_WINDOW_MINUTES = 5         # ...within this many minutes = brute force
```


============================================================
SSH LOG ANALYSIS REPORT
============================================================
Generated: 2026-10-28 11:43:32

-- Summary --
Successful logins : 30
Failed attempts   : 133
Invalid user tries: 27
Unique IPs (failed): 5
-------

--  BRUTE-FORCE SOURCES DETECTED --

IP: 203.0.113.77
  Failed attempts : 93
  Time span       : 5.0 minutes
  First seen      : 2026-10-28 13:24:35
  Last seen       : 2026-10-28 13:29:35
  Usernames tried : admin, guest, oracle, pi, root, test, ubuntu, user


-- Successful logins after suspicious activity (review these) --
  2026-10-28 13:58:33  user=melike  ip=192.168.1.10
  2026-10-28 14:00:33  user=backup  ip=192.168.1.14
  2026-10-28 14:05:33  user=melike  ip=10.0.0.5
  2026-10-28 14:10:33  user=melike  ip=192.168.1.14
  2026-10-28 14:15:33  user=admin  ip=192.168.1.14
  2026-10-28 14:18:33  user=admin  ip=192.168.1.14
  2026-10-28 14:23:33  user=admin  ip=10.0.0.5
  2026-10-28 14:25:33  user=backup  ip=10.0.0.5
  2026-10-28 14:32:33  user=deploy  ip=192.168.1.14
  2026-10-28 14:39:33  user=deploy  ip=192.168.1.14

============================================================

"""

import random
from datetime import datetime, timedelta

# A small pool of "legitimate" users and IPs, plus attacker IPs/usernames
LEGIT_USERS = ["melike", "admin", "deploy", "backup"]
LEGIT_IPS = ["192.168.1.10", "192.168.1.14", "10.0.0.5"]

ATTACKER_IPS = ["203.0.113.77", "185.220.101.5", "45.155.205.12"]
GUESSED_USERNAMES = ["root", "admin", "test", "ubuntu", "oracle", "pi", "guest", "user"]

OUTPUT_FILE = "sample_auth.log"


def format_line(ts: datetime, message: str) -> str:

    return f"{ts.strftime('%b %d %H:%M:%S')} server sshd[{random.randint(1000, 9999)}]: {message}"


def generate_log(num_lines_target: int = 300) -> list[str]:
    lines = []
    current_time = datetime.now() - timedelta(hours=2)


    for _ in range(20):
        current_time += timedelta(minutes=random.randint(1, 10))
        user = random.choice(LEGIT_USERS)
        ip = random.choice(LEGIT_IPS)
        lines.append(format_line(current_time, f"Accepted password for {user} from {ip} port {random.randint(30000,60000)} ssh2"))


    for _ in range(15):
        current_time += timedelta(minutes=random.randint(1, 15))
        user = random.choice(LEGIT_USERS)
        ip = random.choice(LEGIT_IPS)
        lines.append(format_line(current_time, f"Failed password for {user} from {ip} port {random.randint(30000,60000)} ssh2"))


    attack_ip = ATTACKER_IPS[0]
    attack_start = current_time + timedelta(minutes=5)
    t = attack_start
    for _ in range(120):
        t += timedelta(seconds=random.randint(1, 4))
        user = random.choice(GUESSED_USERNAMES)
        if random.random() < 0.3:
            lines.append(format_line(t, f"Invalid user {user} from {attack_ip} port {random.randint(30000,60000)}"))
        else:
            lines.append(format_line(t, f"Failed password for {user} from {attack_ip} port {random.randint(30000,60000)} ssh2"))
    current_time = t


    attack_ip_2 = ATTACKER_IPS[1]
    t2 = current_time + timedelta(minutes=3)
    for _ in range(25):
        t2 += timedelta(seconds=random.randint(20, 90))
        user = random.choice(GUESSED_USERNAMES)
        lines.append(format_line(t2, f"Failed password for invalid user {user} from {attack_ip_2} port {random.randint(30000,60000)} ssh2"))
    current_time = t2


    for _ in range(10):
        current_time += timedelta(minutes=random.randint(2, 8))
        user = random.choice(LEGIT_USERS)
        ip = random.choice(LEGIT_IPS)
        lines.append(format_line(current_time, f"Accepted password for {user} from {ip} port {random.randint(30000,60000)} ssh2"))


    return lines


if __name__ == "__main__":
    log_lines = generate_log()
    with open(OUTPUT_FILE, "w") as f:
        f.write("\n".join(log_lines) + "\n")
    print(f"{len(log_lines)} lines of example log written '{OUTPUT_FILE}' .")
