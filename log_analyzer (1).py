"""
log_analyzer.py
----------------
Parses an SSH authentication log (auth.log style) and detects suspicious
activity, most importantly brute-force login attempts.

Detection logic:
  1. Parse each line with a regex to extract timestamp, event type, username,
     and source IP.
  2. Group failed attempts by IP address.
  3. Flag an IP as a brute-force source if it has more than FAILED_ATTEMPT_THRESHOLD
     failed attempts within a TIME_WINDOW_MINUTES window.
  4. Also flag IPs that repeatedly try "invalid user" (usernames that don't exist
     on the system) - a common automated-attack signature.
  5. Produce a human-readable summary report.

Usage:
    python log_analyzer.py sample_auth.log
    python log_analyzer.py sample_auth.log --report report.txt
"""

import re # regex
import argparse # read the log file name from the command line
from datetime import datetime  # turn log text into real date and time objects
from collections import defaultdict  #  auto-creates a list for new keys


FAILED_ATTEMPT_THRESHOLD = 10   # how many failed attempts
TIME_WINDOW_MINUTES = 5         # how many failed attempts within this many minutes 
CURRENT_YEAR = datetime.now().year

# Regex patterns 
# Matches: "Oct 28 13:24:39 server sshd[9205]: Failed password for admin from 203.0.113.77 port 40022 ssh2"
FAILED_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+"                    # month 3 letters (Oct)
    r"(?P<day>\d+)\s+"                         # day of the month (28)
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"          # time HH:MM:SS (13:24:39)
    r"\S+\s+"                                  # hostname (server)
    r"sshd\[\d+\]:\s+"                         # service name and process ID (sshd[9205]:)
    r"Failed password for (?:invalid user )?"  # fixed text, "invalid user" is optional
    r"(?P<user>\S+) from "                     # username that was tried (admin)
    r"(?P<ip>[\d.]+) port \d+"                 # source IP (203.0.113.77) and port number
)


INVALID_USER_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+"                    # month, 3 letters (Oct)
    r"(?P<day>\d+)\s+"                         # day of the month (28)
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"          # time HH:MM:SS (13:24:40)
    r"\S+\s+"                                  # hostname (server), not saved
    r"sshd\[\d+\]:\s+"                         # service name and process ID (sshd[3967]:)
    r"Invalid user "                           # fixed text: this username does not exist on the server
    r"(?P<user>\S+) from "                     # username that was tried (test)
    r"(?P<ip>[\d.]+) port \d+"                 # source IP (203.0.113.77) and port number
)

# Matches: "Oct 28 13:58:33 server sshd[1111]: Accepted password for melike from 192.168.1.10 port 35941 ssh2"
ACCEPTED_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+"                    # month, 3 letters (Oct)
    r"(?P<day>\d+)\s+"                         # day of the month (28)
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"          # time HH:MM:SS (13:58:33)
    r"\S+\s+"                                  # hostname (server), not saved
    r"sshd\[\d+\]:\s+"                         # service name and process ID (sshd[1111]:)
    r"Accepted password for "                  # fixed text: the login was successful
    r"(?P<user>\S+) from "                     # user who logged in (melike)
    r"(?P<ip>[\d.]+) port \d+"                 # source IP (192.168.1.10) and port number
)

def parse_timestamp(month: str, day: str, time_str: str) -> datetime:
    """Convert log's 'Mon DD HH:MM:SS' format into a real datetime object."""
    dt_str = f"{CURRENT_YEAR} {month} {int(day):02d} {time_str}"
    return datetime.strptime(dt_str, "%Y %b %d %H:%M:%S")


def parse_log(filepath: str) -> dict:
    """
    Reads the log file and returns structured events:
      {
        "failed": [(datetime, user, ip), ...],
        "invalid_user": [(datetime, user, ip), ...],
        "accepted": [(datetime, user, ip), ...],
      }
    """
    events = {"failed": [], "invalid_user": [], "accepted": []}

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            m = FAILED_PATTERN.match(line)
            if m:
                ts = parse_timestamp(m["month"], m["day"], m["time"])
                events["failed"].append((ts, m["user"], m["ip"]))
                continue

            m = INVALID_USER_PATTERN.match(line)
            if m:
                ts = parse_timestamp(m["month"], m["day"], m["time"])
                events["invalid_user"].append((ts, m["user"], m["ip"]))
                continue

            m = ACCEPTED_PATTERN.match(line)
            if m:
                ts = parse_timestamp(m["month"], m["day"], m["time"])
                events["accepted"].append((ts, m["user"], m["ip"]))
                continue

    return events


def detect_brute_force(failed_events: list) -> dict:
    """
    Groups failed attempts by IP, then checks if any IP crosses the
    threshold within the configured time window. Returns a dict of
    {ip: {"count": N, "first_seen": dt, "last_seen": dt, "users_tried": set}}
    for every IP flagged as a brute-force source.
    """
    by_ip = defaultdict(list)
    for ts, user, ip in failed_events:
        by_ip[ip].append((ts, user))

    flagged = {}
    for ip, attempts in by_ip.items():
        attempts.sort(key=lambda x: x[0])
        for i in range(len(attempts)):
            window_start = attempts[i][0]
            window_end_limit = window_start.timestamp() + TIME_WINDOW_MINUTES * 60
            count_in_window = sum(
                1 for ts, _ in attempts[i:] if ts.timestamp() <= window_end_limit
            )
            if count_in_window >= FAILED_ATTEMPT_THRESHOLD:
                flagged[ip] = {
                    "count": len(attempts),
                    "first_seen": attempts[0][0],
                    "last_seen": attempts[-1][0],
                    "users_tried": sorted(set(u for _, u in attempts)),
                }
                break  

    return flagged


def build_report(events: dict, flagged: dict) -> str:
    lines = []
    lines.append("=" * 60)
    lines.append("SSH LOG ANALYSIS REPORT")
    lines.append("=" * 60)
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    lines.append("-- Summary --")
    lines.append(f"Successful logins : {len(events['accepted'])}")
    lines.append(f"Failed attempts   : {len(events['failed'])}")
    lines.append(f"Invalid user tries: {len(events['invalid_user'])}")
    lines.append(f"Unique IPs (failed): {len(set(ip for _, _, ip in events['failed']))}")
    lines.append("")

    if flagged:
        lines.append("--  BRUTE-FORCE SOURCES DETECTED --")
        for ip, info in sorted(flagged.items(), key=lambda kv: -kv[1]["count"]):
            duration = (info["last_seen"] - info["first_seen"]).total_seconds() / 60
            lines.append(f"\nIP: {ip}")
            lines.append(f"  Failed attempts : {info['count']}")
            lines.append(f"  Time span       : {duration:.1f} minutes")
            lines.append(f"  First seen      : {info['first_seen']}")
            lines.append(f"  Last seen       : {info['last_seen']}")
            lines.append(f"  Usernames tried : {', '.join(info['users_tried'][:10])}"
                          + (" ..." if len(info['users_tried']) > 10 else ""))
            lines.append(f"  Recommendation  : Block this IP (e.g. iptables/fail2ban) "
                          f"and review any successful logins from it.")
    else:
        lines.append("-- No brute-force patterns detected --")

    lines.append("")
    lines.append("-- Successful logins after suspicious activity (review these) --")
    if flagged:
        suspicious_window_end = max(info["last_seen"] for info in flagged.values())
        post_attack_logins = [e for e in events["accepted"] if e[0] > min(
            info["first_seen"] for info in flagged.values())]
        if post_attack_logins:
            for ts, user, ip in post_attack_logins:
                flag = " <-- from a flagged attacker IP!" if ip in flagged else ""
                lines.append(f"  {ts}  user={user}  ip={ip}{flag}")
        else:
            lines.append("  None found.")
    else:
        lines.append("  N/A (no attacks detected)")

    lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Analyze an SSH auth.log for brute-force attacks.")
    parser.add_argument("logfile", help="Path to the auth.log file to analyze")
    parser.add_argument("--report", help="Optional path to save the report to a file")
    args = parser.parse_args()

    events = parse_log(args.logfile)
    flagged = detect_brute_force(events["failed"])
    report = build_report(events, flagged)

    print(report)

    if args.report:
        with open(args.report, "w") as f:
            f.write(report)
        print(f"\nRapor '{args.report}' dosyasına da kaydedildi.")


if __name__ == "__main__":
    main()
