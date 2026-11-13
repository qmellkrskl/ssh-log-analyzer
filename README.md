# SSH Log Analyzer & Brute-Force Detector

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
   background noise — so the analyzer can be tested without a real server.
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

To use it on a real server, point it at the real log file (may need `sudo`
to read it):

```bash
python log_analyzer.py /var/log/auth.log --report daily_report.txt
```

## Configuration

Two constants at the top of `log_analyzer.py` control sensitivity:

```python
FAILED_ATTEMPT_THRESHOLD = 10   # failed attempts...
TIME_WINDOW_MINUTES = 5         # ...within this many minutes = brute force
```

## Possible extensions (good "next steps" to mention in an interview)

- Detect **low-and-slow** attacks (few attempts per IP, spread over hours)
  using a longer rolling window.
- Auto-generate `iptables` / `fail2ban` block rules for flagged IPs.
- Send alerts via email/Slack webhook when a new attack is detected.
- Read logs continuously (tail -f style) instead of one-shot analysis.
- Add unit tests (pytest) for the regex parsing and detection logic.

## What this demonstrates (for your resume)

- File I/O and regex-based log parsing in Python
- Algorithmic thinking (sliding time-window detection)
- Security domain knowledge (brute-force patterns, attack signatures)
- Clean CLI design with `argparse`
- Realistic test-data generation for a tool with no live data source

**Suggested resume line:**
> "Built a Python tool that parses SSH authentication logs and detects
> brute-force attacks using a sliding time-window algorithm, generating
> automated security reports."
