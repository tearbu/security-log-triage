# Security Log Triage

A small, dependency-free Python tool that reads authentication logs and flags the patterns a security analyst looks for first: brute-force attacks, password spraying, possible account compromise, and off-hours admin access.

## Why it matters

Authentication logs are usually the first data source in an investigation, and the highest-signal attacks against identity systems are pattern-based: many failures in a short window, one source testing many accounts, or a success that arrives right after a pile of failures. This tool automates that first-pass triage. It grades each finding by severity, tags it with a MITRE ATT&CK technique, and attaches the raw evidence lines, so a finding can be verified in seconds instead of by grepping logs by hand.

## Detections

| # | Detection | Rule | MITRE ATT&CK | Severity |
|---|-----------|------|--------------|----------|
| a | Brute force | ≥ 5 failed logins for one user from one source IP within 10 minutes | T1110.001 (Password Guessing) | High |
| b | Password spraying | One source IP fails against ≥ 4 distinct users within 30 minutes | T1110.003 (Password Spraying) | High |
| c | Success after many failures | Successful login for a user/IP pair with ≥ 5 prior failures the same day | T1078 (Valid Accounts) | Critical |
| d | Off-hours admin login | Successful admin-account login between 00:00 and 05:00 | T1078 (Valid Accounts) | Medium |

## How to run

Python 3.9+, standard library only. Nothing to install.

```bash
python3 src/log_triage.py data/sample-auth.log
```

- Findings print to the console, and a Markdown report is written to `output/report.md` by default.
- Use `--report some/path.md` to choose the report location, or `--no-report` to skip it.
- To run it on a real log, export events as JSON Lines with `timestamp`, `user`, `src_ip`, and `result` (`success`/`failure`) fields, one event per line, and pass that file instead.

## Sample output (actual run against the bundled data)

The bundled `data/sample-auth.log` contains 65 events over two days (2026-11-10 and 2026-11-11), with three seeded incidents plus normal user noise. Verified run output:

```text
Analyzed 65 events from data/sample-auth.log
Findings: 4

[1] Brute force | Severity: High | MITRE T1110.001
    6 failed logins for user 'jdoe' from 203.0.113.45 within 10 minutes (first at 2026-11-10T09:02:11)
      2026-11-10T09:02:11 FAILURE user=jdoe src_ip=203.0.113.45
      ... (6 evidence lines)

[2] Password spraying | Severity: High | MITRE T1110.003
    Source 198.51.100.23 failed against 5 distinct users within 30 minutes: alice, bob, carol, dave, erin

[3] Success after many failures | Severity: Critical | MITRE T1078
    Successful login for user 'jdoe' from 203.0.113.45 at 2026-11-10T09:11:42 after 6 failures the same day - possible account compromise

[4] Off-hours admin login | Severity: Medium | MITRE T1078
    Admin account 'admin' logged in successfully at 2026-11-11T02:37:18 from 10.1.2.5 (inside the off-hours window 00:00-05:00)

Markdown report written to output/report.md
```

Findings by type: 1 brute force, 1 password spraying, 1 success-after-many-failures, 1 off-hours admin login. The full console output (including every evidence line) and the generated `output/report.md` are reproducible by running the command above.

## Files

```text
src/log_triage.py      the analyzer (parsing, 4 detections, console + Markdown reporting)
data/sample-auth.log   65 fictional events over 2 days with seeded incidents
output/report.md       generated report (created when you run the tool)
```

## Honest limitations

- **One input format.** Only JSON Lines with the four fields above; real-world logs (Windows Event XML, syslog, cloud IdP exports) would need a normalizer in front of it.
- **Fixed thresholds.** The 5-in-10-minutes style thresholds are sensible defaults, not tuned to any specific environment; a busy NAT gateway can produce spraying-shaped false positives.
- **Naive admin definition.** "Admin" is matched by username (`admin`, `administrator`, `root`, names starting with `admin` or ending in `_admin`), not by actual group membership.
- **No state or alerting.** It is a batch triage script: no deduplication across runs, no SIEM/syslog output, no baselining of "normal" hours per user.
- **Sample data is fictional.** All users, IPs (documentation ranges 203.0.113.0/24 and 198.51.100.0/24), and events were invented for demonstration.

## License

MIT. See [LICENSE](LICENSE). Copyright (c) 2026 Araf Abubakar.
