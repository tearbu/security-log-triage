#!/usr/bin/env python3
"""
security-log-triage: parse authentication logs and detect common attack patterns.

Detections:
  (a) Brute force            - >=5 failed logins for one user from one source IP
                               within 10 minutes                    (T1110.001)
  (b) Password spraying      - one source IP failing against >=4 distinct users
                               within 30 minutes                    (T1110.003)
  (c) Success after failures - a successful login for a user/IP pair with >=5
                               prior failures the same day          (T1078)
  (d) Off-hours admin login  - successful admin login between 00:00 and 05:00
                                                                    (T1078)

Input: JSON Lines file, one event per line:
  {"timestamp": "2026-11-10T09:02:11", "user": "jdoe",
   "src_ip": "203.0.113.45", "result": "failure"}

Usage:
  python3 src/log_triage.py data/sample-auth.log
  python3 src/log_triage.py data/sample-auth.log --report out.md
  python3 src/log_triage.py data/sample-auth.log --no-report

Standard library only.
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = timedelta(minutes=10)
SPRAY_USER_THRESHOLD = 4
SPRAY_WINDOW = timedelta(minutes=30)
SUCCESS_AFTER_FAILURES = 5
ADMIN_USERS = {"admin", "administrator", "root", "sysadmin"}
OFF_HOURS_START, OFF_HOURS_END = 0, 5  # 00:00 <= time < 05:00


def is_admin(user: str) -> bool:
    u = user.lower()
    return u in ADMIN_USERS or u.startswith("admin") or u.endswith("_admin")


def load_events(path: Path):
    events = []
    with path.open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
                events.append({
                    "timestamp": datetime.fromisoformat(raw["timestamp"]),
                    "raw_ts": raw["timestamp"],
                    "user": raw["user"],
                    "src_ip": raw["src_ip"],
                    "result": raw["result"],
                })
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                print(f"warning: skipping line {lineno}: {exc}", file=sys.stderr)
    events.sort(key=lambda e: e["timestamp"])
    return events


def windows(times, span):
    """Yield (start_index, count) for sliding windows over sorted datetimes."""
    left = 0
    for right in range(len(times)):
        while times[right] - times[left] > span:
            left += 1
        yield left, right - left + 1


def detect_brute_force(events):
    findings = []
    failures = defaultdict(list)
    for e in events:
        if e["result"] == "failure":
            failures[(e["user"], e["src_ip"])].append(e)
    for (user, ip), evs in sorted(failures.items()):
        times = [e["timestamp"] for e in evs]
        best = max((count for _, count in windows(times, BRUTE_FORCE_WINDOW)),
                   default=0)
        if best >= BRUTE_FORCE_THRESHOLD:
            start = next(t for t in times
                         if sum(1 for x in times
                                if t <= x <= t + BRUTE_FORCE_WINDOW) >= BRUTE_FORCE_THRESHOLD)
            in_window = [e for e in evs
                         if start <= e["timestamp"] <= start + BRUTE_FORCE_WINDOW]
            findings.append({
                "type": "Brute force",
                "severity": "High",
                "mitre": "T1110.001",
                "summary": (f"{len(in_window)} failed logins for user '{user}' from "
                            f"{ip} within 10 minutes (first at {in_window[0]['raw_ts']})"),
                "evidence": [f"{e['raw_ts']} FAILURE user={user} src_ip={ip}"
                             for e in in_window],
            })
    return findings


def detect_password_spraying(events):
    findings = []
    failures = defaultdict(list)
    for e in events:
        if e["result"] == "failure":
            failures[e["src_ip"]].append(e)
    for ip, evs in sorted(failures.items()):
        best_users, best_evs = set(), []
        for i, e in enumerate(evs):
            window = [x for x in evs[i:]
                      if x["timestamp"] - e["timestamp"] <= SPRAY_WINDOW]
            users = {x["user"] for x in window}
            if len(users) > len(best_users):
                best_users, best_evs = users, window
        if len(best_users) >= SPRAY_USER_THRESHOLD:
            findings.append({
                "type": "Password spraying",
                "severity": "High",
                "mitre": "T1110.003",
                "summary": (f"Source {ip} failed against {len(best_users)} distinct "
                            f"users within 30 minutes: {', '.join(sorted(best_users))}"),
                "evidence": [f"{e['raw_ts']} FAILURE user={e['user']} src_ip={ip}"
                             for e in best_evs],
            })
    return findings


def detect_success_after_failures(events):
    findings = []
    failures = defaultdict(list)
    for e in events:
        key = (e["user"], e["src_ip"], e["timestamp"].date())
        if e["result"] == "failure":
            failures[key].append(e)
        elif e["result"] == "success":
            prior = [f for f in failures[key] if f["timestamp"] < e["timestamp"]]
            if len(prior) >= SUCCESS_AFTER_FAILURES:
                findings.append({
                    "type": "Success after many failures",
                    "severity": "Critical",
                    "mitre": "T1078",
                    "summary": (f"Successful login for user '{e['user']}' from "
                                f"{e['src_ip']} at {e['raw_ts']} after "
                                f"{len(prior)} failures the same day - possible "
                                f"account compromise"),
                    "evidence": [f"{f['raw_ts']} FAILURE user={e['user']} src_ip={e['src_ip']}"
                                 for f in prior] +
                                [f"{e['raw_ts']} SUCCESS user={e['user']} src_ip={e['src_ip']}"],
                })
    return findings


def detect_offhours_admin(events):
    findings = []
    for e in events:
        if (e["result"] == "success" and is_admin(e["user"])
                and OFF_HOURS_START <= e["timestamp"].hour < OFF_HOURS_END):
            findings.append({
                "type": "Off-hours admin login",
                "severity": "Medium",
                "mitre": "T1078",
                "summary": (f"Admin account '{e['user']}' logged in successfully "
                            f"at {e['raw_ts']} from {e['src_ip']} (inside the "
                            f"off-hours window 00:00-05:00)"),
                "evidence": [f"{e['raw_ts']} SUCCESS user={e['user']} src_ip={e['src_ip']}"],
            })
    return findings


def render_report(findings, source, event_count):
    lines = [
        "# Authentication Log Triage Report",
        "",
        f"- Source log: `{source}`",
        f"- Events analyzed: {event_count}",
        f"- Findings: {len(findings)}",
        "",
    ]
    if not findings:
        lines += ["No suspicious patterns detected.", ""]
    for i, f in enumerate(findings, 1):
        lines += [
            f"## {i}. {f['type']} - Severity: {f['severity']}",
            "",
            f"- MITRE ATT&CK: {f['mitre']}",
            f"- Summary: {f['summary']}",
            "- Evidence:",
            "",
            "```",
            *f["evidence"],
            "```",
            "",
        ]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Triage authentication logs.")
    parser.add_argument("logfile", help="JSON Lines authentication log")
    parser.add_argument("--report", metavar="PATH",
                        help="Markdown report path (default: output/report.md)")
    parser.add_argument("--no-report", action="store_true",
                        help="Do not write a Markdown report")
    args = parser.parse_args(argv)

    events = load_events(Path(args.logfile))
    if not events:
        print("No parseable events found.", file=sys.stderr)
        return 1

    findings = []
    findings += detect_brute_force(events)
    findings += detect_password_spraying(events)
    findings += detect_success_after_failures(events)
    findings += detect_offhours_admin(events)

    print(f"Analyzed {len(events)} events from {args.logfile}")
    print(f"Findings: {len(findings)}\n")
    for i, f in enumerate(findings, 1):
        print(f"[{i}] {f['type']} | Severity: {f['severity']} | MITRE {f['mitre']}")
        print(f"    {f['summary']}")
        for line in f["evidence"]:
            print(f"      {line}")
        print()

    if not args.no_report:
        report_path = Path(args.report) if args.report else Path("output/report.md")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            render_report(findings, args.logfile, len(events)), encoding="utf-8")
        print(f"Markdown report written to {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
