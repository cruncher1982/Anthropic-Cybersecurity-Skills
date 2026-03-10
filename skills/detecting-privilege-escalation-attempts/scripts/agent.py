#!/usr/bin/env python3
"""
Privilege Escalation Detection Agent
Analyzes Windows Security and Sysmon event logs for privilege escalation
indicators including token manipulation, UAC bypass, and sudo abuse.
Authorized security monitoring use only.
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone

try:
    import win32evtlog
    import win32evtlogutil
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False


PRIV_ESC_EVENT_IDS = {
    4672: "Special privileges assigned to new logon",
    4673: "A privileged service was called",
    4674: "An operation was attempted on a privileged object",
    4688: "A new process has been created (check for elevated tokens)",
    4703: "A user right was adjusted",
    1: "Sysmon Process Create (check IntegrityLevel)",
}

SUSPICIOUS_PROCESSES = [
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
]

UAC_BYPASS_INDICATORS = [
    r"fodhelper\.exe", r"eventvwr\.exe", r"sdclt\.exe",
    r"computerdefaults\.exe", r"slui\.exe",
    r"HKCU\\Software\\Classes\\ms-settings",
    r"HKCU\\Software\\Classes\\mscfile",
]


def parse_windows_security_log(server=None, max_events=5000):
    """Parse Windows Security log for privilege escalation events."""
    if not HAS_WIN32:
        return []
    findings = []
    handle = win32evtlog.OpenEventLog(server, "Security")
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    total = 0
    while total < max_events:
        events = win32evtlog.ReadEventLog(handle, flags, 0)
        if not events:
            break
        for event in events:
            if event.EventID & 0xFFFF in PRIV_ESC_EVENT_IDS:
                findings.append({
                    "event_id": event.EventID & 0xFFFF,
                    "description": PRIV_ESC_EVENT_IDS.get(event.EventID & 0xFFFF, ""),
                    "time": event.TimeGenerated.isoformat(),
                    "source": event.SourceName,
                    "user": event.StringInserts[1] if event.StringInserts and len(event.StringInserts) > 1 else "",
                    "data": (event.StringInserts or [])[:5],
                })
            total += 1
    win32evtlog.CloseEventLog(handle)
    return findings


def analyze_sysmon_log(log_file):
    """Analyze exported Sysmon log (JSON/EVTX) for escalation patterns."""
    findings = []
    with open(log_file, "r") as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
            except json.JSONDecodeError:
                continue
            event_id = entry.get("EventID", entry.get("event_id", 0))
            if event_id == 1:
                image = entry.get("Image", entry.get("image", "")).lower()
                integrity = entry.get("IntegrityLevel", entry.get("integrity_level", ""))
                cmdline = entry.get("CommandLine", entry.get("command_line", ""))
                proc_name = image.split("\\")[-1] if image else ""
                if proc_name in SUSPICIOUS_PROCESSES and integrity in ("High", "System"):
                    findings.append({
                        "type": "elevated_suspicious_process",
                        "process": proc_name,
                        "integrity": integrity,
                        "command_line": cmdline[:200],
                        "parent": entry.get("ParentImage", ""),
                        "timestamp": entry.get("UtcTime", entry.get("timestamp", "")),
                        "severity": "high",
                    })
                for pattern in UAC_BYPASS_INDICATORS:
                    if re.search(pattern, cmdline, re.IGNORECASE):
                        findings.append({
                            "type": "uac_bypass_indicator",
                            "pattern": pattern,
                            "process": proc_name,
                            "command_line": cmdline[:200],
                            "timestamp": entry.get("UtcTime", ""),
                            "severity": "critical",
                        })
    return findings


def analyze_linux_auth_log(log_file="/var/log/auth.log"):
    """Analyze Linux auth log for sudo/su escalation attempts."""
    findings = []
    sudo_pattern = re.compile(r"(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sudo:\s+(\S+)\s+:.*COMMAND=(.*)")
    su_pattern = re.compile(r"(\w+\s+\d+\s+[\d:]+)\s+\S+\s+su\[\d+\]:\s+(.*)")
    with open(log_file, "r") as f:
        for line in f:
            m = sudo_pattern.search(line)
            if m:
                findings.append({
                    "type": "sudo_execution",
                    "timestamp": m.group(1),
                    "user": m.group(2),
                    "command": m.group(3)[:200],
                    "severity": "medium",
                })
            m = su_pattern.search(line)
            if m:
                if "FAILED" in m.group(2).upper():
                    findings.append({
                        "type": "failed_su_attempt",
                        "timestamp": m.group(1),
                        "details": m.group(2)[:200],
                        "severity": "high",
                    })
    return findings


def generate_report(findings):
    """Generate privilege escalation detection report."""
    report = {
        "report_title": "Privilege Escalation Detection Report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "critical": len([f for f in findings if f.get("severity") == "critical"]),
        "high": len([f for f in findings if f.get("severity") == "high"]),
        "medium": len([f for f in findings if f.get("severity") == "medium"]),
        "findings": findings,
    }
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect privilege escalation attempts")
    parser.add_argument("--sysmon-log", help="Path to exported Sysmon JSON log")
    parser.add_argument("--auth-log", default="/var/log/auth.log", help="Linux auth log path")
    parser.add_argument("--windows", action="store_true", help="Analyze Windows Security event log")
    parser.add_argument("--output", default="privesc_detection.json", help="Output file")
    args = parser.parse_args()

    findings = []
    if args.windows and HAS_WIN32:
        print("[*] Analyzing Windows Security event log...")
        findings.extend(parse_windows_security_log())
    if args.sysmon_log:
        print(f"[*] Analyzing Sysmon log: {args.sysmon_log}")
        findings.extend(analyze_sysmon_log(args.sysmon_log))
    if args.auth_log:
        try:
            findings.extend(analyze_linux_auth_log(args.auth_log))
        except FileNotFoundError:
            print(f"[!] Auth log not found: {args.auth_log}")

    report = generate_report(findings)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[*] Report: {report['total_findings']} findings "
          f"(critical={report['critical']}, high={report['high']})")
    print(json.dumps(report, indent=2))
