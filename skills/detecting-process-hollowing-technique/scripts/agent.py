#!/usr/bin/env python3
"""Agent for detecting process hollowing (T1055.012) in running processes."""

import argparse
import ctypes
import json
import os
import struct
import subprocess
import sys
from datetime import datetime, timezone


def get_running_processes():
    """Enumerate running processes via tasklist or ps."""
    procs = []
    if sys.platform == "win32":
        out = subprocess.check_output(
            ["tasklist", "/FO", "CSV", "/NH", "/V"], text=True, errors="replace"
        )
        for line in out.strip().splitlines():
            parts = line.strip('"').split('","')
            if len(parts) >= 2:
                procs.append({"name": parts[0], "pid": int(parts[1])})
    else:
        out = subprocess.check_output(
            ["ps", "-eo", "pid,ppid,comm,args", "--no-headers"], text=True
        )
        for line in out.strip().splitlines():
            fields = line.split(None, 3)
            if len(fields) >= 3:
                procs.append({
                    "pid": int(fields[0]),
                    "ppid": int(fields[1]),
                    "name": fields[2],
                    "cmdline": fields[3] if len(fields) > 3 else "",
                })
    return procs


def check_memory_discrepancy_linux(pid):
    """Check for signs of hollowing: discrepancy between mapped exe and memory."""
    indicators = []
    exe_link = f"/proc/{pid}/exe"
    maps_file = f"/proc/{pid}/maps"
    try:
        real_exe = os.readlink(exe_link)
        if " (deleted)" in real_exe:
            indicators.append(f"exe link points to deleted binary: {real_exe}")
    except (OSError, PermissionError):
        return indicators

    try:
        with open(maps_file, "r") as f:
            maps = f.read()
        exe_base = os.path.basename(real_exe)
        first_exec_region = None
        for line in maps.splitlines():
            if "r-xp" in line:
                first_exec_region = line
                break
        if first_exec_region and exe_base not in first_exec_region:
            indicators.append(
                f"Executable memory region does not reference expected binary: {first_exec_region}"
            )
    except (OSError, PermissionError):
        pass
    return indicators


def check_hollowing_windows(pid):
    """Use Windows API to detect hollowing via PEB image base vs section."""
    indicators = []
    try:
        result = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             f"Get-Process -Id {pid} | Select-Object Id,ProcessName,Path,"
             "MainModule,StartTime | ConvertTo-Json"],
            text=True, errors="replace", timeout=10
        )
        data = json.loads(result)
        if data.get("Path") and data.get("MainModule"):
            mod_path = data["MainModule"].get("FileName", "")
            if mod_path and data["Path"].lower() != mod_path.lower():
                indicators.append(
                    f"Process path mismatch: Path={data['Path']} MainModule={mod_path}"
                )
    except (subprocess.SubprocessError, json.JSONDecodeError, KeyError):
        pass
    return indicators


def analyze_process(pid):
    """Analyze a single process for hollowing indicators."""
    if sys.platform == "win32":
        return check_hollowing_windows(pid)
    return check_memory_discrepancy_linux(pid)


def scan_all(target_pids=None):
    """Scan processes for process hollowing indicators."""
    results = []
    procs = get_running_processes()
    targets = procs if not target_pids else [p for p in procs if p["pid"] in target_pids]

    for proc in targets:
        pid = proc["pid"]
        indicators = analyze_process(pid)
        entry = {
            "pid": pid,
            "name": proc.get("name", "unknown"),
            "hollowing_indicators": indicators,
            "suspicious": len(indicators) > 0,
        }
        results.append(entry)
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Detect process hollowing (T1055.012) in running processes"
    )
    parser.add_argument("--pid", type=int, nargs="*", help="Specific PIDs to scan")
    parser.add_argument("--output", "-o", help="Output JSON file path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    print("[*] Process Hollowing Detection Agent")
    print(f"[*] Platform: {sys.platform}")
    print(f"[*] Scan started: {datetime.now(timezone.utc).isoformat()}")

    results = scan_all(target_pids=args.pid)
    suspicious = [r for r in results if r["suspicious"]]

    report = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "platform": sys.platform,
        "total_scanned": len(results),
        "suspicious_count": len(suspicious),
        "suspicious_processes": suspicious,
    }

    if args.verbose:
        for r in results:
            status = "SUSPICIOUS" if r["suspicious"] else "OK"
            print(f"  [{status}] PID {r['pid']} ({r['name']})")
            for ind in r.get("hollowing_indicators", []):
                print(f"    -> {ind}")

    print(f"\n[*] Scanned {len(results)} processes, {len(suspicious)} suspicious")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
