#!/usr/bin/env python3
"""Pass-the-Hash Detection Agent - Detects PTH via NTLM Event 4624 LogonType=3 analysis."""

import json
import logging
import argparse
from collections import defaultdict
from datetime import datetime

from Evtx.Evtx import FileHeader
from lxml import etree

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

NS = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}


def parse_ntlm_logons(evtx_path):
    """Parse Event 4624 NTLM network logons from Security EVTX."""
    ntlm_logons = []
    with open(evtx_path, "rb") as f:
        fh = FileHeader(f)
        for record in fh.records():
            try:
                xml = record.xml()
                root = etree.fromstring(xml.encode("utf-8"))
                eid = root.find(".//evt:System/evt:EventID", NS)
                if eid is None or eid.text != "4624":
                    continue
                data = {}
                for elem in root.findall(".//evt:EventData/evt:Data", NS):
                    data[elem.get("Name", "")] = elem.text or ""
                if data.get("LogonType") == "3" and data.get("AuthenticationPackageName") == "NTLM":
                    time_elem = root.find(".//evt:System/evt:TimeCreated", NS)
                    ntlm_logons.append({
                        "timestamp": time_elem.get("SystemTime", "") if time_elem is not None else "",
                        "account": data.get("TargetUserName", ""),
                        "domain": data.get("TargetDomainName", ""),
                        "source_ip": data.get("IpAddress", ""),
                        "workstation": data.get("WorkstationName", ""),
                        "logon_process": data.get("LogonProcessName", ""),
                        "lm_package": data.get("LmPackageName", ""),
                        "key_length": data.get("KeyLength", ""),
                    })
            except Exception:
                continue
    logger.info("Parsed %d NTLM network logon events", len(ntlm_logons))
    return ntlm_logons


def detect_pth_indicators(ntlm_logons):
    """Detect Pass-the-Hash indicators in NTLM logon events."""
    pth_candidates = []
    for logon in ntlm_logons:
        indicators = []
        if logon["logon_process"].strip() == "NtLmSsp":
            indicators.append("NtLmSsp logon process")
        if logon["lm_package"].strip() == "NTLM V1":
            indicators.append("NTLMv1 (weaker, often PTH)")
        if logon["key_length"] == "0":
            indicators.append("Zero key length (PTH indicator)")
        if logon["workstation"] and logon["source_ip"]:
            indicators.append("Remote NTLM with workstation name")
        if indicators:
            logon["pth_indicators"] = indicators
            logon["confidence"] = min(len(indicators) * 25, 100)
            pth_candidates.append(logon)
    logger.info("Found %d PTH candidate events", len(pth_candidates))
    return pth_candidates


def detect_lateral_movement_chains(ntlm_logons):
    """Detect chains of NTLM logons from the same account across multiple hosts."""
    account_hosts = defaultdict(set)
    account_events = defaultdict(list)
    for logon in ntlm_logons:
        account = f"{logon['domain']}\\{logon['account']}"
        if not logon["account"].endswith("$"):
            account_hosts[account].add(logon["source_ip"])
            account_events[account].append(logon)
    chains = []
    for account, hosts in account_hosts.items():
        if len(hosts) >= 3:
            chains.append({
                "account": account,
                "unique_source_ips": len(hosts),
                "total_logons": len(account_events[account]),
                "source_ips": list(hosts),
                "indicator": "Multi-host NTLM lateral movement",
                "severity": "critical" if len(hosts) >= 5 else "high",
            })
    logger.info("Found %d lateral movement chains", len(chains))
    return chains


def detect_workstation_mismatch(ntlm_logons):
    """Detect mismatches between source workstation and expected host."""
    account_workstations = defaultdict(set)
    for logon in ntlm_logons:
        if logon["account"] and not logon["account"].endswith("$"):
            key = f"{logon['domain']}\\{logon['account']}"
            account_workstations[key].add(logon["workstation"])
    mismatches = []
    for account, workstations in account_workstations.items():
        if len(workstations) >= 3:
            mismatches.append({
                "account": account,
                "unique_workstations": len(workstations),
                "workstations": list(workstations),
                "indicator": "Account used from multiple workstations (PTH spread)",
            })
    return mismatches


def generate_report(ntlm_logons, pth_candidates, chains, mismatches):
    """Generate Pass-the-Hash detection report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "total_ntlm_logons": len(ntlm_logons),
        "pth_candidates": len(pth_candidates),
        "lateral_movement_chains": len(chains),
        "workstation_mismatches": len(mismatches),
        "high_confidence_pth": [p for p in pth_candidates if p.get("confidence", 0) >= 75],
        "chain_details": chains,
        "mismatch_details": mismatches,
        "sample_pth_events": pth_candidates[:20],
    }
    total = len(pth_candidates) + len(chains)
    print(f"PTH DETECTION: {len(pth_candidates)} candidates, {len(chains)} lateral chains")
    return report


def main():
    parser = argparse.ArgumentParser(description="Pass-the-Hash Detection Agent")
    parser.add_argument("--evtx-file", required=True, help="Path to Security EVTX file")
    parser.add_argument("--output", default="pth_report.json")
    args = parser.parse_args()

    ntlm_logons = parse_ntlm_logons(args.evtx_file)
    pth_candidates = detect_pth_indicators(ntlm_logons)
    chains = detect_lateral_movement_chains(ntlm_logons)
    mismatches = detect_workstation_mismatch(ntlm_logons)

    report = generate_report(ntlm_logons, pth_candidates, chains, mismatches)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
