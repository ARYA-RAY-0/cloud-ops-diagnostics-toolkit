#!/usr/bin/env python3
"""
triage_bundle.py — Cross-Layer Incident Correlator
Combines net_tls_probe.py, aws_vpc_sg_auditor.py, and optional linux_triage.sh
into one structured incident report with root-cause hypotheses.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List


def run_json_tool(cmd: List[str]) -> Dict[str, Any]:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    try:
        payload = json.loads(proc.stdout) if proc.stdout.strip() else {}
    except json.JSONDecodeError:
        payload = {"parse_error": proc.stdout.strip() or proc.stderr.strip()}
    payload["_exit_code"] = proc.returncode
    return payload


def run_host_triage(script_path: Path) -> Dict[str, Any]:
    if not script_path.exists():
        return {"ran": False, "_exit_code": 0, "error": "linux_triage.sh not found"}
    proc = subprocess.run(["bash", str(script_path)], capture_output=True, text=True, check=False)
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip().startswith(("[WARN]", "[CRIT]"))]
    return {
        "ran": True,
        "_exit_code": proc.returncode,
        "alerts": lines,
        "raw_output": proc.stdout,
    }


def build_hypothesis(
    net_data: Dict[str, Any],
    sg_data: Dict[str, Any] | None,
    host_data: Dict[str, Any] | None,
) -> List[str]:
    notes: List[str] = []
    dns = net_data.get("dns", {})
    tcp = net_data.get("tcp", {})
    tls = net_data.get("tls", {})
    http = net_data.get("http", {})

    if dns and not dns.get("ok", True):
        notes.append("Earliest failure at DNS: verify hosted zone records, NS delegation, or resolver reachability.")
    elif tcp and not tcp.get("ok", True):
        notes.append("Earliest failure at TCP connect: check Security Groups, NACLs, route tables, or service bind port.")
    elif tls and not tls.get("ok", True):
        notes.append("Earliest failure at TLS handshake: verify cert expiry, SAN/hostname match, or trust chain.")
    elif http and not http.get("ok", True):
        notes.append(f"TCP/TLS succeeded but HTTP returned status {http.get('status_code', 'error')}: inspect app/proxy logs.")
    else:
        notes.append("Network path DNS -> TCP -> TLS -> HTTP succeeded cleanly.")

    if sg_data:
        status = sg_data.get("overall_status", "OK")
        if status in ("CRIT", "WARN"):
            notes.append(
                f"Security Group audit status is {status} ({sg_data.get('findings_count', 0)} findings): review exposed CIDRs and rules."
            )

    if host_data and host_data.get("ran"):
        h_code = host_data.get("_exit_code", 0)
        alerts = host_data.get("alerts", [])
        if h_code > 0:
            notes.append(f"Host triage flagged {len(alerts)} alert(s) (exit {h_code}): inspect CPU load/steal, memory/OOM, or disk/inodes.")
        else:
            notes.append("Host triage passed with no CPU, memory, disk, or inode alerts.")

    return notes


def main() -> int:
    parser = argparse.ArgumentParser(description="Correlate network/TLS probe, SG audit, and Linux host triage.")
    parser.add_argument("host", help="Target hostname for network/TLS probe")
    parser.add_argument("-p", "--port", type=int, default=443, help="Target TCP port (default: 443)")
    parser.add_argument("--sg-file", help="Optional path to Security Group JSON file")
    parser.add_argument("--include-host", action="store_true", help="Run linux_triage.sh and include host alerts")
    parser.add_argument("--json", action="store_true", help="Emit combined JSON report")
    args = parser.parse_args()

    here = Path(__file__).resolve().parent
    net_cmd = [sys.executable, str(here / "net_tls_probe.py"), args.host, "-p", str(args.port), "--json"]
    net_data = run_json_tool(net_cmd)

    sg_data: Dict[str, Any] | None = None
    if args.sg_file:
        sg_cmd = [sys.executable, str(here / "aws_vpc_sg_auditor.py"), args.sg_file, "--json"]
        sg_data = run_json_tool(sg_cmd)

    host_data: Dict[str, Any] | None = None
    if args.include_host:
        host_data = run_host_triage(here / "linux_triage.sh")

    hypotheses = build_hypothesis(net_data, sg_data, host_data)
    codes = [net_data.get("_exit_code", 0)]
    if sg_data:
        codes.append(sg_data.get("_exit_code", 0))
    if host_data and host_data.get("ran"):
        codes.append(host_data.get("_exit_code", 0))
    final_exit = max(codes) if codes else 0

    bundle = {
        "target": f"{args.host}:{args.port}",
        "exit_code": final_exit,
        "hypotheses": hypotheses,
        "network_probe": net_data,
        "security_group_audit": sg_data,
        "host_triage": host_data,
    }

    if args.json:
        print(json.dumps(bundle, indent=2))
    else:
        print(f"\n=== Incident Triage Bundle: {bundle['target']} (Exit: {final_exit}) ===")
        for line in hypotheses:
            print(f"* {line}")
        if sg_data and sg_data.get("findings"):
            print("--- Security Group Findings ---")
            for item in sg_data["findings"]:
                print(
                    f"[{item['severity']}] {item['group_id']} ({item['group_name']}) "
                    f"| {item['ports']} from {item['cidr']} -> {item['reason']}"
                )
        if host_data and host_data.get("alerts"):
            print("--- Host Triage Alerts ---")
            for alert in host_data["alerts"]:
                print(alert)

    return final_exit


if __name__ == "__main__":
    sys.exit(main())
