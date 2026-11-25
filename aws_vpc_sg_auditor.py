#!/usr/bin/env python3
"""
aws_vpc_sg_auditor.py — Offline AWS Security Group JSON Misconfiguration Auditor
Inspects output from `aws ec2 describe-security-groups` (or a sample fixture)
to flag open administrative/database ports, wide CIDRs, and undocumented rules.
"""

import argparse
import json
import sys
from typing import Any, Dict, List

HIGH_RISK_PORTS: Dict[int, str] = {
    22: "SSH",
    3389: "RDP",
    1433: "MSSQL",
    3306: "MySQL/Aurora",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch/OpenSearch",
    27017: "MongoDB",
}


def audit_security_groups(groups: List[Dict[str, Any]]) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    severity_rank = {"OK": 0, "WARN": 1, "CRIT": 2}
    max_level = "OK"

    def record(level: str, sg_id: str, sg_name: str, cidr: str, ports: str, reason: str) -> None:
        nonlocal max_level
        if severity_rank[level] > severity_rank[max_level]:
            max_level = level
        findings.append(
            {
                "severity": level,
                "group_id": sg_id,
                "group_name": sg_name,
                "cidr": cidr,
                "ports": ports,
                "reason": reason,
            }
        )

    for sg in groups:
        sg_id = sg.get("GroupId", "sg-unknown")
        sg_name = sg.get("GroupName", "unknown")

        for perm in sg.get("IpPermissions", []):
            proto = str(perm.get("IpProtocol", "-1"))
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")

            if proto == "-1":
                port_label = "ALL"
            elif from_port == to_port and from_port is not None:
                port_label = f"{proto}/{from_port}"
            else:
                port_label = f"{proto}/{from_port}-{to_port}"

            cidrs: List[tuple[str, str]] = []
            for ip_range in perm.get("IpRanges", []):
                cidr = ip_range.get("CidrIp", "")
                desc = ip_range.get("Description", "").strip()
                if cidr:
                    cidrs.append((cidr, desc))
            for ipv6_range in perm.get("Ipv6Ranges", []):
                cidr6 = ipv6_range.get("CidrIpv6", "")
                desc = ipv6_range.get("Description", "").strip()
                if cidr6:
                    cidrs.append((cidr6, desc))

            for cidr, desc in cidrs:
                is_world = cidr in ("0.0.0.0/0", "::/0")
                prefix_len = None
                if "/" in cidr:
                    try:
                        prefix_len = int(cidr.rsplit("/", 1)[1])
                    except ValueError:
                        prefix_len = None

                if is_world and proto in ("tcp", "-1"):
                    if proto == "-1":
                        record(
                            "CRIT",
                            sg_id,
                            sg_name,
                            cidr,
                            port_label,
                            "All protocols/ports open to public internet",
                        )
                    else:
                        start_p = int(from_port) if from_port is not None else 0
                        end_p = int(to_port) if to_port is not None else 65535
                        matched = [
                            f"{p} ({name})"
                            for p, name in HIGH_RISK_PORTS.items()
                            if start_p <= p <= end_p
                        ]
                        if matched:
                            record(
                                "CRIT",
                                sg_id,
                                sg_name,
                                cidr,
                                port_label,
                                f"Public ingress on high-risk service(s): {', '.join(matched)}",
                            )
                        elif start_p == 0 and end_p == 65535:
                            record(
                                "CRIT",
                                sg_id,
                                sg_name,
                                cidr,
                                port_label,
                                "Full TCP port range (0-65535) open to public internet",
                            )
                        elif start_p not in (80, 443) or end_p not in (80, 443):
                            record(
                                "WARN",
                                sg_id,
                                sg_name,
                                cidr,
                                port_label,
                                "Non-HTTP/HTTPS port open to 0.0.0.0/0 or ::/0",
                            )

                if not is_world and prefix_len is not None and prefix_len <= 16:
                    record(
                        "WARN",
                        sg_id,
                        sg_name,
                        cidr,
                        port_label,
                        f"Broad /{prefix_len} ingress range; verify least-privilege scope",
                    )

                if not desc:
                    record(
                        "WARN",
                        sg_id,
                        sg_name,
                        cidr,
                        port_label,
                        "Ingress rule missing Description tag for auditability",
                    )

    return {
        "groups_audited": len(groups),
        "overall_status": max_level,
        "findings_count": len(findings),
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit exported AWS EC2 Security Group JSON for common misconfigurations."
    )
    parser.add_argument("json_file", help="Path to JSON file containing SecurityGroups list")
    parser.add_argument("--json", action="store_true", help="Emit structured JSON summary")
    args = parser.parse_args()

    try:
        with open(args.json_file, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except OSError as exc:
        print(f"Error reading file: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"Invalid JSON: {exc}", file=sys.stderr)
        return 2

    if isinstance(raw, dict):
        groups = raw.get("SecurityGroups", [])
    elif isinstance(raw, list):
        groups = raw
    else:
        print("JSON root must be an object with SecurityGroups or a list of groups.", file=sys.stderr)
        return 2

    result = audit_security_groups(groups)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(
            f"\n=== AWS Security Group Audit ({result['groups_audited']} groups) "
            f"| Status: {result['overall_status']} ==="
        )
        if not result["findings"]:
            print("[OK] No findings detected.")
        for item in result["findings"]:
            print(
                f"[{item['severity']}] {item['group_id']} ({item['group_name']}) "
                f"| {item['ports']} from {item['cidr']} -> {item['reason']}"
            )

    if result["overall_status"] == "CRIT":
        return 2
    if result["overall_status"] == "WARN":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
