#!/usr/bin/env python3
"""
net_tls_probe.py — OSI Layers 3–7 Endpoint Diagnostic Tool
Isolates DNS resolution, TCP 3-way handshake, TLS negotiation/X.509 expiry,
and HTTP status codes to pinpoint connection bottlenecks cleanly.
"""

import argparse
import datetime
import json
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List


def probe_dns(hostname: str, port: int) -> Dict[str, Any]:
    start = time.perf_counter()
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        ips: List[str] = []
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
        return {"ok": True, "latency_ms": latency_ms, "resolved_ips": ips}
    except socket.gaierror as exc:
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return {"ok": False, "latency_ms": latency_ms, "error": f"DNS_FAILURE: {exc}"}


def probe_tcp(ip: str, port: int, timeout: float) -> Dict[str, Any]:
    start = time.perf_counter()
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return {"ok": True, "target_ip": ip, "port": port, "latency_ms": latency_ms}
    except socket.timeout:
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return {
            "ok": False,
            "target_ip": ip,
            "port": port,
            "latency_ms": latency_ms,
            "error": "TCP_TIMEOUT (Check Security Group, NACL, Route Table, or host firewall)",
        }
    except ConnectionRefusedError:
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return {
            "ok": False,
            "target_ip": ip,
            "port": port,
            "latency_ms": latency_ms,
            "error": "TCP_CONNECTION_REFUSED (Host reachable, but no daemon listening on port)",
        }
    except OSError as exc:
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return {
            "ok": False,
            "target_ip": ip,
            "port": port,
            "latency_ms": latency_ms,
            "error": f"TCP_SOCKET_ERROR: {exc}",
        }


def probe_tls(hostname: str, ip: str, port: int, timeout: float) -> Dict[str, Any]:
    start = time.perf_counter()
    context = ssl.create_default_context()
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as raw_sock:
            raw_sock.settimeout(timeout)
            raw_sock.connect((ip, port))
            with context.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                latency_ms = round((time.perf_counter() - start) * 1000, 2)
                cert = tls_sock.getpeercert() or {}
                cipher = tls_sock.cipher()
                protocol = tls_sock.version()

                not_after_str = cert.get("notAfter")
                days_remaining = None
                if not_after_str:
                    expires_at = datetime.datetime.strptime(
                        not_after_str, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=datetime.timezone.utc)
                    now = datetime.datetime.now(datetime.timezone.utc)
                    days_remaining = (expires_at - now).days

                sans = [val for kind, val in cert.get("subjectAltName", []) if kind == "DNS"]
                issuer_parts = dict(x[0] for x in cert.get("issuer", []))

                return {
                    "ok": True,
                    "latency_ms": latency_ms,
                    "protocol": protocol,
                    "cipher": cipher[0] if cipher else "unknown",
                    "issuer_cn": issuer_parts.get("commonName", "unknown"),
                    "days_until_expiry": days_remaining,
                    "sans_preview": sans[:5],
                    "expiry_warning": days_remaining is not None and days_remaining < 14,
                }
    except ssl.SSLCertVerificationError as exc:
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return {
            "ok": False,
            "latency_ms": latency_ms,
            "error": f"TLS_CERT_VERIFICATION_FAILED: {exc.verify_message}",
        }
    except ssl.SSLError as exc:
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return {
            "ok": False,
            "latency_ms": latency_ms,
            "error": f"TLS_HANDSHAKE_ERROR: {exc}",
        }
    except OSError as exc:
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return {
            "ok": False,
            "latency_ms": latency_ms,
            "error": f"TLS_TRANSPORT_ERROR: {exc}",
        }


def probe_http(hostname: str, port: int, path: str, timeout: float) -> Dict[str, Any]:
    url = f"https://{hostname}:{port}{path}"
    start = time.perf_counter()
    req = urllib.request.Request(
        url,
        method="HEAD",
        headers={"User-Agent": "cloud-ops-diagnostics-toolkit/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            latency_ms = round((time.perf_counter() - start) * 1000, 2)
            return {
                "ok": 200 <= resp.status < 400,
                "url": url,
                "status_code": resp.status,
                "latency_ms": latency_ms,
                "server": resp.headers.get("Server", "not-disclosed"),
            }
    except urllib.error.HTTPError as exc:
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return {
            "ok": False,
            "url": url,
            "status_code": exc.code,
            "latency_ms": latency_ms,
            "error": f"HTTP_ERROR_{exc.code}: {exc.reason}",
        }
    except urllib.error.URLError as exc:
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return {
            "ok": False,
            "url": url,
            "latency_ms": latency_ms,
            "error": f"HTTP_URL_ERROR: {exc.reason}",
        }


def render_human(report: Dict[str, Any]) -> None:
    print(f"\n=== OSI Layer 3-7 Probe: {report['target']} ===")
    dns = report["dns"]
    if not dns["ok"]:
        print(f"[FAIL] Layer 7 DNS      | {dns['error']} ({dns['latency_ms']} ms)")
        return
    print(f"[PASS] Layer 7 DNS      | {', '.join(dns['resolved_ips'])} ({dns['latency_ms']} ms)")

    tcp = report["tcp"]
    if not tcp["ok"]:
        print(f"[FAIL] Layer 4 TCP      | {tcp['error']} ({tcp['latency_ms']} ms)")
        return
    print(f"[PASS] Layer 4 TCP      | Connected to {tcp['target_ip']}:{tcp['port']} ({tcp['latency_ms']} ms)")

    if "tls" in report:
        tls = report["tls"]
        if not tls["ok"]:
            print(f"[FAIL] Layer 5/6 TLS    | {tls['error']} ({tls['latency_ms']} ms)")
            return
        warn_tag = " [WARN: <14d expiry]" if tls["expiry_warning"] else ""
        print(
            f"[PASS] Layer 5/6 TLS    | {tls['protocol']} | {tls['cipher']} | "
            f"Issuer: {tls['issuer_cn']} | Expires in {tls['days_until_expiry']}d{warn_tag} ({tls['latency_ms']} ms)"
        )

    if "http" in report:
        http = report["http"]
        status = "PASS" if http["ok"] else "WARN"
        detail = (
            f"HTTP {http['status_code']} (Server: {http['server']})"
            if "status_code" in http and http["ok"]
            else http.get("error", f"HTTP {http.get('status_code')}")
        )
        print(f"[{status}] Layer 7 HTTP     | {detail} ({http['latency_ms']} ms)")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="OSI Layer 3–7 diagnostic probe for DNS, TCP, TLS, and HTTP triage."
    )
    parser.add_argument("host", help="Target hostname (e.g. aws.amazon.com or expired.badssl.com)")
    parser.add_argument("-p", "--port", type=int, default=443, help="Target TCP port (default: 443)")
    parser.add_argument("--path", default="/", help="HTTP request path (default: /)")
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="Socket timeout in seconds (default: 5.0)")
    parser.add_argument("--skip-tls", action="store_true", help="Only test DNS and Layer 4 TCP reachability")
    parser.add_argument("--json", action="store_true", help="Emit structured JSON output")
    args = parser.parse_args()

    report: Dict[str, Any] = {"target": f"{args.host}:{args.port}"}
    exit_code = 0

    dns_res = probe_dns(args.host, args.port)
    report["dns"] = dns_res
    if not dns_res["ok"]:
        exit_code = 2
    else:
        primary_ip = dns_res["resolved_ips"][0]
        tcp_res = probe_tcp(primary_ip, args.port, args.timeout)
        report["tcp"] = tcp_res
        if not tcp_res["ok"]:
            exit_code = 2
        elif not args.skip_tls:
            tls_res = probe_tls(args.host, primary_ip, args.port, args.timeout)
            report["tls"] = tls_res
            if not tls_res["ok"]:
                exit_code = 2
            else:
                if tls_res.get("expiry_warning"):
                    exit_code = 1
                http_res = probe_http(args.host, args.port, args.path, args.timeout)
                report["http"] = http_res
                if not http_res["ok"] and exit_code == 0:
                    exit_code = 1

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        render_human(report)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
