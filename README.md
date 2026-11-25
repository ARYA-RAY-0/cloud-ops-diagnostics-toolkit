# Cloud Ops Diagnostics Toolkit

**Zero-dependency CLI diagnostics for isolating cross-layer cloud and Linux outages—from DNS and TCP handshakes up through TLS certificates, VPC Security Groups, and host resource exhaustion.**

---

## The Problem This Solves

During live infrastructure incidents, teams routinely lose critical resolution time to **layer-siloed troubleshooting**:

* **Symptom Ambiguity:** A `Connection timed out` or `504 Gateway Timeout` looks identical from an application log whether the root cause is a dropped packet in a VPC Security Group/NACL, an expired X.509 certificate, a dead backend daemon, or a Linux host pinned by CPU steal or inode exhaustion.
* **Heavy Dependency Friction:** Incident responders SSHing into degraded EC2 instances or minimal containers rarely have third-party packages (`boto3`, `requests`, `jq`) pre-installed—and installing packages on a disk-full or network-degraded host often fails.
* **Silent Configuration Drift:** Overly permissive ingress rules (`0.0.0.0/0` on SSH/database ports, undocumented CIDRs) and near-expiry TLS certificates accumulate quietly until they trigger a security audit failure or a sudden production outage.

**This toolkit solves all three** using **100% Python standard library and native Linux utilities**, deterministic exit codes (`0` OK, `1` WARN, `2` CRIT), and an incident correlator (`triage_bundle.py`) that pinpoints the **earliest failing layer** in one pass.

---

## Architecture & Tool Matrix

| Tool | Layer / Scope | What It Isolates | Exit Codes |
| :--- | :--- | :--- | :--- |
| **`net_tls_probe.py`** | OSI Layers 3–7 (Endpoint) | Measures exact latency and failures sequentially across **DNS resolution**, **TCP 3-way handshake** (separating firewall/SG drops from `ConnectionRefused`), **TLS protocol/cipher/expiry** (`<14d` warning), and **HTTP status**. | `0` Healthy<br>`1` Warning (HTTP error / `<14d` cert)<br>`2` Critical (DNS / TCP / TLS failure) |
| **`linux_triage.sh`** | OS / Compute Host | Audits **1m/5m/15m load vs. vCPU count**, cumulative **CPU `iowait` and `steal`**, **memory & OOM killer kernel logs**, **disk capacity (`df -h`)**, **inode exhaustion (`df -i`)**, **listening sockets (`ss -tulnp`)**, and **failed systemd units**. | `0` Healthy<br>`1` Warning (`>=80%` disk/inodes, OOM hits, failed units)<br>`2` Critical (`>=90%` disk/inodes, load `>2x` vCPUs) |
| **`aws_vpc_sg_auditor.py`** | Cloud Network Perimeter (Offline) | Parses exported `aws ec2 describe-security-groups` JSON offline to flag **`0.0.0.0/0` or `::/0` ingress on high-risk ports** (`22`, `3389`, `3306`, `5432`, `1433`, `6379`, `9200`, `27017`), broad CIDR blocks (`<= /16`), and undocumented rules. | `0` Clean<br>`1` Warning (Wide CIDRs / missing descriptions)<br>`2` Critical (Exposed admin/DB ports) |
| **`triage_bundle.py`** | Cross-Layer Correlator | Orchestrates `net_tls_probe.py`, `aws_vpc_sg_auditor.py`, and optional `linux_triage.sh` into a unified report with an **earliest-failing-layer root-cause hypothesis**. | Highest severity (`max` of sub-tool exit codes) |

---

## Quick Start

### 1. Probe an Endpoint Across OSI Layers 3–7

```bash
# Healthy HTTPS check
python3 net_tls_probe.py ://amazon.com

# Isolate a Layer 4 TCP timeout (e.g., blocked by Security Group or NACL)
python3 net_tls_probe.py ://amazon.com -p 8443 --skip-tls -t 2

# Emit machine-readable JSON for automation
python3 net_tls_probe.py ://badssl.com --json
```

### 2. Run Linux / EC2 Host Triage

```bash
chmod +x linux_triage.sh
./linux_triage.sh
```

### 3. Audit Exported AWS Security Groups Offline

```bash
# Works with live AWS CLI exports or local fixtures (no credentials required)
python3 aws_vpc_sg_auditor.py samples/sample_sgs.json
```

### 4. Run Full Cross-Layer Incident Correlation

```bash
python3 triage_bundle.py ://amazon.com --sg-file samples/sample_sgs.json --include-host
```

### 5. Run the Offline Unit Test Suite

```bash
python3 -m unittest discover -s tests -v
```

---

## Real Captured Outputs (`samples/`)

### Layer 5/6 TLS Certificate Failure (`samples/broken_tls_output.txt`)

```text
=== OSI Layer 3-7 Probe: ://badssl.com:443 ===
[PASS] Layer 7 DNS      | 104.154.89.105 (192.72 ms)
[PASS] Layer 4 TCP      | Connected to 104.154.89.105:443 (256.99 ms)
[FAIL] Layer 5/6 TLS    | TLS_CERT_VERIFICATION_FAILED: certificate has expired (550.71 ms)
```

### Layer 4 TCP Timeout (`samples/tcp_timeout_output.txt`)

```text
=== OSI Layer 3-7 Probe: ://amazon.com:8443 ===
[PASS] Layer 7 DNS      | 3.160.170.120, 3.160.170.109, 3.160.170.50, 3.160.170.92 (12.16 ms)
[FAIL] Layer 4 TCP      | TCP_TIMEOUT (Check Security Group, NACL, Route Table, or host firewall) (2000.78 ms)
```

### Cross-Layer Incident Bundle (`triage_bundle.py`)

```text
=== Incident Triage Bundle: ://amazon.com:443 (Exit: 2) ===
* Network path DNS -> TCP -> TLS -> HTTP succeeded cleanly.
* Security Group audit status is CRIT (3 findings): review exposed CIDRs and rules.
* Host triage flagged 2 alert(s) (exit 2): inspect CPU load/steal, memory/OOM, or disk/inodes.
--- Security Group Findings ---
[CRIT] sg-0fedcba9876543210 (app-db-exposed-sg) | tcp/22 from 0.0.0.0/0 -> Public ingress on high-risk service(s): 22 (SSH)
[WARN] sg-0fedcba9876543210 (app-db-exposed-sg) | tcp/22 from 0.0.0.0/0 -> Ingress rule missing Description tag for auditability
[CRIT] sg-0fedcba9876543210 (app-db-exposed-sg) | tcp/5432 from 0.0.0.0/0 -> Public ingress on high-risk service(s): 5432 (PostgreSQL)
--- Host Triage Alerts ---
[CRIT] Filesystem /usr/lib/wsl/drivers at 92% capacity
[CRIT] Filesystem /mnt/c at 92% capacity
```

---

## Repository Layout

```text
cloud-ops-diagnostics-toolkit/
├── net_tls_probe.py          # OSI Layer 3-7 DNS, TCP, TLS, and HTTP diagnostic CLI
├── linux_triage.sh           # Host-level CPU, memory/OOM, disk/inode, and socket snapshot
├── aws_vpc_sg_auditor.py     # Offline AWS Security Group JSON misconfiguration auditor
├── triage_bundle.py          # Cross-layer orchestrator and earliest-failure correlator
├── tests/
│   └── test_toolkit.py       # Zero-dependency unittest suite
├── samples/                  # Captured probe, audit, and host triage artifacts
└── README.md
```
