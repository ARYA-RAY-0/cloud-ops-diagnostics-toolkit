#!/usr/bin/env bash
set -euo pipefail

# linux_triage.sh — Host-level Linux/EC2 triage snapshot
# Checks CPU load/steal/iowait, memory/OOM events, disk/inode usage, and sockets.

EXIT_CODE=0
warn() {
    echo "[WARN] $1"
    if [ "$EXIT_CODE" -lt 1 ]; then
        EXIT_CODE=1
    fi
}

crit() {
    echo "[CRIT] $1"
    EXIT_CODE=2
}

echo "=== Linux Host Triage: $(hostname) ($(date -u '+%Y-%m-%d %H:%M:%S UTC')) ==="

# 1. CPU & Load Average
VCPUS=$(nproc 2>/dev/null || echo 1)
LOAD_1M=$(awk '{print $1}' /proc/loadavg)
LOAD_5M=$(awk '{print $2}' /proc/loadavg)
LOAD_15M=$(awk '{print $3}' /proc/loadavg)
echo "--- CPU & Load (vCPUs: ${VCPUS}) ---"
echo "Load average (1m / 5m / 15m): ${LOAD_1M} / ${LOAD_5M} / ${LOAD_15M}"

awk -v l1="$LOAD_1M" -v cpus="$VCPUS" 'BEGIN {
    if (l1 > cpus * 2) exit 2;
    else if (l1 > cpus) exit 1;
    else exit 0;
}' && LOAD_STATUS=0 || LOAD_STATUS=$?

if [ "$LOAD_STATUS" -eq 2 ]; then
    crit "1m load (${LOAD_1M}) exceeds 2x vCPU count (${VCPUS})"
elif [ "$LOAD_STATUS" -eq 1 ]; then
    warn "1m load (${LOAD_1M}) exceeds vCPU count (${VCPUS})"
fi

if command -v mpstat >/dev/null 2>&1; then
    MP_LINE=$(mpstat 1 1 2>/dev/null | awk '/Average:|all/ && $NF ~ /[0-9.]+/ {print $0}' | tail -n 1)
    echo "mpstat: ${MP_LINE}"
elif [ -r /proc/stat ]; then
    awk '/^cpu / {
        idle=$5+$6;
        total=$2+$3+$4+$5+$6+$7+$8;
        if (total>0) printf "Cumulative CPU iowait: %.1f%% | irq+softirq: %.1f%% | steal: %.1f%%\n", ($6/total)*100, (($7+$8)/total)*100, ($9/total)*100
    }' /proc/stat
fi

# 2. Memory & OOM Killer Check
echo "--- Memory & OOM ---"
free -m 2>/dev/null || cat /proc/meminfo | head -n 5
OOM_HITS=$( (dmesg -T 2>/dev/null || true; journalctl -k --no-pager -n 200 2>/dev/null || true) | grep -iE "out of memory|oom-killer|killed process" | tail -n 5 || true )
if [ -n "$OOM_HITS" ]; then
    warn "Recent OOM killer activity detected:"
    echo "$OOM_HITS"
else
    echo "[OK] No recent OOM killer messages found in accessible kernel logs"
fi

# 3. Disk Space & Inodes
echo "--- Disk Space (df -h) ---"
df -h -x tmpfs -x devtmpfs
while read -r fs size used avail usep mount; do
    pct=${usep%%%}
    if [ "$pct" -ge 90 ] 2>/dev/null; then
        crit "Filesystem ${mount} at ${usep} capacity"
    elif [ "$pct" -ge 80 ] 2>/dev/null; then
        warn "Filesystem ${mount} at ${usep} capacity"
    fi
done < <(df -h -x tmpfs -x devtmpfs | awk 'NR>1 {print $1, $2, $3, $4, $5, $6}')

echo "--- Inodes (df -i) ---"
df -i -x tmpfs -x devtmpfs
while read -r fs inodes iused ifree iusep mount; do
    ipct=${iusep%%%}
    if [ "$ipct" -ge 90 ] 2>/dev/null; then
        crit "Inodes on ${mount} at ${iusep}"
    elif [ "$ipct" -ge 80 ] 2>/dev/null; then
        warn "Inodes on ${mount} at ${iusep}"
    fi
done < <(df -i -x tmpfs -x devtmpfs | awk 'NR>1 {print $1, $2, $3, $4, $5, $6}')

# 4. Listening Sockets & Failed Services
echo "--- Listening Sockets ---"
if command -v ss >/dev/null 2>&1; then
    ss -tulnp 2>/dev/null || ss -tuln
else
    echo "[INFO] 'ss' not available on this host"
fi

if command -v systemctl >/dev/null 2>&1; then
    FAILED_UNITS=$(systemctl --failed --no-legend 2>/dev/null || true)
    if [ -n "$FAILED_UNITS" ]; then
        warn "Failed systemd units detected:"
        echo "$FAILED_UNITS"
    else
        echo "[OK] No failed systemd units"
    fi
fi

exit "$EXIT_CODE"