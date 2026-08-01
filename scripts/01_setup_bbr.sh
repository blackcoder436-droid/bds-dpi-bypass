#!/usr/bin/env bash
# ==============================================================================
# Script 01: Enable TCP BBR Congestion Control
# Reduces packet loss & optimizes throughput for mobile ISP connections
# ==============================================================================

set -euo pipefail

echo "=== [1/4] Enabling Linux BBR Congestion Control ==="

# Check sysctl BBR status
if sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
    echo "✓ TCP BBR is already enabled!"
else
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p
    echo "✓ Successfully enabled TCP BBR!"
fi
