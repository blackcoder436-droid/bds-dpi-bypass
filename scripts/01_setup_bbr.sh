#!/usr/bin/env bash

set -Eeuo pipefail

SYSCTL_FILE="/etc/sysctl.d/99-bds-dpi-bbr.conf"

if [[ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)" == "bbr" ]]; then
    echo "TCP BBR is already enabled."
    exit 0
fi

cat > "${SYSCTL_FILE}" <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

sysctl --system >/dev/null
[[ "$(sysctl -n net.ipv4.tcp_congestion_control)" == "bbr" ]] || {
    echo "Failed to enable TCP BBR." >&2
    exit 1
}

echo "TCP BBR enabled."
