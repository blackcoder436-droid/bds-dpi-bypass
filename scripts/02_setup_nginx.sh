#!/usr/bin/env bash
# ==============================================================================
# Script 02: Nginx Reverse Proxy Setup
# Copies Nginx configuration template and reloads Nginx service
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_SOURCE="${SCRIPT_DIR}/../config/nginx/bds-node.conf"
NGINX_TARGET="/etc/nginx/sites-available/bds-node"
NGINX_ENABLED="/etc/nginx/sites-enabled/bds-node"

echo "=== [2/4] Setting up Nginx Reverse Proxy ==="

if [ ! -f "${CONFIG_SOURCE}" ]; then
    echo "❌ Error: ${CONFIG_SOURCE} does not exist!"
    exit 1
fi

mkdir -p /etc/nginx/ssl/bds-node

cp "${CONFIG_SOURCE}" "${NGINX_TARGET}"
ln -sf "${NGINX_TARGET}" "${NGINX_ENABLED}"

# Test Nginx syntax and reload
nginx -t
systemctl reload nginx

echo "✓ Nginx reverse proxy configured and reloaded successfully!"
