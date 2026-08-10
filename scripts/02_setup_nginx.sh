#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="${SCRIPT_DIR}/../config/nginx/bds-node.conf"
TARGET="/etc/nginx/sites-available/bds-dpi-bypass"
ENABLED="/etc/nginx/sites-enabled/bds-dpi-bypass"

: "${PANEL_DOMAIN:?PANEL_DOMAIN is required}"
: "${SUB_DOMAIN:?SUB_DOMAIN is required}"
: "${CDN_DOMAIN:?CDN_DOMAIN is required}"
: "${XUI_PANEL_PORT:?XUI_PANEL_PORT is required}"
: "${XUI_SUB_PORT:?XUI_SUB_PORT is required}"
: "${XUI_WEB_BASE_PATH:?XUI_WEB_BASE_PATH is required}"
: "${TLS_CERT_FILE:?TLS_CERT_FILE is required}"
: "${TLS_KEY_FILE:?TLS_KEY_FILE is required}"

python3 - "${TEMPLATE}" "${TARGET}" <<'PY'
import os
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
values = {
    "PANEL_DOMAIN": os.environ["PANEL_DOMAIN"],
    "SUB_DOMAIN": os.environ["SUB_DOMAIN"],
    "CDN_DOMAIN": os.environ["CDN_DOMAIN"],
    "XUI_PANEL_PORT": os.environ["XUI_PANEL_PORT"],
    "XUI_SUB_PORT": os.environ["XUI_SUB_PORT"],
    "XUI_WEB_BASE_PATH": os.environ["XUI_WEB_BASE_PATH"],
    "TLS_CERT_FILE": os.environ["TLS_CERT_FILE"],
    "TLS_KEY_FILE": os.environ["TLS_KEY_FILE"],
}
for key, value in values.items():
    source = source.replace("{{" + key + "}}", value)
if "{{" in source or "}}" in source:
    raise SystemExit("unresolved Nginx template variable")
path = pathlib.Path(sys.argv[2])
path.write_text(source, encoding="utf-8")
PY

ln -sfn "${TARGET}" "${ENABLED}"

# These legacy files overlap the generated hostnames. The master installer has
# already archived /etc/nginx before this cleanup.
rm -f /etc/nginx/sites-enabled/bds-node /etc/nginx/sites-enabled/bds-node.conf

nginx -t
systemctl enable --now nginx
systemctl reload nginx

echo "Nginx configuration installed."
