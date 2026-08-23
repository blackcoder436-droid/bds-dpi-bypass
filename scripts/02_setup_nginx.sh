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

# 3x-UI nodes can have hundreds of concurrent long-lived WebSocket sessions.
# Keep the global event capacity deterministic on every fresh or replacement VPS.
python3 - /etc/nginx/nginx.conf <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
if re.search(r"worker_rlimit_nofile\s+\d+;", source):
    source = re.sub(r"worker_rlimit_nofile\s+\d+;", "worker_rlimit_nofile 65535;", source, count=1)
else:
    match = re.search(r"worker_processes\s+[^;]+;", source)
    if not match:
        raise SystemExit("worker_processes directive not found")
    source = source[:match.end()] + "\nworker_rlimit_nofile 65535;" + source[match.end():]
source = re.sub(r"worker_connections\s+\d+;", "worker_connections 8192;", source, count=1)
events = re.search(r"events\s*\{(?P<body>.*?)\}", source, re.DOTALL)
if not events:
    raise SystemExit("events block not found")
body = events.group("body")
if re.search(r"#?\s*multi_accept\s+(?:on|off);", body):
    body = re.sub(r"#?\s*multi_accept\s+(?:on|off);", "\n    multi_accept on;", body)
else:
    body += "\n    multi_accept on;\n"
source = source[:events.start("body")] + body + source[events.end("body"):]
path.write_text(source, encoding="utf-8")
PY

# These legacy files overlap the generated hostnames. The master installer has
# already archived /etc/nginx before this cleanup.
rm -f /etc/nginx/sites-enabled/bds-node /etc/nginx/sites-enabled/bds-node.conf

nginx -t
systemctl enable --now nginx
systemctl reload nginx

echo "Nginx configuration installed."
