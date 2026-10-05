#!/usr/bin/env python3
"""Add or update one CDN VLESS inbound routed through a regional SOCKS5 proxy."""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


def load_core():
    candidates = [Path(__file__).with_name("04_configure_3xui_db.py"), Path("/usr/local/libexec/bds-configure-3xui.py")]
    path = next((candidate for candidate in candidates if candidate.exists()), None)
    if path is None:
        raise RuntimeError("bds-configure-3xui.py is not installed")
    spec = importlib.util.spec_from_file_location("bds_configure_3xui", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def region_tag(code: str) -> str:
    return f"BDS-REGION-{code.upper()}"


def update_template(template: dict[str, Any], *, tag: str, inbound_port: int, proxy_protocol: str = "socks5", proxy_host: str, proxy_port: int, proxy_user: str, proxy_password: str) -> dict[str, Any]:
    outbounds = template.setdefault("outbounds", [])
    routing = template.setdefault("routing", {})
    rules = routing.setdefault("rules", [])
    outbound_protocol = "socks" if proxy_protocol == "socks5" else "http"
    server = {"address": proxy_host, "port": proxy_port}
    if proxy_user and proxy_password:
        server["users"] = [{"user": proxy_user, "pass": proxy_password}]
    outbound = {"tag": tag, "protocol": outbound_protocol, "settings": {"servers": [server]}}
    outbounds[:] = [item for item in outbounds if not isinstance(item, dict) or item.get("tag") != tag]
    outbounds.append(outbound)
    rule = {"type": "field", "inboundTag": [f"in-{inbound_port}-tcp"], "outboundTag": tag}
    rules[:] = [item for item in rules if not isinstance(item, dict) or item.get("outboundTag") != tag]
    rules.insert(0, rule)
    return template


def nginx_location(path: str, port: int) -> str:
    return f"""location = {path} {{
    proxy_pass http://127.0.0.1:{port};
    include /etc/nginx/proxy_params;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_read_timeout 86400s;
    proxy_send_timeout 86400s;
}}
"""


def template_has_tag(value: object, tag: str) -> bool:
    if not isinstance(value, dict):
        return False
    return any(isinstance(item, dict) and item.get("tag") == tag for item in value.get("outbounds", [])) and any(
        isinstance(item, dict) and item.get("outboundTag") == tag
        for item in (value.get("routing") or {}).get("rules", [])
    )


def check_proxy_tunnel(protocol: str, proxy_host: str, proxy_port: int, proxy_user: str, proxy_password: str, target_host: str, target_port: int, timeout: float = 8.0) -> None:
    """Verify that the regional proxy can open a TCP tunnel without printing credentials."""
    def receive_exact(connection: socket.socket, size: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < size:
            chunk = connection.recv(size - len(chunks))
            if not chunk:
                raise RuntimeError("Proxy closed the connection during negotiation")
            chunks.extend(chunk)
        return bytes(chunks)

    with socket.create_connection((proxy_host, proxy_port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        if protocol == "http":
            headers = [f"CONNECT {target_host}:{target_port} HTTP/1.1", f"Host: {target_host}:{target_port}"]
            if proxy_user:
                import base64
                token = base64.b64encode(f"{proxy_user}:{proxy_password}".encode()).decode()
                headers.append(f"Proxy-Authorization: Basic {token}")
            connection.sendall(("\r\n".join(headers) + "\r\n\r\n").encode())
            response = bytearray()
            while b"\r\n\r\n" not in response and len(response) < 8192:
                chunk = connection.recv(1024)
                if not chunk:
                    break
                response.extend(chunk)
            if b"\r\n\r\n" not in response or not re.match(br"HTTP/\d(?:\.\d)? 2\d\d(?: |$)", bytes(response).split(b"\r\n", 1)[0]):
                raise RuntimeError("HTTP proxy CONNECT check failed")
            return

        methods = b"\x00\x02" if proxy_user else b"\x00"
        connection.sendall(b"\x05" + bytes([len(methods)]) + methods)
        reply = receive_exact(connection, 2)
        if reply[0] != 5 or reply[1] == 0xFF:
            raise RuntimeError("SOCKS5 negotiation failed")
        if reply[1] == 2:
            user, password = proxy_user.encode(), proxy_password.encode()
            if len(user) > 255 or len(password) > 255:
                raise RuntimeError("SOCKS5 credentials are too long")
            connection.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
            if receive_exact(connection, 2) != b"\x01\x00":
                raise RuntimeError("SOCKS5 authentication failed")
        host = target_host.encode()
        if len(host) > 255:
            raise RuntimeError("Health target hostname is too long")
        connection.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack("!H", target_port))
        reply = receive_exact(connection, 4)
        if reply[1] != 0:
            raise RuntimeError("SOCKS5 proxy tunnel check failed")
        if reply[3] == 0x01:
            receive_exact(connection, 6)
        elif reply[3] == 0x04:
            receive_exact(connection, 18)
        elif reply[3] == 0x03:
            receive_exact(connection, receive_exact(connection, 1)[0] + 2)
        else:
            raise RuntimeError("SOCKS5 proxy returned an invalid address type")


def persist_postgres_template(dsn: str, template: dict[str, Any]) -> None:
    serialized = json.dumps(template, separators=(",", ":"))
    delimiter = "$bds_region$"
    if delimiter in serialized:
        raise RuntimeError("Unexpected PostgreSQL delimiter in Xray template")
    sql = f"UPDATE settings SET value={delimiter}{serialized}{delimiter} WHERE key='xrayTemplateConfig';\n"
    subprocess.run(["psql", dsn, "-v", "ON_ERROR_STOP=1"], input=sql, text=True, check=True, stdout=subprocess.DEVNULL)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--panel-url", required=True)
    parser.add_argument("--username", default=os.environ.get("XUI_USERNAME"))
    parser.add_argument("--password", default=os.environ.get("XUI_PASSWORD"))
    parser.add_argument("--region-code", required=True)
    parser.add_argument("--region-name", required=True)
    parser.add_argument("--server-label", default=os.environ.get("SERVER_LABEL", ""))
    parser.add_argument("--node-code")
    parser.add_argument("--cdn-domain", required=True)
    parser.add_argument("--inbound-port", required=True, type=int)
    parser.add_argument("--path", required=True)
    parser.add_argument("--proxy-host", default=os.environ.get("REGION_PROXY_HOST"))
    parser.add_argument("--proxy-protocol", choices=("socks5", "http"), default=os.environ.get("REGION_PROXY_PROTOCOL", "socks5"))
    parser.add_argument("--proxy-port", type=int, default=int(os.environ.get("REGION_PROXY_PORT", "0")))
    parser.add_argument("--proxy-user", default=os.environ.get("REGION_PROXY_USER"))
    parser.add_argument("--proxy-password", default=os.environ.get("REGION_PROXY_PASSWORD"))
    parser.add_argument("--source-port", type=int, default=10001)
    parser.add_argument("--health-host", default=os.environ.get("REGION_HEALTH_HOST", "api.ipify.org"))
    parser.add_argument("--health-port", type=int, default=int(os.environ.get("REGION_HEALTH_PORT", "443")))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def canonical_node_code(region_code: str, server_label: str, explicit: str | None = None) -> str:
    if explicit:
        value = explicit.upper()
        if not re.fullmatch(r"[A-Z]{2,8}[0-9]+", value):
            raise RuntimeError("NODE_CODE must be 2-8 letters followed by a numeric panel suffix")
        if not value.startswith(region_code.upper()):
            raise RuntimeError("NODE_CODE must start with REGION_CODE")
        return value
    suffix = re.search(r"([0-9]+)$", server_label)
    if suffix is None:
        raise RuntimeError("SERVER_LABEL requires a numeric suffix when NODE_CODE is omitted")
    return f"{region_code.upper()}{suffix.group(1)}"


def verification_state(api: Any, *, inbound_port: int, node_code: str, region_code: str, tag: str, path: str) -> dict[str, Any]:
    existing = api.request("panel/api/inbounds/list").get("obj") or []
    inbound = next((item for item in existing if int(item.get("port", 0)) == inbound_port), None)
    settings = api.request("panel/api/setting/all", "POST").get("obj") or {}
    template = load_core().json_field(settings.get("xrayTemplateConfig"), {})
    route_file = Path("/etc/nginx/bds-region-routes.d") / f"{region_code.lower()}.conf"
    expected_remark = f"{node_code} - VLESS WS CDN"
    return {
        "inbound": bool(inbound and inbound.get("remark") == expected_remark),
        "routing": template_has_tag(template, tag),
        "nginx": route_file.exists() and f"location = {path}" in route_file.read_text(encoding="utf-8"),
    }


def main() -> int:
    args = parse_args()
    if not re.fullmatch(r"[A-Za-z]{2,8}", args.region_code):
        raise RuntimeError("REGION_CODE must be 2-8 letters")
    if not re.fullmatch(r"/[A-Za-z0-9/_-]{2,80}", args.path):
        raise RuntimeError("PATH must be an absolute safe WebSocket path")
    if not (1024 <= args.inbound_port <= 65535) or not (1 <= args.proxy_port <= 65535):
        raise RuntimeError("Invalid inbound or proxy port")
    if args.dry_run and args.verify_only:
        raise RuntimeError("DRY_RUN and VERIFY_ONLY are mutually exclusive")
    node_code = canonical_node_code(args.region_code, args.server_label, args.node_code)
    required = (args.username, args.password, args.proxy_host)
    if not all(required):
        raise RuntimeError("Panel and REGION_PROXY_* credentials are required")
    if bool(args.proxy_user) != bool(args.proxy_password):
        raise RuntimeError("REGION_PROXY_USER and REGION_PROXY_PASSWORD must be provided together")
    core = load_core()
    api = core.ApiClient(args.panel_url, args.username, args.password)
    api.login()
    tag = region_tag(args.region_code)
    if args.verify_only:
        state = verification_state(api, inbound_port=args.inbound_port, node_code=node_code, region_code=args.region_code, tag=tag, path=args.path)
        if not all(state.values()):
            raise RuntimeError("Region verification failed: " + ", ".join(key for key, value in state.items() if not value))
        check_proxy_tunnel(args.proxy_protocol, args.proxy_host, args.proxy_port, args.proxy_user, args.proxy_password, args.health_host, args.health_port)
        state["proxy"] = True
        result = {"status": "verified", "nodeCode": node_code, "inboundPort": args.inbound_port, "checks": state}
        print(json.dumps(result, separators=(",", ":")) if args.json else f"Verified {node_code}: inbound, routing, and Nginx route are active.")
        return 0
    existing = api.request("panel/api/inbounds/list").get("obj") or []
    current = next((item for item in existing if int(item.get("port", 0)) == args.inbound_port), None)
    expected_remark = f"{node_code} - VLESS WS CDN"
    if current and str(current.get("remark", "")).strip() != expected_remark:
        raise RuntimeError(f"Inbound port {args.inbound_port} is already used by another panel inbound")
    source = next((item for item in existing if int(item.get("port", 0)) == args.source_port), None)
    if not source:
        raise RuntimeError(f"Source inbound port {args.source_port} was not found")
    source_settings = core.json_field(source.get("settings"), {})
    clients = source_settings.get("clients")
    if not isinstance(clients, list) or not clients:
        raise RuntimeError("Source inbound has no clients to attach")
    settings = api.request("panel/api/setting/all", "POST").get("obj") or {}
    template = core.json_field(settings.get("xrayTemplateConfig"), {})
    update_template(template, tag=tag, inbound_port=args.inbound_port, proxy_protocol=args.proxy_protocol, proxy_host=args.proxy_host, proxy_port=args.proxy_port, proxy_user=args.proxy_user, proxy_password=args.proxy_password)
    check_proxy_tunnel(args.proxy_protocol, args.proxy_host, args.proxy_port, args.proxy_user, args.proxy_password, args.health_host, args.health_port)
    if args.dry_run:
        result = {"status": "dry_run", "nodeCode": node_code, "clients": len(clients), "inboundPort": args.inbound_port, "outboundTag": tag}
        print(json.dumps(result, separators=(",", ":")) if args.json else f"Dry run passed: {node_code} will attach {len(clients)} clients on {args.inbound_port} via {tag}.")
        return 0
    stream = {"network": "ws", "security": "none", "externalProxy": core.external_proxy(args.cdn_domain, 443, True, sni=args.cdn_domain), "wsSettings": {"acceptProxyProtocol": False, "host": args.cdn_domain, "path": args.path, "headers": {"Host": args.cdn_domain}}}
    payload = {"enable": True, "remark": f"{node_code} - VLESS WS CDN", "listen": "127.0.0.1", "port": args.inbound_port, "protocol": "vless", "settings": {"clients": clients, "decryption": "none", "fallbacks": []}, "streamSettings": stream, "sniffing": core.sniffing(), "expiryTime": 0, "total": 0, "trafficReset": "never", "subSortIndex": 100}
    if current:
        payload["id"] = current["id"]
        api.request(f"panel/api/inbounds/update/{current['id']}", "POST", payload)
    else:
        api.request("panel/api/inbounds/add", "POST", payload)
    # Some 3x-UI releases omit auto-detect fields from setting/all and then
    # reset them to defaults during setting/update. Re-assert the client
    # compatibility contract whenever the Xray template is saved.
    settings.update({
        "subJsonEnable": True,
        "subJsonAutoDetect": True,
        "subJsonUserAgentRegex": "(?i)hiddify",
        "subJsonPath": "/json/",
    })
    settings["xrayTemplateConfig"] = json.dumps(template, separators=(",", ":"))
    api.request("panel/api/setting/update", "POST", settings)
    refreshed = api.request("panel/api/inbounds/list").get("obj") or []
    spec = {**payload, "streamSettings": stream}
    core.configure_hosts(api, refreshed, [spec])
    route_dir = Path("/etc/nginx/bds-region-routes.d")
    route_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    route_file = route_dir / f"{args.region_code.lower()}.conf"
    route_file.write_text(nginx_location(args.path, args.inbound_port), encoding="utf-8")
    subprocess.run(["nginx", "-t"], check=True)
    subprocess.run(["systemctl", "reload", "nginx"], check=True)
    persisted = api.request("panel/api/setting/all", "POST").get("obj") or {}
    persisted_template = core.json_field(persisted.get("xrayTemplateConfig"), {})
    if not template_has_tag(persisted_template, tag):
        dsn = os.environ.get("XUI_DB_DSN", "")
        if not dsn:
            raise RuntimeError("3x-UI did not persist xrayTemplateConfig and XUI_DB_DSN is unavailable for the PostgreSQL fallback")
        persist_postgres_template(dsn, template)
        subprocess.run(["systemctl", "restart", "x-ui"], check=True)
        for _ in range(30):
            if subprocess.run(["systemctl", "is-active", "--quiet", "x-ui"]).returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("x-ui did not become active after the Xray template update")
    state = verification_state(api, inbound_port=args.inbound_port, node_code=node_code, region_code=args.region_code, tag=tag, path=args.path)
    if not all(state.values()):
        raise RuntimeError("Post-apply region verification failed")
    result = {"status": "configured", "nodeCode": node_code, "clients": len(clients), "inboundPort": args.inbound_port, "checks": state}
    print(json.dumps(result, separators=(",", ":")) if args.json else f"Configured {node_code} region for {len(clients)} clients. Proxy credentials were not printed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
