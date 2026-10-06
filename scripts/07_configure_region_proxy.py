#!/usr/bin/env python3
"""Add or update one CDN VLESS inbound routed through a regional proxy."""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
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


def parse_xray_template(value: Any) -> dict[str, Any]:
    config_keys = {"inbounds", "outbounds", "routing", "log", "api", "dns", "policy", "stats"}
    for _ in range(8):
        if isinstance(value, dict):
            if config_keys.intersection(value):
                return value
            nested = value.get("xraySetting", value.get("xrayTemplateConfig"))
            if nested is None:
                return {}
            value = nested
            continue
        if isinstance(value, str) and value.strip():
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                return {}
            continue
        return {}
    return {}


def read_xray_template(api: Any, core: Any) -> dict[str, Any]:
    # Prefer the panel's Xray-specific reader, but retain setting/all for
    # older builds and normalize legacy response-shaped JSON wrappers.
    try:
        result = api.request("panel/api/xray/", "POST").get("obj") or {}
        template = parse_xray_template(result.get("xraySetting") if isinstance(result, dict) and "xraySetting" in result else result)
        if template:
            return template
    except RuntimeError:
        pass
    settings = api.request("panel/api/setting/all", "POST").get("obj") or {}
    template = parse_xray_template(settings.get("xrayTemplateConfig") if isinstance(settings, dict) else None)
    if not template:
        raise RuntimeError("3x-UI did not return a usable Xray template")
    return template


def save_xray_template(api: Any, template: dict[str, Any]) -> None:
    # 3x-UI persists Xray templates through this dedicated form endpoint;
    # setting/update may return success without storing xrayTemplateConfig.
    api.request(
        "panel/api/xray/update",
        "POST",
        form={"xraySetting": json.dumps(template, separators=(",", ":"))},
    )


def restart_xray(api: Any) -> None:
    api.request("panel/api/server/restartXrayService", "POST")


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


NGINX_REGION_INCLUDE = "/etc/nginx/bds-region-routes.d/*.conf"


def _matching_brace(text: str, opening: int) -> int:
    depth = 0
    quote = ""
    escaped = False
    comment = False
    for index in range(opening, len(text)):
        char = text[index]
        if comment:
            if char == "\n":
                comment = False
            continue
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char == "#":
            comment = True
        elif char in ("'", '"'):
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    raise RuntimeError("Unbalanced braces in Nginx configuration")


def nginx_server_blocks(config: str) -> list[tuple[str, int, int]]:
    """Return server blocks and their source offsets, ignoring braces in comments/strings."""
    result = []
    for match in re.finditer(r"(?m)^[ \t]*server\s*\{", config):
        opening = config.find("{", match.start(), match.end())
        closing = _matching_brace(config, opening)
        result.append((config[match.start():closing + 1], match.start(), closing + 1))
    return result


def is_cdn_tls_server(block: str, cdn_domain: str) -> bool:
    names = re.findall(r"(?m)^\s*server_name\s+([^;]+);", block)
    if not any(cdn_domain in value.split() for value in names):
        return False
    for value in re.findall(r"(?m)^\s*listen\s+([^;]+);", block):
        parts = value.split()
        if parts and parts[0].rsplit(":", 1)[-1] == "443" and "ssl" in parts[1:]:
            return True
    return False


def cdn_server_block(config: str, cdn_domain: str) -> tuple[str, int, int]:
    matches = [item for item in nginx_server_blocks(config) if is_cdn_tls_server(item[0], cdn_domain)]
    if len(matches) != 1:
        raise RuntimeError(f"Expected one active HTTPS CDN server for {cdn_domain}; found {len(matches)}")
    return matches[0]


def nginx_config_sections(dump: str) -> list[tuple[str, str]]:
    markers = list(re.finditer(r"(?m)^# configuration file (.+):\s*$", dump))
    return [
        (marker.group(1), dump[marker.end():markers[index + 1].start() if index + 1 < len(markers) else len(dump)])
        for index, marker in enumerate(markers)
    ]


def active_cdn_config(dump: str, cdn_domain: str) -> tuple[Path, str]:
    matches: list[tuple[Path, str]] = []
    for source, text in nginx_config_sections(dump):
        path = Path(source)
        for block, _, _ in nginx_server_blocks(text):
            if is_cdn_tls_server(block, cdn_domain):
                matches.append((path.resolve(), block))
    if len(matches) != 1:
        raise RuntimeError(f"Expected one loaded HTTPS CDN config for {cdn_domain}; found {len(matches)}")
    return matches[0]


def has_region_route_include(block: str) -> bool:
    return re.search(
        rf"(?m)^\s*include\s+{re.escape(NGINX_REGION_INCLUDE)}\s*;",
        block,
    ) is not None


def add_region_route_include(config: str, cdn_domain: str) -> tuple[str, bool]:
    block, start, end = cdn_server_block(config, cdn_domain)
    if has_region_route_include(block):
        return config, False
    closing = end - 1
    updated = config[:closing].rstrip() + f"\n\n    include {NGINX_REGION_INCLUDE};\n" + config[closing:]
    return updated, True


def ensure_region_route_include(cdn_domain: str) -> None:
    """Repair the CDN vhost if older node setup omitted the dynamic region include."""
    dump = subprocess.run(["nginx", "-T"], check=True, capture_output=True, text=True).stdout
    source_path, active_block = active_cdn_config(dump, cdn_domain)
    if has_region_route_include(active_block):
        return
    if not source_path.is_file():
        raise RuntimeError("The active CDN Nginx source file is missing; refusing to guess a config path")
    original = source_path.read_text(encoding="utf-8")
    updated, changed = add_region_route_include(original, cdn_domain)
    if not changed:
        raise RuntimeError("Could not safely add the region route include to the active CDN server")
    mode = source_path.stat().st_mode & 0o777
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=source_path.parent, delete=False) as temporary:
            temporary.write(updated)
            temporary_path = Path(temporary.name)
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, source_path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def check_local_websocket_route(cdn_domain: str, path: str) -> None:
    """Verify the active local CDN vhost forwards a WebSocket upgrade to its inbound."""
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {cdn_domain}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode("ascii")
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", 443), timeout=8) as connection:
        with context.wrap_socket(connection, server_hostname=cdn_domain) as secure:
            secure.settimeout(8)
            secure.sendall(request)
            response = bytearray()
            while b"\r\n\r\n" not in response and len(response) < 16384:
                chunk = secure.recv(2048)
                if not chunk:
                    break
                response.extend(chunk)
    status = bytes(response).split(b"\r\n", 1)[0]
    if not re.match(br"HTTP/1\.[01] 101(?:\s|$)", status):
        raise RuntimeError("Local CDN WebSocket route did not return HTTP 101")


def nginx_route_is_active(cdn_domain: str, path: str) -> bool:
    try:
        dump = subprocess.run(["nginx", "-T"], check=True, capture_output=True, text=True).stdout
        _, block = active_cdn_config(dump, cdn_domain)
        if not has_region_route_include(block):
            return False
        check_local_websocket_route(cdn_domain, path)
        return True
    except (OSError, RuntimeError, subprocess.CalledProcessError, ssl.SSLError, socket.timeout):
        return False


def template_has_tag(value: object, tag: str) -> bool:
    if not isinstance(value, dict):
        return False
    return any(isinstance(item, dict) and item.get("tag") == tag for item in value.get("outbounds", [])) and any(
        isinstance(item, dict) and item.get("outboundTag") == tag
        for item in (value.get("routing") or {}).get("rules", [])
    )


def xray_route_state(template: dict[str, Any], runtime: object, tag: str) -> dict[str, bool]:
    template_rules = (template.get("routing") or {}).get("rules", [])
    runtime_outbounds = runtime.get("outbounds", []) if isinstance(runtime, dict) else []
    runtime_rules = (runtime.get("routing") or {}).get("rules", []) if isinstance(runtime, dict) else []
    return {
        "outbound": any(isinstance(item, dict) and item.get("tag") == tag for item in template.get("outbounds", []))
        and any(isinstance(item, dict) and item.get("tag") == tag for item in runtime_outbounds),
        "routing": any(isinstance(item, dict) and item.get("outboundTag") == tag for item in template_rules)
        and any(isinstance(item, dict) and item.get("outboundTag") == tag for item in runtime_rules),
    }


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


def enable_read_request_retries(api: Any, *, sleep_fn=time.sleep, max_attempts: int = 6) -> None:
    """Retry transient connection refusals for idempotent 3x-UI reads only."""
    original_request = api.request
    read_only_post_paths = {"panel/api/setting/all", "panel/api/xray/"}

    def request(path: str, method: str = "GET", payload: Any = None, form: dict[str, str] | None = None) -> dict[str, Any]:
        retryable = method.upper() == "GET" or (method.upper() == "POST" and path.lstrip("/") in read_only_post_paths)
        for attempt in range(max_attempts if retryable else 1):
            try:
                return original_request(path, method, payload, form)
            except RuntimeError as exc:
                transient_refusal = re.search(
                    r"3x-UI request failed on [A-Za-z0-9_/-]+:.*(?:Connection refused|ECONNREFUSED|Errno 111)",
                    str(exc),
                    re.IGNORECASE,
                )
                if not retryable or not transient_refusal or attempt + 1 >= max_attempts:
                    raise
                sleep_fn(min(0.5 * (2**attempt), 4.0))

        raise RuntimeError("3x-UI read retry loop ended unexpectedly")

    api.request = request


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


def verification_state(api: Any, *, inbound_port: int, node_code: str, region_code: str, tag: str, path: str, cdn_domain: str) -> dict[str, Any]:
    existing = api.request("panel/api/inbounds/list").get("obj") or []
    inbound = next((item for item in existing if int(item.get("port", 0)) == inbound_port), None)
    template = read_xray_template(api, load_core())
    runtime = api.request("panel/api/server/getConfigJson").get("obj") or {}
    expected_remark = f"{node_code} - VLESS WS CDN"
    route_state = xray_route_state(template, runtime, tag)
    return {
        "inbound": bool(inbound and inbound.get("remark") == expected_remark),
        **route_state,
        "nginx": nginx_route_is_active(cdn_domain, path),
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
    enable_read_request_retries(api)
    api.login()
    tag = region_tag(args.region_code)
    if args.verify_only:
        state = verification_state(api, inbound_port=args.inbound_port, node_code=node_code, region_code=args.region_code, tag=tag, path=args.path, cdn_domain=args.cdn_domain)
        if not all(state.values()):
            raise RuntimeError("Region verification failed: " + ", ".join(key for key, value in state.items() if not value))
        check_proxy_tunnel(args.proxy_protocol, args.proxy_host, args.proxy_port, args.proxy_user, args.proxy_password, args.health_host, args.health_port)
        state["proxy"] = True
        result = {"status": "verified", "nodeCode": node_code, "inboundPort": args.inbound_port, "checks": state}
        print(json.dumps(result, separators=(",", ":")) if args.json else f"Verified {node_code}: inbound, routing, proxy tunnel, and live Nginx WebSocket route are active.")
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
    template = read_xray_template(api, core)
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
    save_xray_template(api, template)
    refreshed = api.request("panel/api/inbounds/list").get("obj") or []
    spec = {**payload, "streamSettings": stream}
    core.configure_hosts(api, refreshed, [spec])
    restart_xray(api)
    route_dir = Path("/etc/nginx/bds-region-routes.d")
    route_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    route_file = route_dir / f"{args.region_code.lower()}.conf"
    route_file.write_text(nginx_location(args.path, args.inbound_port), encoding="utf-8")
    ensure_region_route_include(args.cdn_domain)
    subprocess.run(["nginx", "-t"], check=True)
    subprocess.run(["systemctl", "reload", "nginx"], check=True)
    state = verification_state(api, inbound_port=args.inbound_port, node_code=node_code, region_code=args.region_code, tag=tag, path=args.path, cdn_domain=args.cdn_domain)
    if not all(state.values()):
        failed_checks = ", ".join(key for key, value in state.items() if not value)
        raise RuntimeError(f"Post-apply region verification failed: {failed_checks}")
    result = {"status": "configured", "nodeCode": node_code, "clients": len(clients), "inboundPort": args.inbound_port, "checks": state}
    print(json.dumps(result, separators=(",", ":")) if args.json else f"Configured {node_code} region for {len(clients)} clients. Proxy credentials were not printed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
