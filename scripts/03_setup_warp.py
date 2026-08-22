#!/usr/bin/env python3
"""Install and verify a Cloudflare WARP outbound through the 3x-UI API."""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import secrets
import sys
from datetime import datetime, timezone
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


WARP_TEST_URL = "https://www.google.com/generate_204"
WARP_PORTS = (500, 1701, 4500, 2408)


@dataclass
class ApiClient:
    base_url: str
    username: str
    password: str

    def __post_init__(self) -> None:
        self.cookies = ""
        self.csrf_token = ""

    def request(self, path: str, method: str = "GET", form: dict[str, str] | None = None, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        body = None
        headers = {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"}
        if form is not None:
            from urllib.parse import urlencode
            body = urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif payload is not None:
            body = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        if self.cookies:
            headers["Cookie"] = self.cookies
        if self.csrf_token:
            headers["X-CSRF-Token"] = self.csrf_token
        req = urllib.request.Request(self.base_url.rstrip("/") + "/" + path.lstrip("/"), data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                cookies = response.headers.get_all("Set-Cookie") or []
                if cookies:
                    self.cookies = "; ".join(value.split(";", 1)[0] for value in cookies)
                result = json.loads(response.read().decode())
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"3x-UI HTTP {exc.code}: {exc.read().decode(errors='replace')[:200]}") from exc
        if not isinstance(result, dict) or result.get("success") is False:
            raise RuntimeError(f"3x-UI rejected {path}: {result.get('msg', 'unknown error')}")
        return result

    def login(self) -> None:
        token = self.request("csrf-token").get("obj")
        if isinstance(token, str):
            self.csrf_token = token
        self.request("login", "POST", payload={"username": self.username, "password": self.password, "twoFactorCode": ""})


def register_warp() -> dict[str, Any]:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import x25519
    except ImportError as exc:
        raise RuntimeError("python3-cryptography is required for WARP key generation") from exc
    private = x25519.X25519PrivateKey.generate()
    private_raw = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    public_raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    private_key = base64.b64encode(private_raw).decode()
    public_key = base64.b64encode(public_raw).decode()
    request = urllib.request.Request(
        "https://api.cloudflareclient.com/v0a4005/reg",
        data=json.dumps({"key": public_key, "tos": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"), "type": "PC", "model": "bds-dpi-bypass", "name": f"bds-{secrets.token_hex(4)}"}).encode(),
        headers={"Content-Type": "application/json", "CF-Client-Version": "a-6.30-3596", "User-Agent": "okhttp/3.12.1"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            result = json.loads(response.read().decode())
            result["_private_key"] = private_key
            return result
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Cloudflare WARP registration failed: HTTP {exc.code}") from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--panel-url", required=True)
    parser.add_argument("--username", default=os.environ.get("XUI_USERNAME"))
    parser.add_argument("--password", default=os.environ.get("XUI_PASSWORD"))
    parser.add_argument("--required-ports", default="10001,10002,10003,10004")
    parser.add_argument("--verify-only", action="store_true")
    return parser.parse_args()


def parse_json_object(value: Any, error: str) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise RuntimeError(error) from exc
        if isinstance(parsed, dict):
            return parsed
    raise RuntimeError(error)


def load_xray_template(api: ApiClient) -> dict[str, Any]:
    wrapper = parse_json_object(api.request("panel/api/xray/", "POST").get("obj") or {}, "3x-UI returned an invalid Xray template wrapper")
    return parse_json_object(wrapper.get("xraySetting"), "3x-UI did not return an Xray template")


def warp_inbound_tags(api: ApiClient, required_ports: tuple[int, ...] = (10001, 10002, 10003, 10004)) -> list[str]:
    """Return 3x-UI runtime tags for the selected BDS CDN inbounds."""
    inbounds = api.request("panel/api/inbounds/list").get("obj") or []
    if not isinstance(inbounds, list):
        raise RuntimeError("3x-UI returned an invalid inbound list")
    tags_by_port = {
        int(item["port"]): str(item["tag"])
        for item in inbounds
        if isinstance(item, dict) and item.get("port") is not None and item.get("tag")
    }
    missing = [str(port) for port in required_ports if port not in tags_by_port]
    if missing:
        raise RuntimeError(f"Missing CDN inbound tag(s) for port(s): {', '.join(missing)}")
    return [tags_by_port[port] for port in required_ports]


def normalize_address(address: str, prefix: int) -> str:
    raw = str(address).strip()
    if not raw:
        return ""
    try:
        return str(ipaddress.ip_interface(raw if "/" in raw else f"{raw}/{prefix}"))
    except ValueError as exc:
        raise RuntimeError("Cloudflare WARP returned an invalid interface address") from exc


def endpoint_host_and_port(endpoint: str) -> tuple[str, int | None]:
    raw = str(endpoint).strip()
    if not raw:
        raise RuntimeError("Cloudflare WARP returned an empty endpoint")
    if raw.startswith("["):
        match = re.fullmatch(r"\[([^]]+)](?::(\d+))?", raw)
        if not match:
            raise RuntimeError("Cloudflare WARP returned an invalid endpoint")
        return match.group(1), int(match.group(2)) if match.group(2) else None
    if raw.count(":") == 1 and raw.rsplit(":", 1)[1].isdigit():
        host, port = raw.rsplit(":", 1)
        return host, int(port)
    return raw, None


def endpoint_candidates(endpoint: str) -> list[str]:
    host, offered_port = endpoint_host_and_port(endpoint)
    ports = []
    if offered_port:
        ports.append(offered_port)
    ports.extend(port for port in WARP_PORTS if port not in ports)
    rendered_host = f"[{host}]" if ":" in host else host
    return [f"{rendered_host}:{port}" for port in ports]


def build_warp_candidates(registration: dict[str, Any]) -> list[dict[str, Any]]:
    config = registration.get("config") or {}
    peer = (config.get("peers") or [{}])[0]
    endpoint_data = peer.get("endpoint") or {}
    endpoint = str(endpoint_data.get("v4") or endpoint_data.get("host") or "")
    addresses = config.get("interface", {}).get("addresses", {})
    private_key = str(registration.get("_private_key", ""))
    public_key = str(peer.get("public_key", ""))
    client_id = str(config.get("client_id", ""))
    try:
        reserved = list(base64.b64decode(client_id, validate=True))
    except (ValueError, base64.binascii.Error) as exc:
        raise RuntimeError("Cloudflare WARP returned an invalid client id") from exc
    address = [normalize_address(str(addresses.get("v4", "")), 32)]
    if addresses.get("v6"):
        address.append(normalize_address(str(addresses["v6"]), 128))
    if not all([private_key, public_key, endpoint, address[0]]) or len(reserved) != 3:
        raise RuntimeError("Cloudflare WARP returned an incomplete configuration")
    return [
        {
            "protocol": "wireguard",
            "tag": "warp",
            "settings": {
                "secretKey": private_key,
                "address": address,
                "peers": [{"publicKey": public_key, "endpoint": candidate, "allowedIPs": ["0.0.0.0/0", "::/0"]}],
                "reserved": reserved,
                "mtu": 1280,
                "domainStrategy": "ForceIPv4",
                "noKernelTun": True,
            },
        }
        for candidate in endpoint_candidates(endpoint)
    ]


def outbound_test_passed(result: dict[str, Any]) -> bool:
    obj = result.get("obj")
    if isinstance(obj, str):
        try:
            obj = json.loads(obj)
        except json.JSONDecodeError:
            return False
    return isinstance(obj, dict) and obj.get("success") is True


def test_outbound(api: ApiClient, outbound: dict[str, Any], other_outbounds: list[dict[str, Any]]) -> bool:
    for _ in range(2):
        try:
            result = api.request("panel/api/xray/testOutbound", "POST", form={
                "outbound": json.dumps(outbound, separators=(",", ":")),
                "allOutbounds": json.dumps(other_outbounds + [outbound], separators=(",", ":")),
                "mode": "real",
            })
        except RuntimeError:
            continue
        if outbound_test_passed(result):
            return True
    return False


def select_working_warp(api: ApiClient, template: dict[str, Any]) -> dict[str, Any]:
    current = template.get("outbounds") or []
    if not isinstance(current, list):
        raise RuntimeError("3x-UI returned invalid Xray outbounds")
    other_outbounds = [entry for entry in current if isinstance(entry, dict) and entry.get("tag") != "warp"]
    existing = next((entry for entry in current if isinstance(entry, dict) and entry.get("tag") == "warp"), None)
    if existing and test_outbound(api, existing, other_outbounds):
        return existing
    for candidate in build_warp_candidates(register_warp()):
        if test_outbound(api, candidate, other_outbounds):
            return candidate
    raise RuntimeError("No Cloudflare WARP endpoint passed the real outbound test")


def route_uses_all_tags(template: dict[str, Any], inbound_tags: list[str]) -> bool:
    rules = (template.get("routing") or {}).get("rules") or []
    return any(
        isinstance(rule, dict)
        and rule.get("outboundTag") == "warp"
        and set(rule.get("inboundTag") or []) == set(inbound_tags)
        for rule in rules
    )


def verify_installed_warp(api: ApiClient, template: dict[str, Any], inbound_tags: list[str]) -> None:
    outbounds = template.get("outbounds") or []
    warp = next((entry for entry in outbounds if isinstance(entry, dict) and entry.get("tag") == "warp"), None)
    if not warp:
        raise RuntimeError("Cloudflare WARP outbound is missing")
    others = [entry for entry in outbounds if isinstance(entry, dict) and entry.get("tag") != "warp"]
    if not route_uses_all_tags(template, inbound_tags):
        raise RuntimeError("Cloudflare CDN inbounds are not all routed through WARP")
    if not test_outbound(api, warp, others):
        raise RuntimeError("Cloudflare WARP failed the real outbound verification")


def main() -> int:
    args = parse_args()
    if not args.username or not args.password:
        raise RuntimeError("XUI_USERNAME and XUI_PASSWORD must be provided through the environment or arguments")
    api = ApiClient(args.panel_url, args.username, args.password)
    api.login()
    required_ports = tuple(int(value.strip()) for value in getattr(args, "required_ports", "10001,10002,10003,10004").split(",") if value.strip())
    if not required_ports:
        raise RuntimeError("At least one WARP-routed inbound port is required")
    inbound_tags = warp_inbound_tags(api, required_ports)
    template = load_xray_template(api)
    if args.verify_only:
        verify_installed_warp(api, template, inbound_tags)
        print("Cloudflare WARP real outbound and all four CDN routes verified.")
        return 0

    warp = select_working_warp(api, template)
    current_outbounds = template.get("outbounds") or []
    template["outbounds"] = [entry for entry in current_outbounds if isinstance(entry, dict) and entry.get("tag") != "warp"] + [warp]
    routing = template.setdefault("routing", {})
    rules = [rule for rule in routing.get("rules", []) if not (isinstance(rule, dict) and rule.get("outboundTag") == "warp")]
    rules.append({"type": "field", "inboundTag": inbound_tags, "outboundTag": "warp"})
    routing["rules"] = rules
    api.request("panel/api/xray/update", "POST", form={"xraySetting": json.dumps(template, separators=(",", ":")), "outboundTestUrl": WARP_TEST_URL})
    verify_installed_warp(api, load_xray_template(api), inbound_tags)
    print("Cloudflare WARP configured and passed real outbound verification for all CDN routes.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
