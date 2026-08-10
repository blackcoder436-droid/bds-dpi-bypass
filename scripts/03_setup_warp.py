#!/usr/bin/env python3
"""Register Cloudflare WARP and update 3x-UI through its HTTP API."""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import sys
from datetime import datetime, timezone
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


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
            with urllib.request.urlopen(req, timeout=20) as response:
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
        with urllib.request.urlopen(request, timeout=20) as response:
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
    return parser.parse_args()


def warp_inbound_tags(api: ApiClient) -> list[str]:
    """Return the runtime tags for BDS's four Cloudflare/CDN inbounds.

    3x-UI 3.6 generates tags such as ``in-10001-tcp``.  They must be read
    from the panel instead of guessed: a stale tag silently bypasses WARP and
    exposes the VPS as the user's egress IP.
    """
    result = api.request("panel/api/inbounds/list")
    inbounds = result.get("obj") or []
    if not isinstance(inbounds, list):
        raise RuntimeError("3x-UI returned an invalid inbound list")
    tags_by_port = {
        int(item["port"]): str(item["tag"])
        for item in inbounds
        if isinstance(item, dict)
        and item.get("port") is not None
        and item.get("tag")
    }
    required_ports = (10001, 10002, 10003, 10004)
    missing = [str(port) for port in required_ports if port not in tags_by_port]
    if missing:
        raise RuntimeError(f"Missing CDN inbound tag(s) for port(s): {', '.join(missing)}")
    return [tags_by_port[port] for port in required_ports]


def main() -> int:
    args = parse_args()
    if not args.username or not args.password:
        raise RuntimeError("XUI_USERNAME and XUI_PASSWORD must be provided through the environment or arguments")
    api = ApiClient(args.panel_url, args.username, args.password)
    api.login()
    inbound_tags = warp_inbound_tags(api)
    xray_response = api.request("panel/api/xray/", "POST")
    obj = xray_response.get("obj") or {}
    if isinstance(obj, str):
        try:
            obj = json.loads(obj)
        except json.JSONDecodeError as exc:
            raise RuntimeError("3x-UI returned an invalid Xray template wrapper") from exc
    raw_template = obj.get("xraySetting") if isinstance(obj, dict) else None
    if isinstance(raw_template, str):
        template = json.loads(raw_template)
    elif isinstance(raw_template, dict):
        template = raw_template
    else:
        raise RuntimeError("3x-UI did not return an Xray template")

    current_outbounds = template.get("outbounds", [])
    existing_warp = next((entry for entry in current_outbounds if entry.get("tag") == "warp"), None)
    outbounds = [entry for entry in current_outbounds if entry.get("tag") != "warp"]
    if existing_warp:
        outbounds.append(existing_warp)
    else:
        warp = register_warp()
        config = warp.get("config") or {}
        peer = (config.get("peers") or [{}])[0]
        private_key = str(warp.get("_private_key", ""))
        public_key = str(peer.get("public_key", ""))
        endpoint = str((peer.get("endpoint") or {}).get("host", ""))
        addresses = config.get("interface", {}).get("addresses", {})
        client_id = str(config.get("client_id", ""))
        if not all([private_key, public_key, endpoint, addresses.get("v4"), client_id]):
            raise RuntimeError("Cloudflare WARP returned an incomplete configuration")
        reserved = list(base64.b64decode(client_id))
        outbounds.append({
            "protocol": "wireguard",
            "tag": "warp",
            "settings": {
                "secretKey": private_key,
                "address": [f"{addresses['v4']}/32"] + ([f"{addresses['v6']}/128"] if addresses.get("v6") else []),
                "peers": [{"publicKey": public_key, "endpoint": endpoint, "allowedIPs": ["0.0.0.0/0", "::/0"]}],
                "reserved": reserved,
                "mtu": 1280,
            },
        })
    routing = template.setdefault("routing", {})
    rules = [rule for rule in routing.get("rules", []) if rule.get("outboundTag") != "warp"]
    rules.append({"type": "field", "inboundTag": inbound_tags, "outboundTag": "warp"})
    routing["rules"] = rules
    template["outbounds"] = outbounds
    api.request("panel/api/xray/update", "POST", form={"xraySetting": json.dumps(template, separators=(",", ":")), "outboundTestUrl": "https://www.google.com/generate_204"})
    print("Cloudflare WARP outbound configured through the 3x-UI API.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
