#!/usr/bin/env python3
"""Idempotently configure a BDS node through the 3x-UI HTTP API.

This intentionally does not read or write x-ui.db. The same flow therefore
works with both PostgreSQL and SQLite panel backends and stays compatible with
3x-UI migrations.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ALL_PORTS = (10001, 10002, 10003, 10004, 10005, 8443)


@dataclass
class ApiClient:
    base_url: str
    username: str
    password: str

    def __post_init__(self) -> None:
        self.cookies: str = ""
        self.csrf_token: str = ""

    def request(self, path: str, method: str = "GET", payload: Any = None, form: dict[str, str] | None = None) -> dict[str, Any]:
        url = self.base_url.rstrip("/") + "/" + path.lstrip("/")
        headers = {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"}
        body: bytes | None = None
        if form is not None:
            body = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif payload is not None:
            body = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        if self.cookies:
            headers["Cookie"] = self.cookies
        if self.csrf_token:
            headers["X-CSRF-Token"] = self.csrf_token
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                set_cookie = response.headers.get_all("Set-Cookie") or []
                if set_cookie:
                    self.cookies = "; ".join(value.split(";", 1)[0] for value in set_cookie)
                raw = response.read().decode()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise RuntimeError(f"3x-UI HTTP {exc.code} on {path}: {detail[:200]}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"3x-UI request failed on {path}: {exc.reason}") from exc
        try:
            result = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"3x-UI returned non-JSON response on {path}") from exc
        if not isinstance(result, dict) or result.get("success") is False:
            raise RuntimeError(f"3x-UI rejected {path}: {result.get('msg', 'unknown error')}")
        return result

    def login(self) -> None:
        token = self.request("csrf-token").get("obj")
        if isinstance(token, str):
            self.csrf_token = token
        self.request("login", "POST", {"username": self.username, "password": self.password, "twoFactorCode": ""})


@dataclass(frozen=True)
class ProfileValues:
    client_id: str
    email: str
    sub_id: str
    password: str

    def as_dict(self) -> dict[str, str]:
        return {
            "client_id": self.client_id,
            "email": self.email,
            "sub_id": self.sub_id,
            "password": self.password,
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--panel-url", required=True)
    parser.add_argument("--username", default=os.environ.get("XUI_USERNAME"))
    parser.add_argument("--password", default=os.environ.get("XUI_PASSWORD"))
    parser.add_argument("--sub-domain", required=True)
    parser.add_argument("--sub-port", type=int, required=True)
    parser.add_argument("--sub-path", default="sub")
    parser.add_argument("--cdn-domain", required=True)
    parser.add_argument("--direct-domain", required=True)
    parser.add_argument("--reality-dest", default="www.google.com:443")
    parser.add_argument("--reality-server-name", default="www.google.com")
    parser.add_argument("--server-label", default=os.environ.get("SERVER_LABEL", "SG1"))
    parser.add_argument("--profiles-file", default="/etc/bds-dpi-bypass/subscription-profiles.json")
    parser.add_argument("--dry-run", action="store_true", help="Validate the unified profile without changing panel state")
    return parser.parse_args()


def json_field(value: Any, fallback: dict[str, Any]) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else fallback.copy()
        except json.JSONDecodeError:
            pass
    return fallback.copy()


def sniffing() -> dict[str, Any]:
    return {"enabled": True, "destOverride": ["http", "tls", "quic"], "metadataOnly": False, "routeOnly": False}


def random_token(length: int) -> str:
    value = ""
    while len(value) < length:
        value += secrets.token_urlsafe(length).replace("-", "").replace("_", "")
    return value[:length]


def new_profile(prefix: str) -> ProfileValues:
    return ProfileValues(
        client_id=str(uuid.uuid4()),
        email=f"bds-{prefix}-{random_token(10).lower()}",
        sub_id=random_token(16).lower(),
        password=random_token(24),
    )


def parse_profile(value: Any, name: str) -> ProfileValues:
    if not isinstance(value, dict):
        raise RuntimeError(f"Invalid {name} client in the profiles file")
    fields = {key: str(value.get(key, "")).strip() for key in ("client_id", "email", "sub_id", "password")}
    if not all(fields.values()):
        raise RuntimeError(f"Incomplete {name} client in the profiles file")
    try:
        uuid.UUID(fields["client_id"])
    except ValueError as exc:
        raise RuntimeError(f"Invalid {name} client UUID in the profiles file") from exc
    return ProfileValues(**fields)


def load_profiles(path: Path) -> dict[str, ProfileValues]:
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Cannot read subscription profiles file: {path}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"Invalid subscription profiles file: {path}")
    # v2 is the canonical format. Keep the old Advanced identity in memory
    # for one migration pass so it can be removed from the panel inbounds.
    if isinstance(value.get("client"), dict):
        profiles = {"client": parse_profile(value["client"], "unified")}
        if isinstance(value.get("advanced"), dict):
            profiles["legacy_advanced"] = parse_profile(value["advanced"], "legacy advanced")
        return profiles

    # v1 used separate Main and Advanced identities. Main becomes the single
    # client; Advanced is retained only long enough for migration cleanup.
    if isinstance(value.get("main"), dict):
        profiles = {"client": parse_profile(value["main"], "legacy main")}
        if isinstance(value.get("advanced"), dict):
            profiles["legacy_advanced"] = parse_profile(value["advanced"], "legacy advanced")
        return profiles
    raise RuntimeError("Subscription profiles file is missing unified client data")


def save_profiles(path: Path, profiles: dict[str, ProfileValues], sub_base_url: str, server_label: str = "SG1") -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    client = profiles.get("client") or profiles.get("main")
    if client is None:
        raise RuntimeError("Cannot save profiles without a unified client")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}", server_label):
        raise RuntimeError("SERVER_LABEL must be 1-32 letters, numbers, underscores, or hyphens")
    payload = {
        "version": 2,
        "server_label": server_label,
        "sub_base_url": sub_base_url.rstrip("/") + "/",
        "client": client.as_dict(),
    }
    temporary_name = ""
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
            temporary_name = handle.name
            os.chmod(temporary_name, 0o600)
            json.dump(payload, handle, indent=2)
            handle.write("\n")
        os.replace(temporary_name, path)
        os.chmod(path, 0o600)
    finally:
        if temporary_name and os.path.exists(temporary_name):
            os.unlink(temporary_name)


def extract_existing_profile(
    existing: list[dict[str, Any]],
    ports: tuple[int, ...],
    excluded_sub_ids: set[str] | None = None,
) -> ProfileValues | None:
    excluded_sub_ids = excluded_sub_ids or set()
    candidates: dict[tuple[str, str], dict[str, Any]] = {}
    for item in existing:
        if not isinstance(item, dict):
            continue
        try:
            port = int(item.get("port"))
        except (TypeError, ValueError):
            continue
        if port not in ports:
            continue
        settings = json_field(item.get("settings"), {})
        clients = settings.get("clients")
        if not isinstance(clients, list):
            continue
        for client in clients:
            if not isinstance(client, dict):
                continue
            email = str(client.get("email", "")).strip()
            sub_id = str(client.get("subId", "")).strip()
            if not email or not sub_id or sub_id in excluded_sub_ids:
                continue
            values = candidates.setdefault((email, sub_id), {"email": email, "sub_id": sub_id, "ports": set()})
            values["ports"].add(port)
            if client.get("id"):
                values.setdefault("client_id", str(client["id"]))
            password = client.get("password") or settings.get("password")
            if password:
                values.setdefault("password", str(password))
    complete = [value for value in candidates.values() if value.get("client_id") and value.get("password")]
    if complete:
        values = max(complete, key=lambda value: len(value["ports"]))
        return ProfileValues(values["client_id"], values["email"], values["sub_id"], values["password"])
    return None


def resolve_profiles(existing: list[dict[str, Any]], profiles_file: Path) -> dict[str, ProfileValues]:
    stored = load_profiles(profiles_file)
    client = stored.get("client") or extract_existing_profile(existing, ALL_PORTS) or new_profile("client")
    profiles = {"client": client}
    legacy_advanced = stored.get("legacy_advanced")
    if legacy_advanced and (legacy_advanced.sub_id != client.sub_id or legacy_advanced.email != client.email):
        profiles["legacy_advanced"] = legacy_advanced
    return profiles


def reality_public_key(private_key: str) -> str:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import x25519
    except ImportError as exc:
        raise RuntimeError("python3-cryptography is required for Reality key handling") from exc
    padded = private_key + "=" * (-len(private_key) % 4)
    private = x25519.X25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(padded))
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.urlsafe_b64encode(public).decode().rstrip("=")


def extract_existing_reality_key(existing: list[dict[str, Any]]) -> tuple[str, str, list[str]] | None:
    for item in existing:
        if not isinstance(item, dict):
            continue
        try:
            port = int(item.get("port"))
        except (TypeError, ValueError):
            continue
        if port != 8443:
            continue
        stream = json_field(item.get("streamSettings"), {})
        reality = stream.get("realitySettings")
        if isinstance(reality, dict) and reality.get("privateKey"):
            private_key = str(reality["privateKey"])
            client_settings = reality.get("settings") if isinstance(reality.get("settings"), dict) else {}
            public_key = str(client_settings.get("publicKey") or reality.get("publicKey") or reality_public_key(private_key))
            short_ids = [str(value) for value in reality.get("shortIds", []) if value]
            return private_key, public_key, short_ids or [secrets.token_hex(4)]
    return None


def external_proxy(host: str, port: int, force_tls: bool = False) -> list[dict[str, Any]]:
    item: dict[str, Any] = {"dest": host, "port": port}
    if force_tls:
        item["forceTls"] = "tls"
    return [item]


def build_specs(args: argparse.Namespace, profiles: dict[str, ProfileValues], private_key: str, public_key: str, short_ids: list[str]) -> list[dict[str, Any]]:
    cdn_proxy = external_proxy(args.cdn_domain, 443, True)
    direct_ss_proxy = external_proxy(args.direct_domain, 10005)
    direct_reality_proxy = external_proxy(args.direct_domain, 8443)
    client = profiles["client"]
    common = {"email": client.email, "limitIp": 0, "totalGB": 0, "expiryTime": 0, "enable": True, "tgId": 0, "subId": client.sub_id, "reset": 0}
    ws = lambda path: {"network": "ws", "security": "none", "externalProxy": cdn_proxy, "wsSettings": {"acceptProxyProtocol": False, "host": args.cdn_domain, "path": path, "headers": {"Host": args.cdn_domain}}}
    return [
        {"profile": "client", "subSortIndex": 10, "protocol": "vless", "port": 10001, "remark": f"{args.server_label} - VLESS WS CDN", "listen": "127.0.0.1", "shareAddrStrategy": "custom", "shareAddr": args.cdn_domain, "settings": {"clients": [{**common, "id": client.client_id}], "decryption": "none", "fallbacks": []}, "streamSettings": ws("/vless-ws")},
        {"profile": "client", "subSortIndex": 20, "protocol": "vmess", "port": 10002, "remark": f"{args.server_label} - VMess WS CDN", "listen": "127.0.0.1", "shareAddrStrategy": "custom", "shareAddr": args.cdn_domain, "settings": {"clients": [{**common, "id": client.client_id, "alterId": 0, "security": "aes-128-gcm"}]}, "streamSettings": ws("/vmess-ws")},
        {"profile": "client", "subSortIndex": 30, "protocol": "trojan", "port": 10003, "remark": f"{args.server_label} - Trojan WS CDN", "listen": "127.0.0.1", "shareAddrStrategy": "custom", "shareAddr": args.cdn_domain, "settings": {"clients": [{**common, "password": client.password}]}, "streamSettings": ws("/trojan-ws")},
        {"profile": "client", "subSortIndex": 40, "protocol": "shadowsocks", "port": 10004, "remark": f"{args.server_label} - Shadowsocks WS CDN", "listen": "127.0.0.1", "shareAddrStrategy": "custom", "shareAddr": args.cdn_domain, "settings": {"method": "chacha20-ietf-poly1305", "password": client.password, "network": "tcp,udp", "clients": [{**common, "method": "chacha20-ietf-poly1305", "password": client.password}]}, "streamSettings": ws("/ss-ws")},
        {"profile": "client", "subSortIndex": 50, "protocol": "shadowsocks", "port": 10005, "remark": f"{args.server_label} - Shadowsocks Direct", "listen": "0.0.0.0", "shareAddrStrategy": "custom", "shareAddr": args.direct_domain, "settings": {"method": "chacha20-ietf-poly1305", "password": client.password, "network": "tcp,udp", "ivCheck": False, "clients": [{**common, "method": "chacha20-ietf-poly1305", "password": client.password}]}, "streamSettings": {"network": "tcp", "security": "none", "externalProxy": direct_ss_proxy, "tcpSettings": {"acceptProxyProtocol": False, "header": {"type": "none"}}}},
        {"profile": "client", "subSortIndex": 60, "protocol": "vless", "port": 8443, "remark": f"{args.server_label} - VLESS Reality Direct", "listen": "0.0.0.0", "shareAddrStrategy": "custom", "shareAddr": args.direct_domain, "settings": {"clients": [{**common, "id": client.client_id, "flow": "xtls-rprx-vision"}], "decryption": "none", "fallbacks": []}, "streamSettings": {"network": "tcp", "security": "reality", "externalProxy": direct_reality_proxy, "realitySettings": {"show": False, "xver": 0, "dest": args.reality_dest, "serverNames": [args.reality_server_name], "privateKey": private_key, "settings": {"publicKey": public_key, "fingerprint": "chrome", "spiderX": "/"}, "minClientVer": "", "maxClientVer": "", "maxTimeDiff": 0, "shortIds": short_ids}, "tcpSettings": {"acceptProxyProtocol": False, "header": {"type": "none"}}}},
    ]


def configure_settings(api: ApiClient, args: argparse.Namespace) -> None:
    current = api.request("panel/api/setting/all", "POST").get("obj") or {}
    if not isinstance(current, dict):
        raise RuntimeError("Unexpected settings response")
    current.update({
        "subEnable": True,
        "subListen": "127.0.0.1",
        "subPort": args.sub_port,
        "subPath": f"/{args.sub_path.strip('/')}/",
        "subDomain": args.sub_domain,
        "subURI": f"https://{args.sub_domain}/{args.sub_path.strip('/')}/",
        "subEncrypt": True,
        "subCertFile": "",
        "subKeyFile": "",
    })
    api.request("panel/api/setting/update", "POST", current)


def merge_managed_clients(existing_item: dict[str, Any] | None, spec: dict[str, Any], profiles: dict[str, ProfileValues]) -> dict[str, Any]:
    desired_settings = dict(spec["settings"])
    desired_clients = desired_settings.get("clients")
    if not isinstance(desired_clients, list) or len(desired_clients) != 1:
        raise RuntimeError(f"Expected one managed client for inbound port {spec['port']}")
    current_settings = json_field(existing_item.get("settings"), {}) if existing_item else {}
    current_clients = current_settings.get("clients")
    managed_emails = {profile.email for profile in profiles.values()}
    managed_sub_ids = {profile.sub_id for profile in profiles.values()}
    preserved: list[dict[str, Any]] = []
    if isinstance(current_clients, list):
        for client in current_clients:
            if not isinstance(client, dict):
                continue
            if str(client.get("email", "")) in managed_emails or str(client.get("subId", "")) in managed_sub_ids:
                continue
            preserved.append(client)
    desired_settings["clients"] = preserved + desired_clients
    return desired_settings


def configure_inbounds(api: ApiClient, existing: list[dict[str, Any]], specs: list[dict[str, Any]], profiles: dict[str, ProfileValues]) -> None:
    by_port = {int(item.get("port")): item for item in existing if isinstance(item, dict) and item.get("port") is not None}
    for spec in specs:
        existing_item = by_port.get(spec["port"])
        payload = {key: value for key, value in spec.items() if key != "profile"}
        payload["settings"] = merge_managed_clients(existing_item, spec, profiles)
        payload.update({
            "enable": True,
            "expiryTime": int(existing_item.get("expiryTime", 0)) if existing_item else 0,
            "total": int(existing_item.get("total", 0)) if existing_item else 0,
            "sniffing": sniffing(),
            "trafficReset": existing_item.get("trafficReset", "never") if existing_item else "never",
        })
        if existing_item:
            payload["id"] = existing_item["id"]
            api.request(f"panel/api/inbounds/update/{existing_item['id']}", "POST", payload)
        else:
            api.request("panel/api/inbounds/add", "POST", payload)


def main() -> int:
    args = parse_args()
    if not args.username or not args.password:
        raise RuntimeError("XUI_USERNAME and XUI_PASSWORD must be provided through the environment or arguments")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}", args.server_label):
        raise RuntimeError("SERVER_LABEL must be 1-32 letters, numbers, underscores, or hyphens")
    api = ApiClient(args.panel_url, args.username, args.password)
    api.login()
    existing = api.request("panel/api/inbounds/list").get("obj") or []
    if not isinstance(existing, list):
        raise RuntimeError("Unexpected inbound list response")
    profiles_file = Path(args.profiles_file)
    profiles = resolve_profiles(existing, profiles_file)
    # 3x-UI provides its own Reality key generator; generated key material is
    # kept in the panel database and never written to the repository.
    current_key = extract_existing_reality_key(existing)
    if args.dry_run:
        private_key = current_key[0] if current_key else "dry-run-private-key"
        public_key = current_key[1] if current_key else "dry-run-public-key"
        short_ids = current_key[2] if current_key else ["dryrun00"]
        specs = build_specs(args, profiles, private_key, public_key, short_ids)
        by_port = {int(item.get("port")): item for item in existing if isinstance(item, dict) and item.get("port") is not None}
        for spec in specs:
            merge_managed_clients(by_port.get(spec["port"]), spec, profiles)
        print(f"Dry run passed: unified {args.server_label} client will cover all six inbounds; unrelated clients are preserved.")
        return 0
    configure_settings(api, args)
    key_result = (api.request("panel/api/server/getNewX25519Cert").get("obj") or {}) if current_key is None else {}
    private_key = current_key[0] if current_key else str(key_result.get("privateKey", ""))
    public_key = current_key[1] if current_key else str(key_result.get("publicKey", ""))
    short_ids = current_key[2] if current_key else [secrets.token_hex(4)]
    if not private_key or not public_key:
        raise RuntimeError("3x-UI did not return a complete X25519 key pair")
    configure_inbounds(api, existing, build_specs(args, profiles, private_key, public_key, short_ids), profiles)
    save_profiles(profiles_file, profiles, f"https://{args.sub_domain}/{args.sub_path.strip('/')}/", args.server_label)
    print(f"Configured one unified {args.server_label} client across six BDS inbounds. Profile: {profiles_file}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
