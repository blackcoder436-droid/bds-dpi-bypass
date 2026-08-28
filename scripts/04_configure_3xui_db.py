#!/usr/bin/env python3
"""Idempotently configure a BDS node through the 3x-UI HTTP API.

This intentionally does not read or write x-ui.db. The same flow therefore
works with both PostgreSQL and SQLite panel backends and stays compatible with
3x-UI migrations.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import socket
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
RETIRED_PORTS = (10004, 8443)


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
    parser.add_argument("--disable-outline-direct", action="store_true")
    parser.add_argument("--server-label", default=os.environ.get("SERVER_LABEL", "SG1"))
    parser.add_argument("--deployment-profile", choices=("full", "cdn_vless_backup"), default="full")
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


def external_proxy(
    host: str,
    port: int,
    force_tls: bool = False,
    *,
    sni: str | None = None,
) -> list[dict[str, Any]]:
    item: dict[str, Any] = {"dest": host, "port": port}
    if force_tls:
        item["forceTls"] = "tls"
    if sni:
        item["sni"] = sni
    return [item]


def resolve_cdn_ipv4(domain: str) -> list[str]:
    addresses = sorted({item[4][0] for item in socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)})
    if not addresses:
        raise RuntimeError(f"CDN domain has no IPv4 address: {domain}")
    return addresses


def build_specs(args: argparse.Namespace, profiles: dict[str, ProfileValues]) -> list[dict[str, Any]]:
    cdn_addresses = resolve_cdn_ipv4(args.cdn_domain)
    direct_ss_proxy = external_proxy(args.direct_domain, 10005)
    client = profiles["client"]
    common = {"email": client.email, "limitIp": 0, "totalGB": 0, "expiryTime": 0, "enable": True, "tgId": 0, "subId": client.sub_id, "reset": 0}
    def ws(path: str, address: str) -> dict[str, Any]:
        return {"network": "ws", "security": "none", "externalProxy": external_proxy(address, 443, True, sni=args.cdn_domain), "wsSettings": {"acceptProxyProtocol": False, "host": args.cdn_domain, "path": path, "headers": {"Host": args.cdn_domain}}}
    address = lambda index: cdn_addresses[index % len(cdn_addresses)]
    specs = [
        {"profile": "client", "subSortIndex": 10, "protocol": "vless", "port": 10001, "remark": f"{args.server_label} - VLESS WS CDN", "listen": "127.0.0.1", "shareAddrStrategy": "custom", "shareAddr": address(0), "settings": {"clients": [{**common, "id": client.client_id}], "decryption": "none", "fallbacks": []}, "streamSettings": ws("/vless-ws", address(0))},
        {"profile": "client", "subSortIndex": 20, "protocol": "vmess", "port": 10002, "remark": f"{args.server_label} - VMess WS CDN", "listen": "127.0.0.1", "shareAddrStrategy": "custom", "shareAddr": address(1), "settings": {"clients": [{**common, "id": client.client_id, "alterId": 0, "security": "aes-128-gcm"}]}, "streamSettings": ws("/vmess-ws", address(1))},
        {"profile": "client", "subSortIndex": 30, "protocol": "trojan", "port": 10003, "remark": f"{args.server_label} - Trojan WS CDN", "listen": "127.0.0.1", "shareAddrStrategy": "custom", "shareAddr": address(0), "settings": {"clients": [{**common, "password": client.password}]}, "streamSettings": ws("/trojan-ws", address(0))},
    ]
    if not args.disable_outline_direct:
        specs.append({"profile": "client", "subSortIndex": 40, "protocol": "shadowsocks", "port": 10005, "remark": f"{args.server_label} - Shadowsocks Direct", "listen": "0.0.0.0", "shareAddrStrategy": "custom", "shareAddr": args.direct_domain, "settings": {"method": "chacha20-ietf-poly1305", "password": client.password, "network": "tcp,udp", "ivCheck": False, "clients": [{**common, "method": "chacha20-ietf-poly1305", "password": client.password}]}, "streamSettings": {"network": "tcp", "security": "none", "externalProxy": direct_ss_proxy, "tcpSettings": {"acceptProxyProtocol": False, "header": {"type": "none"}}}})
    return specs[:1] if getattr(args, "deployment_profile", "full") == "cdn_vless_backup" else specs


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
    if getattr(args, "deployment_profile", "full") == "cdn_vless_backup":
        template = json_field(current.get("xrayTemplateConfig"), {})
        policy = template.setdefault("policy", {})
        levels = policy.setdefault("levels", {})
        level_zero = levels.setdefault("0", {})
        level_zero.update({"handshake": 4, "connIdle": 90, "uplinkOnly": 2, "downlinkOnly": 5, "bufferSize": 64})
        current["xrayTemplateConfig"] = json.dumps(template, separators=(",", ":"))
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


HOST_GROUP_FIELDS = (
    "sortOrder", "remark", "serverDescription", "isDisabled", "isHidden", "tags",
    "alpn", "fingerprint", "overrideSniFromAddress", "keepSniBlank",
    "pinnedPeerCertSha256", "verifyPeerCertByName", "allowInsecure", "echConfigList",
    "muxParams", "sockoptParams", "finalMask", "vlessRoute", "excludeFromSubTypes",
    "nodeGuids", "mihomoIpVersion", "mihomoX25519", "shuffleHost",
)


def build_host_payload(
    spec: dict[str, Any],
    inbound_id: int,
    existing_group: dict[str, Any] | None = None,
) -> dict[str, Any]:
    proxy = spec["streamSettings"]["externalProxy"][0]
    payload = {
        key: existing_group[key]
        for key in HOST_GROUP_FIELDS
        if existing_group is not None and key in existing_group
    }
    payload.update({
        "inboundIds": [inbound_id],
        "hosts": [str(proxy["dest"])],
        "remark": str(payload.get("remark") or f"BDS managed {spec['remark']}"),
        "port": int(proxy["port"]),
        "security": str(proxy.get("forceTls") or "same"),
        "sni": str(proxy.get("sni") or ""),
        "hostHeader": "",
        "path": "",
        "isDisabled": False,
        "overrideSniFromAddress": False,
        "keepSniBlank": False,
    })
    return payload


def configure_hosts(api: ApiClient, inbounds: list[dict[str, Any]], specs: list[dict[str, Any]]) -> None:
    inbound_by_port = {
        int(item.get("port")): item
        for item in inbounds
        if isinstance(item, dict) and item.get("id") is not None and item.get("port") is not None
    }
    groups = api.request("panel/api/hosts/list").get("obj") or []
    if not isinstance(groups, list):
        raise RuntimeError("Unexpected host list response")

    for spec in specs:
        inbound = inbound_by_port.get(int(spec["port"]))
        if inbound is None:
            raise RuntimeError(f"Configured inbound port {spec['port']} was not returned by 3x-UI")
        inbound_id = int(inbound["id"])
        desired_address = str(spec["streamSettings"]["externalProxy"][0]["dest"])
        candidates = [
            group for group in groups
            if isinstance(group, dict) and inbound_id in [int(value) for value in group.get("inboundIds", [])]
        ]
        existing_group = next(
            (group for group in candidates if desired_address in [str(value) for value in group.get("hosts", [])]),
            candidates[0] if len(candidates) == 1 else None,
        )
        payload = build_host_payload(spec, inbound_id, existing_group)
        group_id = str(existing_group.get("groupId", "")) if existing_group else ""
        if group_id:
            api.request(f"panel/api/hosts/update/{group_id}", "POST", payload)
        else:
            created = api.request("panel/api/hosts/add", "POST", payload).get("obj") or []
            if isinstance(created, list):
                groups.extend(value for value in created if isinstance(value, dict))


def disable_retired_inbounds(api: ApiClient, existing: list[dict[str, Any]], retired_ports: set[int]) -> None:
    for item in existing:
        if not isinstance(item, dict) or int(item.get("port", 0)) not in retired_ports or item.get("enable") is False:
            continue
        payload = {key: value for key, value in item.items() if key != "clientStats"}
        payload["enable"] = False
        api.request(f"panel/api/inbounds/update/{item['id']}", "POST", payload)


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
    specs = build_specs(args, profiles)
    retired_ports = set(ALL_PORTS) - {int(spec["port"]) for spec in specs}
    if args.dry_run:
        by_port = {int(item.get("port")): item for item in existing if isinstance(item, dict) and item.get("port") is not None}
        for spec in specs:
            merge_managed_clients(by_port.get(spec["port"]), spec, profiles)
        print(f"Dry run passed: unified {args.server_label} client will cover {len(specs)} supported inbounds; unrelated clients are preserved.")
        return 0
    configure_settings(api, args)
    configure_inbounds(api, existing, specs, profiles)
    refreshed = api.request("panel/api/inbounds/list").get("obj") or []
    if not isinstance(refreshed, list):
        raise RuntimeError("Unexpected inbound list response after configuration")
    configure_hosts(api, refreshed, specs)
    disable_retired_inbounds(api, existing, retired_ports)
    save_profiles(profiles_file, profiles, f"https://{args.sub_domain}/{args.sub_path.strip('/')}/", args.server_label)
    print(f"Configured one unified {args.server_label} client across {len(specs)} supported BDS inbounds. Profile: {profiles_file}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
