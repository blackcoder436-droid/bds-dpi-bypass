#!/usr/bin/env python3
"""Display or verify the root-only unified client subscription profile."""

from __future__ import annotations

import argparse
import base64
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_PROFILES_FILE = "/etc/bds-dpi-bypass/subscription-profiles.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profiles-file", default=DEFAULT_PROFILES_FILE)
    parser.add_argument(
        "--check-url-base",
        help="Verify the client subscription against this internal base URL without printing its token.",
    )
    parser.add_argument("--host-header", help="Host header to use for an internal subscription check.")
    parser.add_argument("--expected-profile", choices=("full", "cdn_vless_backup"), default="full")
    return parser.parse_args()


def load_profiles(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Cannot read subscription profiles file: {path}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"Invalid subscription profiles file: {path}")
    base_url = str(value.get("sub_base_url", "")).strip().rstrip("/")
    if not base_url:
        raise RuntimeError("Subscription profiles file is missing sub_base_url")
    profile_name = "client" if "client" in value else "main"
    profile = value.get(profile_name)
    if not isinstance(profile, dict) or not str(profile.get("sub_id", "")).strip():
        raise RuntimeError(f"Subscription profiles file is missing {profile_name}.sub_id")
    normalized = dict(value)
    normalized["sub_base_url"] = base_url
    normalized["client"] = profile
    return normalized


def decode_subscription(body: bytes) -> list[str]:
    text = body.decode(errors="replace").strip()
    if "://" not in text:
        try:
            padded = text + "=" * (-len(text) % 4)
            text = base64.b64decode(padded, validate=False).decode(errors="replace")
        except (ValueError, UnicodeDecodeError) as exc:
            raise RuntimeError("Subscription response is neither raw links nor valid base64") from exc
    links = [line.strip() for line in text.splitlines() if "://" in line]
    if not links:
        raise RuntimeError("Subscription response contains no share links")
    return links


def link_scheme(link: str) -> str:
    return link.split("://", 1)[0].lower()


def check_profile(profile: dict[str, Any], base_url: str, host_header: str | None = None, expected_profile: str = "full") -> tuple[int, list[str]]:
    sub_id = str(profile["sub_id"]).strip()
    headers = {"User-Agent": "HiddifyNext/2.0"}
    if host_header:
        headers["Host"] = host_header
    request = urllib.request.Request(f"{base_url.rstrip('/')}/{sub_id}", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            links = decode_subscription(response.read())
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Client subscription request failed: {exc.reason}") from exc
    schemes = [link_scheme(link) for link in links]
    if expected_profile == "cdn_vless_backup":
        if len(links) != 1 or schemes != ["vless"]:
            raise RuntimeError("Backup subscription must contain exactly one VLESS profile")
        return len(links), schemes
    if len(links) < 6:
        raise RuntimeError("Client subscription returned fewer than six profiles")
    required_counts = {"vless": 2, "ss": 2, "vmess": 1, "trojan": 1}
    missing = [
        f"{scheme} ({schemes.count(scheme)}/{minimum})"
        for scheme, minimum in required_counts.items()
        if schemes.count(scheme) < minimum
    ]
    if missing:
        raise RuntimeError(f"Client subscription is missing expected protocol profiles: {', '.join(missing)}")
    return len(links), sorted(set(schemes))


def main() -> int:
    args = parse_args()
    profiles_path = Path(args.profiles_file)
    profiles = load_profiles(profiles_path)
    if args.check_url_base:
        count, schemes = check_profile(profiles["client"], args.check_url_base, args.host_header, args.expected_profile)
        print(f"Client subscription verified: {count} profiles ({', '.join(schemes)})")
        return 0

    base_url = str(profiles["sub_base_url"]).rstrip("/")
    print(f"Client subscription: {base_url}/{profiles['client']['sub_id']}")
    print("VMess uses explicit AES-128-GCM for Hiddify/sing-box and Xray compatibility.")
    print("Direct profiles can still be blocked by the current ISP or mobile network.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
