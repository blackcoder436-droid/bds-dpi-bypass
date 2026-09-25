#!/usr/bin/env python3
"""Proxy 3x-UI subscriptions and repair invalid Xray JSON client fields."""
from __future__ import annotations
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade", "content-length", "content-encoding"}


def repair_json(value: object) -> None:
    if isinstance(value, list):
        for item in value:
            repair_json(item)
        return
    if not isinstance(value, dict):
        return
    stream = value.get("streamSettings")
    if value.get("protocol") == "vless":
        settings = value.setdefault("settings", {})
        if isinstance(settings, dict) and not settings.get("encryption"):
            settings["encryption"] = "none"
        if isinstance(stream, dict) and stream.get("security") == "reality":
            reality = stream.get("realitySettings")
            if isinstance(reality, dict):
                reality.pop("serverNames", None)
    for item in value.values():
        repair_json(item)


def make_handler(upstream: str):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, _format: str, *args: object) -> None:
            return
        def do_HEAD(self) -> None:  # noqa: N802
            self.forward(False)
        def do_GET(self) -> None:  # noqa: N802
            self.forward(True)
        def forward(self, include_body: bool) -> None:
            headers = {key: value for key, value in self.headers.items() if key.lower() not in HOP_HEADERS}
            headers["Accept-Encoding"] = "identity"
            try:
                response = urlopen(Request(upstream + self.path, headers=headers, method=self.command), timeout=20)
            except HTTPError as error:
                response = error
            data = response.read() if include_body else b""
            content_type = response.headers.get("Content-Type", "")
            if include_body and response.status == 200 and ("json" in content_type.lower() or data.lstrip().startswith((b"{", b"["))):
                try:
                    parsed = json.loads(data)
                    repair_json(parsed)
                    data = json.dumps(parsed, separators=(",", ":")).encode()
                    content_type = "application/json; charset=utf-8"
                except (TypeError, ValueError):
                    pass
            self.send_response(response.status)
            for key, value in response.headers.items():
                if key.lower() not in HOP_HEADERS and key.lower() != "content-type":
                    self.send_header(key, value)
            if content_type:
                self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if include_body:
                self.wfile.write(data)
    return Handler


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2097)
    parser.add_argument("--upstream", default="http://127.0.0.1:2096")
    args = parser.parse_args()
    ThreadingHTTPServer((args.listen, args.port), make_handler(args.upstream.rstrip("/"))).serve_forever()


if __name__ == "__main__":
    main()
