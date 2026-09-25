from __future__ import annotations
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("subscription_sanitizer", ROOT / "scripts" / "06_subscription_sanitizer.py")
if spec is None or spec.loader is None:
    raise RuntimeError("Cannot load subscription sanitizer")
sanitizer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = sanitizer
spec.loader.exec_module(sanitizer)


class SubscriptionSanitizerTests(unittest.TestCase):
    def test_repairs_reality_outbound_without_touching_server_config(self) -> None:
        outbound = {"protocol": "vless", "settings": {"encryption": ""}, "streamSettings": {"security": "reality", "realitySettings": {"serverName": "example.com", "serverNames": ["example.com"]}}}
        server = {"streamSettings": {"security": "reality", "realitySettings": {"serverNames": ["example.com"]}}}
        payload = [outbound, server]
        sanitizer.repair_json(payload)
        self.assertEqual(outbound["settings"]["encryption"], "none")
        self.assertNotIn("serverNames", outbound["streamSettings"]["realitySettings"])
        self.assertEqual(server["streamSettings"]["realitySettings"]["serverNames"], ["example.com"])

    def test_non_reality_outbound_is_unchanged(self) -> None:
        payload = {"protocol": "vless", "settings": {"encryption": "none"}, "streamSettings": {"security": "tls"}}
        expected = dict(payload)
        sanitizer.repair_json(payload)
        self.assertEqual(payload, expected)

    def test_repairs_empty_encryption_on_ws_vless_outbound(self) -> None:
        payload = {"protocol": "vless", "settings": {"encryption": ""}, "streamSettings": {"security": "tls", "network": "ws"}}
        sanitizer.repair_json(payload)
        self.assertEqual(payload["settings"]["encryption"], "none")


if __name__ == "__main__":
    unittest.main()
