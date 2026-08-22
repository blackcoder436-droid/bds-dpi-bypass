from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("setup_warp", ROOT / "scripts" / "03_setup_warp.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Cannot load WARP setup module")
warp = importlib.util.module_from_spec(SPEC)
sys.modules["setup_warp"] = warp
SPEC.loader.exec_module(warp)


def registration(endpoint: str = "162.159.192.1:2408") -> dict[str, object]:
    return {
        "_private_key": "private-key",
        "config": {
            "client_id": "AQID",
            "interface": {"addresses": {"v4": "172.16.0.2/32", "v6": "2606:4700:110:abcd::2/128"}},
            "peers": [{"public_key": "public-key", "endpoint": {"v4": endpoint, "host": endpoint}}],
        },
    }


class FakeApi:
    def __init__(self, test_results: list[bool] | None = None) -> None:
        self.test_results = list(test_results or [])
        self.calls: list[tuple[str, str, dict[str, str] | None]] = []

    def request(self, path: str, method: str = "GET", form: dict[str, str] | None = None, payload=None):
        self.calls.append((path, method, form))
        if path.endswith("testOutbound"):
            passed = self.test_results.pop(0) if self.test_results else False
            return {"success": True, "obj": {"success": passed, "mode": "real"}}
        return {"success": True}


class WarpProvisioningTests(unittest.TestCase):
    def test_backup_profile_accepts_only_vless_cdn_port(self) -> None:
        api = mock.MagicMock()
        api.request.return_value = {"obj": [{"port": 10001, "tag": "inbound-10001"}]}
        self.assertEqual(warp.warp_inbound_tags(api, (10001,)), ["inbound-10001"])

    def test_panel_public_prefix_is_preserved_for_authenticated_routes(self) -> None:
        deploy = (ROOT / "deploy.sh").read_text(encoding="utf-8")
        nginx = (ROOT / "config" / "nginx" / "bds-node.conf").read_text(encoding="utf-8")
        self.assertIn('-webBasePath "/"', deploy)
        self.assertIn('--panel-url "http://127.0.0.1:${XUI_PANEL_PORT}"', deploy)
        self.assertIn('location /{{XUI_WEB_BASE_PATH}}/', nginx)
        self.assertIn('proxy_pass http://127.0.0.1:{{XUI_PANEL_PORT}};', nginx)

    def test_endpoint_with_port_is_not_duplicated(self) -> None:
        candidates = warp.endpoint_candidates("162.159.192.1:2408")
        self.assertEqual(candidates[0], "162.159.192.1:2408")
        self.assertNotIn("162.159.192.1:2408:500", candidates)
        self.assertIn("162.159.192.1:500", candidates)

    def test_candidate_has_three_reserved_bytes_and_userspace_ipv4_settings(self) -> None:
        candidate = warp.build_warp_candidates(registration())[0]
        settings = candidate["settings"]
        self.assertEqual(settings["reserved"], [1, 2, 3])
        self.assertEqual(settings["address"], ["172.16.0.2/32", "2606:4700:110:abcd::2/128"])
        self.assertEqual(settings["domainStrategy"], "ForceIPv4")
        self.assertIs(settings["noKernelTun"], True)

    def test_broken_existing_warp_is_replaced_by_first_real_working_candidate(self) -> None:
        api = FakeApi([False, False, False, False, True])
        existing = {"protocol": "wireguard", "tag": "warp", "settings": {}}
        template = {"outbounds": [{"protocol": "freedom", "tag": "direct"}, existing]}
        with mock.patch.object(warp, "register_warp", return_value=registration()):
            selected = warp.select_working_warp(api, template)
        self.assertIsNot(selected, existing)
        self.assertEqual(selected["settings"]["peers"][0]["endpoint"], "162.159.192.1:500")
        test_calls = [call for call in api.calls if call[0].endswith("testOutbound")]
        self.assertEqual(len(test_calls), 5)
        for _, _, form in test_calls:
            self.assertEqual(form["mode"], "real")

    def test_no_working_endpoint_fails_closed(self) -> None:
        api = FakeApi([False] * 8)
        with mock.patch.object(warp, "register_warp", return_value=registration()):
            with self.assertRaisesRegex(RuntimeError, "No Cloudflare WARP endpoint"):
                warp.select_working_warp(api, {"outbounds": []})

    def test_verification_requires_all_runtime_cdn_tags_and_real_test(self) -> None:
        tags = [f"in-{port}-tcp" for port in (10001, 10002, 10003, 10004)]
        template = {
            "outbounds": [{"protocol": "wireguard", "tag": "warp", "settings": {}}],
            "routing": {"rules": [{"type": "field", "inboundTag": tags, "outboundTag": "warp"}]},
        }
        warp.verify_installed_warp(FakeApi([True]), template, tags)
        with self.assertRaisesRegex(RuntimeError, "not all routed"):
            warp.verify_installed_warp(FakeApi([True]), template, tags + ["unexpected"])
        with self.assertRaisesRegex(RuntimeError, "real outbound"):
            warp.verify_installed_warp(FakeApi([False]), template, tags)

    def test_update_payload_keeps_exact_runtime_tags(self) -> None:
        tags = [f"in-{port}-tcp" for port in (10001, 10002, 10003, 10004)]
        template = {
            "outbounds": [{"protocol": "freedom", "tag": "direct"}],
            "routing": {"rules": []},
        }
        api = mock.MagicMock()
        api.login.return_value = None
        api.request.side_effect = [
            {"success": True, "obj": [{"port": port, "tag": tag} for port, tag in zip((10001, 10002, 10003, 10004), tags)]},
            {"success": True, "obj": {"xraySetting": json.dumps(template)}},
            {"success": True},
            {"success": True, "obj": {"xraySetting": json.dumps({
                "outbounds": [{"protocol": "wireguard", "tag": "warp", "settings": {}}],
                "routing": {"rules": [{"type": "field", "inboundTag": tags, "outboundTag": "warp"}]},
            })}},
            {"success": True, "obj": {"success": True, "mode": "real"}},
        ]
        selected = {"protocol": "wireguard", "tag": "warp", "settings": {}}
        with mock.patch.object(warp, "parse_args", return_value=SimpleNamespace(panel_url="http://panel/panel", username="admin", password="secret", verify_only=False)), \
             mock.patch.object(warp, "ApiClient", return_value=api), \
             mock.patch.object(warp, "select_working_warp", return_value=selected):
            self.assertEqual(warp.main(), 0)
        update = next(call for call in api.request.call_args_list if call.args[0].endswith("update"))
        saved = json.loads(update.kwargs["form"]["xraySetting"])
        self.assertTrue(warp.route_uses_all_tags(saved, tags))


if __name__ == "__main__":
    unittest.main()
