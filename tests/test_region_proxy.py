from __future__ import annotations
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("region_proxy", ROOT / "scripts" / "07_configure_region_proxy.py")
if spec is None or spec.loader is None:
    raise RuntimeError("Cannot load region proxy tool")
region = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = region
spec.loader.exec_module(region)


class RegionProxyTests(unittest.TestCase):
    def test_template_is_read_and_saved_via_xray_settings_api(self) -> None:
        template = {"outbounds": [{"tag": "direct"}], "routing": {"rules": []}}

        class FakeApi:
            def __init__(self):
                self.calls = []

            def request(self, path, method="GET", payload=None, form=None):
                self.calls.append((path, method, payload, form))
                if path == "panel/api/xray/":
                    import json
                    return {"obj": {"xraySetting": json.dumps(template)}}
                return {"success": True}

        class FakeCore:
            @staticmethod
            def json_field(value, fallback):
                import json
                return json.loads(value) if isinstance(value, str) else value

        api = FakeApi()
        self.assertEqual(region.read_xray_template(api, FakeCore), template)
        region.save_xray_template(api, template)
        self.assertEqual(api.calls[0][:3], ("panel/api/xray/", "POST", None))
        self.assertEqual(api.calls[1][:3], ("panel/api/xray/update", "POST", None))
        self.assertEqual(api.calls[1][3]["xraySetting"], '{"outbounds":[{"tag":"direct"}],"routing":{"rules":[]}}')
        region.restart_xray(api)
        self.assertEqual(api.calls[2][:3], ("panel/api/server/restartXrayService", "POST", None))

    def test_template_update_is_idempotent_and_scoped(self) -> None:
        template = {"outbounds": [{"tag": "WARP", "protocol": "wireguard"}], "routing": {"rules": [{"type": "field", "inboundTag": ["in-10001-tcp"], "outboundTag": "WARP"}]}}
        kwargs = dict(tag="BDS-REGION-JP", inbound_port=10006, proxy_host="proxy.example", proxy_port=1080, proxy_user="user", proxy_password="secret")
        region.update_template(template, **kwargs)
        region.update_template(template, **kwargs)
        self.assertEqual([item["tag"] for item in template["outbounds"]].count("BDS-REGION-JP"), 1)
        self.assertEqual([item["outboundTag"] for item in template["routing"]["rules"]].count("BDS-REGION-JP"), 1)
        self.assertEqual(template["routing"]["rules"][0]["inboundTag"], ["in-10006-tcp"])
        self.assertEqual(template["routing"]["rules"][1]["outboundTag"], "WARP")

    def test_nginx_location_is_exact_and_uses_loopback_port(self) -> None:
        value = region.nginx_location("/jp-vless-ws", 10006)
        self.assertIn("location = /jp-vless-ws", value)
        self.assertIn("proxy_pass http://127.0.0.1:10006;", value)

    def test_template_tag_check_requires_outbound_and_rule(self) -> None:
        template = {"outbounds": [{"tag": "BDS-REGION-TH"}], "routing": {"rules": []}}
        self.assertFalse(region.template_has_tag(template, "BDS-REGION-TH"))
        template["routing"]["rules"].append({"outboundTag": "BDS-REGION-TH"})
        self.assertTrue(region.template_has_tag(template, "BDS-REGION-TH"))

    def test_runtime_outbound_and_routing_must_match_saved_template(self) -> None:
        tag = "BDS-REGION-US"
        template = {"outbounds": [{"tag": tag}], "routing": {"rules": [{"outboundTag": tag}]}}
        runtime = {"outbounds": [{"tag": tag}], "routing": {"rules": []}}
        self.assertEqual(region.xray_route_state(template, runtime, tag), {"outbound": True, "routing": False})
        runtime["routing"]["rules"].append({"outboundTag": tag})
        self.assertEqual(region.xray_route_state(template, runtime, tag), {"outbound": True, "routing": True})

    def test_canonical_node_code_uses_panel_suffix(self) -> None:
        self.assertEqual(region.canonical_node_code("jp", "SG1"), "JP1")
        self.assertEqual(region.canonical_node_code("th", "SG3"), "TH3")
        self.assertEqual(region.canonical_node_code("jp", "SG3", "JP3"), "JP3")
        with self.assertRaises(RuntimeError):
            region.canonical_node_code("jp", "Singapore")

    def test_read_requests_retry_transient_connection_refusals(self) -> None:
        class FakeApi:
            def __init__(self):
                self.calls = 0

            def request(self, path, method="GET", payload=None, form=None):
                self.calls += 1
                if self.calls == 1:
                    raise RuntimeError(f"3x-UI request failed on {path}: [Errno 111] Connection refused")
                return {"success": True}

        api = FakeApi()
        waits = []
        region.enable_read_request_retries(api, sleep_fn=waits.append)
        self.assertEqual(api.request("panel/api/inbounds/list"), {"success": True})
        self.assertEqual(api.calls, 2)
        self.assertEqual(waits, [0.5])

    def test_xray_template_read_is_safe_to_retry(self) -> None:
        class FakeApi:
            def __init__(self):
                self.calls = 0

            def request(self, path, method="GET", payload=None, form=None):
                self.calls += 1
                if self.calls == 1:
                    raise RuntimeError(f"3x-UI request failed on {path}: [Errno 111] Connection refused")
                return {"success": True}

        api = FakeApi()
        waits = []
        region.enable_read_request_retries(api, sleep_fn=waits.append)
        self.assertEqual(api.request("panel/api/xray/", "POST"), {"success": True})
        self.assertEqual(api.calls, 2)
        self.assertEqual(waits, [0.5])

    def test_mutating_requests_are_not_retried(self) -> None:
        class FakeApi:
            def __init__(self):
                self.calls = 0

            def request(self, path, method="GET", payload=None, form=None):
                self.calls += 1
                raise RuntimeError(f"3x-UI request failed on {path}: [Errno 111] Connection refused")

        api = FakeApi()
        region.enable_read_request_retries(api, sleep_fn=lambda _: self.fail("mutating request must not retry"))
        with self.assertRaisesRegex(RuntimeError, "Connection refused"):
            api.request("panel/api/inbounds/add", "POST", {"remark": "new"})
        self.assertEqual(api.calls, 1)

    def test_http_proxy_maps_to_xray_http_outbound(self) -> None:
        template = {"outbounds": [], "routing": {"rules": []}}
        region.update_template(template, tag="BDS-REGION-JP1", inbound_port=10006, proxy_protocol="http", proxy_host="proxy.example", proxy_port=8080, proxy_user="user", proxy_password="secret")
        self.assertEqual(template["outbounds"][0]["protocol"], "http")

    def test_proxy_auth_is_optional(self) -> None:
        template = {"outbounds": [], "routing": {"rules": []}}
        region.update_template(template, tag="BDS-REGION-JP", inbound_port=10006, proxy_host="proxy.example", proxy_port=1080, proxy_user="", proxy_password="")
        self.assertNotIn("users", template["outbounds"][0]["settings"]["servers"][0])


if __name__ == "__main__":
    unittest.main()
