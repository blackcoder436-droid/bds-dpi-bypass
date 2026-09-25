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


if __name__ == "__main__":
    unittest.main()
