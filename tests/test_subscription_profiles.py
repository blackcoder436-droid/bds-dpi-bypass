from __future__ import annotations

import base64
import io
import importlib.util
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


configure = load_module("configure_3xui", ROOT / "scripts" / "04_configure_3xui_db.py")
show = load_module("show_subscriptions", ROOT / "scripts" / "05_show_subscriptions.py")


class SubscriptionProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.main = configure.ProfileValues(
            client_id="11111111-1111-4111-8111-111111111111",
            email="existing-main",
            sub_id="existingmainsub",
            password="existing-main-password",
        )
        self.advanced = configure.ProfileValues(
            client_id="22222222-2222-4222-8222-222222222222",
            email="existing-advanced",
            sub_id="existingadvancedsub",
            password="existing-advanced-password",
        )
        self.unrelated = {
            "id": "33333333-3333-4333-8333-333333333333",
            "email": "customer-preserved",
            "subId": "customerpreserved",
            "password": "customer-password",
            "enable": True,
        }

    def client_for_port(self, port: int) -> dict[str, object]:
        profile = self.main if port in (10001, 10002, 10003) else self.advanced
        common = {"email": profile.email, "subId": profile.sub_id, "enable": True}
        if port in (10001, 10002, 8443):
            common["id"] = profile.client_id
        if port in (10003, 10004, 10005):
            common["password"] = profile.password
        return common

    def existing_inbounds(self) -> list[dict[str, object]]:
        result = []
        for index, port in enumerate((10001, 10002, 10003, 10004, 10005, 8443), start=1):
            clients = [self.client_for_port(port)]
            if port == 10005:
                clients.append(self.unrelated)
            settings = {"clients": clients}
            if port in (10004, 10005):
                settings["password"] = self.advanced.password
            result.append({"id": index, "port": port, "settings": json.dumps(settings)})
        return result

    def test_v1_profiles_use_main_identity_and_remove_legacy_advanced_client(self) -> None:
        existing = self.existing_inbounds()
        with tempfile.TemporaryDirectory() as directory:
            profiles_file = Path(directory) / "profiles.json"
            profiles_file.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "sub_base_url": "https://sub.example.com/sub/",
                        "main": self.main.as_dict(),
                        "advanced": self.advanced.as_dict(),
                    }
                ),
                encoding="utf-8",
            )
            profiles = configure.resolve_profiles(existing, profiles_file)
            self.assertEqual(profiles["client"], self.main)
            self.assertEqual(profiles["legacy_advanced"], self.advanced)

            args = SimpleNamespace(
                cdn_domain="cdn.example.com",
                direct_domain="direct.example.com",
                reality_dest="www.google.com:443",
                reality_server_name="www.google.com",
                server_label="SG1",
            )
            specs = configure.build_specs(args, profiles, "private", "public", ["abcd1234"])
            self.assertEqual(
                [spec["remark"] for spec in specs],
                [
                    "SG1 - VLESS WS CDN",
                    "SG1 - VMess WS CDN",
                    "SG1 - Trojan WS CDN",
                    "SG1 - Shadowsocks WS CDN",
                    "SG1 - Shadowsocks Direct",
                    "SG1 - VLESS Reality Direct",
                ],
            )
            self.assertEqual([spec["subSortIndex"] for spec in specs], [10, 20, 30, 40, 50, 60])
            vmess = next(spec for spec in specs if spec["port"] == 10002)
            self.assertEqual(vmess["settings"]["clients"][0]["security"], "aes-128-gcm")
            existing_by_port = {item["port"]: item for item in existing}
            for spec in specs:
                settings = configure.merge_managed_clients(existing_by_port[spec["port"]], spec, profiles)
                clients = settings["clients"]
                sub_ids = {client["subId"] for client in clients}
                self.assertEqual(spec["profile"], "client")
                self.assertIn(profiles["client"].sub_id, sub_ids)
                self.assertNotIn(profiles["legacy_advanced"].sub_id, sub_ids)
                if spec["port"] == 10005:
                    self.assertIn(self.unrelated["subId"], sub_ids)

    def test_v2_profiles_file_round_trip_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private" / "profiles.json"
            profiles = {"client": self.main, "legacy_advanced": self.advanced}
            configure.save_profiles(path, profiles, "https://sub.example.com/sub/", "SG1")
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["version"], 2)
            self.assertEqual(payload["server_label"], "SG1")
            self.assertEqual(payload["client"], self.main.as_dict())
            self.assertNotIn("main", payload)
            self.assertNotIn("advanced", payload)
            self.assertNotIn("legacy_advanced", payload)
            self.assertEqual(configure.load_profiles(path), {"client": self.main})
            resolved = configure.resolve_profiles([], path)
            self.assertEqual(resolved, {"client": self.main})

    def test_show_loader_uses_main_for_v1_and_client_for_v2(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profiles.json"
            path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "sub_base_url": "https://sub.example.com/sub/",
                        "main": self.main.as_dict(),
                        "advanced": self.advanced.as_dict(),
                    }
                ),
                encoding="utf-8",
            )
            loaded = show.load_profiles(path)
            self.assertEqual(loaded["client"], self.main.as_dict())
            self.assertEqual(loaded["sub_base_url"], "https://sub.example.com/sub")

            path.write_text(
                json.dumps(
                    {
                        "version": 2,
                        "server_label": "SG1",
                        "sub_base_url": "https://sub.example.com/sub/",
                        "client": self.advanced.as_dict(),
                    }
                ),
                encoding="utf-8",
            )
            loaded = show.load_profiles(path)
            self.assertEqual(loaded["client"], self.advanced.as_dict())

    def test_show_main_prints_only_the_unified_client_url(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profiles.json"
            path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "sub_base_url": "https://sub.example.com/sub/",
                        "main": self.main.as_dict(),
                        "advanced": self.advanced.as_dict(),
                    }
                ),
                encoding="utf-8",
            )
            args = SimpleNamespace(
                profiles_file=str(path),
                check_url_base=None,
                host_header=None,
            )
            output = io.StringIO()
            with mock.patch.object(show, "parse_args", return_value=args), redirect_stdout(output):
                self.assertEqual(show.main(), 0)

        rendered = output.getvalue()
        self.assertIn(f"https://sub.example.com/sub/{self.main.sub_id}", rendered)
        self.assertNotIn(self.advanced.sub_id, rendered)
        self.assertEqual(rendered.count("https://"), 1)

    def test_unified_subscription_check_requires_all_six_profiles(self) -> None:
        raw = "\n".join(
            (
                "vless://cdn",
                "vmess://cdn",
                "trojan://cdn",
                "ss://cdn",
                "ss://direct",
                "vless://reality",
            )
        ).encode()

        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = base64.b64encode(raw)
        with mock.patch.object(show.urllib.request, "urlopen", return_value=response) as urlopen:
            count, schemes = show.check_profile(
                {"sub_id": "client-subscription-id"},
                "http://127.0.0.1:2096/sub",
                "sub.example.com",
            )

        self.assertEqual(count, 6)
        self.assertEqual(schemes, ["ss", "trojan", "vless", "vmess"])
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:2096/sub/client-subscription-id")
        self.assertEqual(request.get_header("Host"), "sub.example.com")

    def test_unified_subscription_check_rejects_incomplete_protocol_counts(self) -> None:
        raw = "\n".join(
            (
                "vless://cdn",
                "vmess://cdn-one",
                "vmess://cdn-two",
                "trojan://cdn",
                "ss://direct",
                "vless://reality",
            )
        ).encode()
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = base64.b64encode(raw)

        with mock.patch.object(show.urllib.request, "urlopen", return_value=response):
            with self.assertRaisesRegex(RuntimeError, r"ss \(1/2\)"):
                show.check_profile(
                    {"sub_id": "client-subscription-id"},
                    "http://127.0.0.1:2096/sub",
                )

    def test_backup_subscription_requires_exactly_one_vless_profile(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = base64.b64encode(b"vless://cdn\n")
        with mock.patch.object(show.urllib.request, "urlopen", return_value=response):
            count, schemes = show.check_profile(
                {"sub_id": "client-subscription-id"},
                "http://127.0.0.1:2096/sub",
                expected_profile="cdn_vless_backup",
            )
        self.assertEqual((count, schemes), (1, ["vless"]))

    def test_subscription_decoder_accepts_base64(self) -> None:
        raw = "vless://one\nvmess://two\ntrojan://three\n".encode()
        encoded = base64.b64encode(raw)
        self.assertEqual(show.decode_subscription(encoded), raw.decode().splitlines())


if __name__ == "__main__":
    unittest.main()
