import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class NginxTemplateTests(unittest.TestCase):
    def test_public_panel_prefix_is_preserved_when_proxying(self) -> None:
        template = (ROOT / "config" / "nginx" / "bds-node.conf").read_text(encoding="utf-8")
        panel_location = re.search(
            r"location /\{\{XUI_WEB_BASE_PATH\}\}/ \{(?P<body>.*?)\n    \}",
            template,
            re.DOTALL,
        )

        self.assertIsNotNone(panel_location)
        self.assertIn(
            "proxy_pass http://127.0.0.1:{{XUI_PANEL_PORT}};",
            panel_location.group("body"),
        )
        self.assertNotIn(
            "proxy_pass http://127.0.0.1:{{XUI_PANEL_PORT}}/;",
            panel_location.group("body"),
        )

    def test_panel_root_redirects_to_the_canonical_base_path(self) -> None:
        template = (ROOT / "config" / "nginx" / "bds-node.conf").read_text(encoding="utf-8")
        self.assertIn("location = / {", template)
        self.assertIn("return 302 /{{XUI_WEB_BASE_PATH}}/;", template)

    def test_subscription_uses_json_sanitizer_and_ss_route_exists(self) -> None:
        template = (ROOT / "config" / "nginx" / "bds-node.conf").read_text(encoding="utf-8")
        self.assertIn("proxy_pass http://127.0.0.1:2097;", template)
        self.assertIn("location /ss-ws {", template)
        self.assertIn("proxy_pass http://127.0.0.1:10004;", template)
        self.assertIn("include /etc/nginx/bds-region-routes.d/*.conf;", template)


if __name__ == "__main__":
    unittest.main()
