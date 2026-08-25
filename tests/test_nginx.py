import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class NginxTemplateTests(unittest.TestCase):
    def test_public_panel_prefix_is_stripped_before_proxying(self) -> None:
        template = (ROOT / "config" / "nginx" / "bds-node.conf").read_text(encoding="utf-8")
        panel_location = re.search(
            r"location /\{\{XUI_WEB_BASE_PATH\}\}/ \{(?P<body>.*?)\n    \}",
            template,
            re.DOTALL,
        )

        self.assertIsNotNone(panel_location)
        self.assertIn(
            "proxy_pass http://127.0.0.1:{{XUI_PANEL_PORT}}/;",
            panel_location.group("body"),
        )
        self.assertNotIn(
            "proxy_pass http://127.0.0.1:{{XUI_PANEL_PORT}};",
            panel_location.group("body"),
        )


if __name__ == "__main__":
    unittest.main()
