import json
import tempfile
import unittest
from pathlib import Path

from configflare.scanner import scan_path


class ScannerTests(unittest.TestCase):
    def write_config(self, root: Path, data) -> None:
        (root / ".mcp.json").write_text(json.dumps(data), encoding="utf-8")

    def test_clean_server(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_config(root, {"mcpServers": {"python": {"command": "python", "args": ["server.py"], "env": {"API_TOKEN": "${API_TOKEN}"}}}})
            report = scan_path(root)
            self.assertEqual(report.score, 0)
            self.assertEqual(report.servers_scanned, 1)

    def test_hardcoded_secret_never_leaks_value(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret = "super-secret-value-123"
            self.write_config(root, {"mcpServers": {"bad": {"command": "python", "env": {"API_KEY": secret}}}})
            report = scan_path(root)
            rendered = json.dumps(report.to_dict())
            self.assertIn("hardcoded-secret", rendered)
            self.assertNotIn(secret, rendered)

    def test_dangerous_flag_is_critical(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_config(root, {"mcpServers": {"bad": {"command": "python", "args": ["--dangerously-skip-permissions"]}}})
            report = scan_path(root)
            self.assertTrue(any(item.rule == "dangerous-flag" for item in report.findings))
            self.assertEqual(report.level, "critical")

    def test_invalid_json_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "mcp.json")
            path.write_text("{broken", encoding="utf-8")
            report = scan_path(path)
            self.assertEqual(report.findings[0].rule, "invalid-json")


if __name__ == "__main__":
    unittest.main()
