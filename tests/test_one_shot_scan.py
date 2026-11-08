"""Prevent accidentally widening a one-shot authorized public-site scan."""
import time
import unittest
from unittest.mock import patch

from ops.one_shot_scan import request_manifest, SCAN_ID, TOOLS, URL


class OneShotTests(unittest.TestCase):
    def setUp(self):
        self.data = {
            "id": SCAN_ID,
            "url": URL,
            "mode": "passive",
            "tools": list(TOOLS),
            "expires_utc": "2026-11-10T03:00:00Z"
        }

    def test_approved_root_and_tools_only(self):
        out = request_manifest(self.data, now=1794155000)
        self.assertEqual(out["url"], "https://artisys.dev/")
        self.assertEqual(out["mode"], "passive")
        self.assertEqual(out["tools"], ["zap", "subfinder", "httpx", "katana", "testssl"])

    def test_active_tools_not_permitted(self):
        for value in ["sqlmap", "nikto", "ffuf", "feroxbuster", "nuclei"]:
            changed = {**self.data, "tools": [*TOOLS, value]}
            with self.assertRaises(ValueError):
                request_manifest(changed, now=1794155000)

    def test_other_targets_not_permitted(self):
        for url in ["https://www.artisys.dev/", "https://artisys.dev/admin",
                    "http://artisys.dev/", "https://example.org/"]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                request_manifest({**self.data, "url": url}, now=1794155000)

    def test_expired_request_rejected(self):
        with self.assertRaises(ValueError):
            request_manifest(self.data, now=1794350000)

    def test_unknown_fields_rejected(self):
        with self.assertRaises(ValueError):
            request_manifest({**self.data, "extra": True}, now=1794155000)


if __name__ == "__main__":
    unittest.main()
