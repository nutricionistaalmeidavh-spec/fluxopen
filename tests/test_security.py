import unittest
from unittest.mock import patch
import socket
import time
from security import normalize_target, sign_manifest, verify_manifest, validate_selection


class SecurityTests(unittest.TestCase):
    def test_rejects_private_hosts_and_invalid_schemes(self):
        for url in ("http://127.0.0.1/", "http://localhost/", "http://10.0.0.1/",
                    "file:///etc/passwd", "http://admin:password@site.org/",
                    "https://site.org:22/", "https://site.org/#fragment"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                normalize_target(url, resolve=False)

    @patch("security.socket.getaddrinfo")
    def test_rejects_rebinding_to_private_ip(self, getaddrinfo):
        getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.5", 443))]
        with self.assertRaises(ValueError):
            normalize_target("https://example.org/")

    @patch("security.socket.getaddrinfo")
    def test_accepts_public_host(self, getaddrinfo):
        getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443))]
        self.assertEqual(normalize_target("https://App.Example.ORG/path?q=1"),
                         "https://app.example.org/path?q=1")

    def test_active_tool_requires_active_mode(self):
        with self.assertRaises(ValueError):
            validate_selection(["zap", "sqlmap"], "passive")
        self.assertEqual(validate_selection(["sqlmap"], "active"), ["sqlmap"])

    def test_manifest_signature_expiry_and_tampering(self):
        now = int(time.time())
        manifest = dict(id="a" * 32, url="https://site.org/", tools=["zap"],
                        mode="passive", issued=now, expires=now + 3600)
        packed, sig = sign_manifest(manifest, "x" * 40)
        self.assertEqual(verify_manifest(packed, sig, "x" * 40, resolve=False)["id"], "a" * 32)
        with self.assertRaises(ValueError):
            verify_manifest(packed, "0" * 64, "x" * 40, resolve=False)
        with self.assertRaises(ValueError):
            verify_manifest(packed, sig, "x" * 40, resolve=False, now=now + 3700)


if __name__ == "__main__":
    unittest.main()
