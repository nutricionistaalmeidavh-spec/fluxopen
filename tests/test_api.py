"""Offline API smoke tests: all external GitHub calls and DNS lookups mocked."""
import os
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import patch

TMP = tempfile.TemporaryDirectory()
os.environ["DB_PATH"] = str(Path(TMP.name) / "test.db")
os.environ["REPORTS_DIR"] = str(Path(TMP.name) / "reports")
os.environ["ADMIN_PASSWORD"] = "integration-test-password"
os.environ["SCAN_SIGNING_SECRET"] = "x" * 40
os.environ["SCAN_BACKEND"] = "github"

from fastapi.testclient import TestClient
from app.main import app


class PanelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def test_auth_and_csrf_are_enforced(self):
        self.client.cookies.clear()  # Each test starts logged out.
        self.assertEqual(self.client.get("/api/targets").status_code, 401)
        login = self.client.post("/api/login", json={"password": "integration-test-password"})
        self.assertEqual(login.status_code, 200)
        self.assertTrue(login.json()["csrf"])
        self.assertEqual(self.client.post("/api/targets", json={}).status_code, 403)
        self.assertEqual(self.client.get("/api/targets").status_code, 200)

    def test_target_and_scan_lifecycle(self):
        login = self.client.post("/api/login", json={"password": "integration-test-password"})
        csrf = login.json()["csrf"]
        headers = {"X-CSRF-Token": csrf}
        with patch("app.main.normalize_target", return_value="https://demo.org/"):
            target = self.client.post("/api/targets", json={
                "name": "Demo",
                "url": "https://demo.org/",
                "permission": "Contrato documentado de auditoria do domínio",
                "valid_until": (date.today() + timedelta(days=30)).isoformat(),
                "confirmed": True
            }, headers=headers)
        self.assertEqual(target.status_code, 200, target.text)
        with patch("app.main.normalize_target", return_value="https://demo.org/"), patch(
                "app.main.github_request", return_value=None) as gh:
            scan = self.client.post("/api/scans", json={
                "target_id": target.json()["id"],
                "tools": ["zap", "subfinder"],
                "mode": "passive"
            }, headers=headers)
        self.assertEqual(scan.status_code, 200, scan.text)
        gh.assert_called_once()
        self.assertEqual(len(scan.json()["id"]), 32)
        self.assertEqual(self.client.get("/api/scans/" + scan.json()["id"]).status_code, 200)

    def test_active_requires_confirmation(self):
        login = self.client.post("/api/login", json={"password": "integration-test-password"})
        csrf = login.json()["csrf"]
        resp = self.client.post("/api/scans", json={
            "target_id": 1, "tools": ["sqlmap"], "mode": "active",
            "confirmed_active": False
        }, headers={"X-CSRF-Token": csrf})
        self.assertEqual(resp.status_code, 422)


if __name__ == "__main__":
    unittest.main()
