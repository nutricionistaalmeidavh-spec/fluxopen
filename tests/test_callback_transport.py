"""Regression: Cloudflare error 1010 must not block signed report delivery."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parent.parent

class CallbackTransportTests(unittest.TestCase):
    def test_signed_callback_uses_explicit_user_agent(self):
        for name in ("scan.yml", "artisys-once.yml"):
            with self.subTest(workflow=name):
                code=(ROOT/".github"/"workflows"/name).read_text()
                self.assertIn("FluxOpen-GitHub-Actions/1.0",code)
                self.assertIn("X-FluxOpen-Signature",code)
                self.assertIn("if: always()",code)
    def test_no_persistent_callback_diagnostic_job(self):
        code=(ROOT/".github"/"workflows"/"ci.yml").read_text()
        self.assertNotIn("callback_probe:",code)

if __name__=="__main__":
    unittest.main()
