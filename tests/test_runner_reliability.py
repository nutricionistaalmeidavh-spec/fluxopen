"""Regression coverage for scanner invocation, incomplete evidence and exit states."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scanner.runner import command, execute, report_status


class ReliabilityTests(unittest.TestCase):
    def test_ffuf_filters_wildcard_spa_responses_without_raising_rate(self):
        flags=command("ffuf","https://example.org/","example.org")
        self.assertIn("-ac",flags)
        self.assertEqual(flags[flags.index("-rate")+1],"2")
        self.assertEqual(flags[flags.index("-t")+1],"1")

    def test_nuclei_skips_update_check_but_preserves_safe_limits(self):
        flags=command("nuclei","https://example.org/","example.org")
        self.assertIn("-duc",flags)
        self.assertEqual(flags[flags.index("-rl")+1],"2")
        self.assertEqual(flags[flags.index("-c")+1],"1")

    def test_nikto_help_output_is_error_even_with_exit_code_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake=SimpleNamespace(returncode=0,stdout="Nikto v2.5.0\nUsage: nikto.pl -h host\nOptions:\n")
            with patch("scanner.runner.subprocess.run",return_value=fake):
                result=execute("nikto","https://example.org/","example.org",Path(tmp))
            self.assertEqual(result["status"],"error")
            self.assertIn("Usage:",result["excerpt"])

    def test_zap_report_generation_error_is_partial_not_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake=SimpleNamespace(returncode=0,stdout="WARN-NEW: 1\nAutomation plan failures: NoSuchFileException")
            with patch("scanner.runner.subprocess.run",return_value=fake):
                result=execute("zap","https://example.org/","example.org",Path(tmp))
            self.assertEqual(result["status"],"warning")

    def test_unexecuted_only_is_not_a_complete_audit(self):
        self.assertEqual(report_status([{"status":"skipped"}]),"completed_with_errors")
        self.assertEqual(report_status([{"status":"error"}]),"failed")
        self.assertEqual(report_status([{"status":"ok"},{"status":"error"}]),"completed_with_errors")
        self.assertEqual(report_status([{"status":"ok"},{"status":"skipped"}]),"completed")


if __name__=="__main__":
    unittest.main()
