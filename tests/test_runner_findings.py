"""Fixtures reproduce ZAP report-path failure and nested testssl JSON output."""
import json
import tempfile
import unittest
from pathlib import Path
from scanner.runner import normalize_findings, command


class ParseFindingsTests(unittest.TestCase):
    def test_zap_uses_relative_paths_inside_mounted_workdir(self):
        args=command("zap","https://example.org/","example.org")
        self.assertEqual(args[args.index("-J")+1],"zap.json")
        self.assertEqual(args[args.index("-r")+1],"zap.html")

    def test_zap_structured_alerts_have_rule_id_occurrence_and_urls(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/"zap.json").write_text(json.dumps({"site":[{"@name":"https://example.org/","alerts":[{
                "pluginid":"10038","name":"Content Security Policy Header Not Set",
                "riskdesc":"Medium (Medium)","desc":"Missing CSP",
                "count":"5","instances":[{"uri":"https://example.org/"},
                                          {"uri":"https://example.org/docs"}]
            }]}]}))
            rows=normalize_findings("zap",root)
            self.assertEqual(len(rows),1)
            self.assertEqual(rows[0]["rule_id"],"10038")
            self.assertEqual(rows[0]["occurrences"],5)
            self.assertEqual(rows[0]["severity"],"medium")
            self.assertEqual(rows[0]["urls"],["https://example.org/","https://example.org/docs"])

    def test_zap_falls_back_to_console_warnings_when_json_missing(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/"zap.log").write_text(
                "WARN-NEW: Strict-Transport-Security Header Not Set [10035] x 5\n"
                "\thttps://example.org/ (200 OK)\n"
                "WARN-NEW: Content Security Policy (CSP) Header Not Set [10038] x 3\n"
                "\thttps://example.org/app (200 OK)\n"
                "FAIL-NEW: 0 WARN-NEW: 14 PASS: 54\n"
                "Automation plan failures: NoSuchFileException\n"
            )
            rows=normalize_findings("zap",root)
            self.assertEqual(len(rows),2)
            self.assertEqual(rows[0]["rule_id"],"10035")
            self.assertEqual(rows[0]["occurrences"],5)
            self.assertEqual(rows[1]["url"],"https://example.org/app")
            self.assertEqual(rows[0]["severity"],"warning")

    def test_testssl_pretty_nested_findings_ignores_benign_results(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/"testssl.json").write_text(json.dumps({
                "clientProblem1":[{"id":"engine_problem","severity":"WARN","finding":"Binary warning"}],
                "scanResult":[{"targetHost":"example.org","ip":"203.0.113.10","port":"443",
                    "protocols":[
                        {"id":"SSLv3","severity":"OK","finding":"not offered"},
                        {"id":"TLS1","severity":"LOW","finding":"offered (deprecated)"},
                        {"id":"TLS1_1","severity":"LOW","finding":"offered (deprecated)"},
                        {"id":"TLS1_2","severity":"OK","finding":"offered"}
                    ],"vulnerabilities":[{"id":"heartbleed","severity":"OK","finding":"not vulnerable"}]
                }]
            }))
            rows=normalize_findings("testssl",root)
            self.assertEqual({r["rule_id"] for r in rows},{"TLS1","TLS1_1"})
            self.assertTrue(all(r["severity"]=="low" for r in rows))
            self.assertTrue(all(r["url"]=="https://example.org/" for r in rows))
            self.assertNotIn("engine_problem",str(rows))

    def test_testssl_flat_json_remains_compatible(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/"testssl.json").write_text(json.dumps([
                {"id":"TLS1","severity":"LOW","finding":"offered"},
                {"id":"TLS1_2","severity":"OK","finding":"offered"}
            ]))
            self.assertEqual([x["rule_id"] for x in normalize_findings("testssl",root)],["TLS1"])


if __name__=="__main__":
    unittest.main()
