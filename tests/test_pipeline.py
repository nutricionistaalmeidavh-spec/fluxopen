import time
import unittest
from unittest.mock import patch
from security import TOOLS, sign_manifest
from scanner.verify_pipeline import build_report


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.secret = 'test-only-' * 6
        now = int(time.time())
        self.manifest = dict(id='a' * 32, url='https://example.org/?id=1',
                             mode='active', tools=list(TOOLS), issued=now, expires=now + 600)
        self.payload, self.signature = sign_manifest(self.manifest, self.secret)

    def test_all_modules_without_network_or_processes(self):
        with patch('socket.getaddrinfo', side_effect=AssertionError('DNS forbidden')), \
             patch('subprocess.run', side_effect=AssertionError('Processes forbidden')):
            report = build_report(self.payload, self.signature, self.secret, self.manifest['id'])
        self.assertTrue(report['verification_only'])
        self.assertEqual([m['tool'] for m in report['modules']], list(TOOLS))
        self.assertTrue(all(m['status'] == 'skipped' for m in report['modules']))
        self.assertEqual(report['findings'], [])

    def test_invalid_signature_rejected(self):
        with self.assertRaises(ValueError):
            build_report(self.payload, '0' * 64, self.secret, self.manifest['id'])

    def test_mismatched_run_rejected(self):
        with self.assertRaises(ValueError):
            build_report(self.payload, self.signature, self.secret, 'b' * 32)
