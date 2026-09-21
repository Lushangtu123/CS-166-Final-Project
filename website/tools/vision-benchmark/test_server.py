"""Boundary tests for the independent localhost harness server."""
import http.client
import json
from pathlib import Path
import socket
import subprocess
import sys
import time
import unittest


class LocalHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            cls.port = probe.getsockname()[1]
        cls.process = subprocess.Popen([sys.executable, str(Path(__file__).with_name('serve.py')), '--port', str(cls.port)], stdout=subprocess.DEVNULL)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if cls.process.poll() is not None:
                raise RuntimeError('Local harness exited during startup')
            try:
                with socket.create_connection(('127.0.0.1', cls.port), timeout=.1):
                    return
            except OSError:
                time.sleep(.05)
        cls.process.terminate()
        cls.process.wait(timeout=5)
        raise RuntimeError('Local harness failed to start')

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        cls.process.wait(timeout=5)

    def request(self, path, method='GET', headers=None, body=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def test_real_pipeline_resources_and_identity(self):
        self.assertEqual(self.request('/')[0], 200)
        self.assertEqual(self.request('/static/vision-worker.mjs?v=2')[0], 200)
        status, headers, body = self.request('/identity.json')
        self.assertEqual(status, 200)
        identity = json.loads(body)
        self.assertTrue(identity['asset_manifest_verified'])
        self.assertGreater(identity['asset_count'], 20)
        self.assertIn('vision-worker.mjs', identity['extraction_sha256'])
        self.assertFalse(identity['risk_enabled'])
        self.assertNotIn('Access-Control-Allow-Origin', headers)

    def test_disallows_traversal_source_files_and_foreign_hosts(self):
        for path in ['/serve.py', '/synthetic-manifest.json', '/static/%2e%2e/app.py', '/%2e%2e/app.py']:
            self.assertEqual(self.request(path)[0], 404)
        self.assertEqual(self.request('/', headers={'Host': 'attacker.example'})[0], 403)

    def test_post_requires_exact_local_origin_and_never_exposes_case_route(self):
        self.assertEqual(self.request('/api/analyze-visual', 'POST', body=b'{}')[0], 403)
        headers = {'Origin': f'http://127.0.0.1:{self.port}'}
        self.assertEqual(self.request('/api/analyze-visual', 'POST', headers, b'{}')[0], 404)
        self.assertEqual(self.request('/api/cases/visual', 'POST', headers, b'{}')[0], 404)


if __name__ == '__main__':
    unittest.main()
