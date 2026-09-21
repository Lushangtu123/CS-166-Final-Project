"""Keep the runtime smoke output tied to raw MIME analysis behavior."""

import json
from pathlib import Path
import subprocess
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class VercelRuntimeSmokeTests(unittest.TestCase):
    def test_raw_mime_positive_and_incomplete_controls_are_reported(self):
        target_python = (PROJECT_ROOT / '.python-version').read_text().strip()
        if f'{sys.version_info.major}.{sys.version_info.minor}' != target_python:
            self.skipTest(f'Committed artifact targets Python {target_python}')
        completed = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / 'website/tests/vercel_runtime_smoke.py')],
            cwd=PROJECT_ROOT, capture_output=True, text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout.splitlines()[-1])
        self.assertIn(report['mime_phishing_risk_level'], {'high', 'critical'})
        self.assertEqual(report['mime_phishing_ml_prediction'], 1)
        self.assertEqual(report['mime_uncertain_risk_level'], 'unknown')
        self.assertEqual(report['mime_uncertain_ml_status'], 'available')
        self.assertFalse(report['mime_uncertain_analysis_complete'])


if __name__ == '__main__':
    unittest.main()
