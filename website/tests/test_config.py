import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


WEBSITE_DIR = Path(__file__).resolve().parents[1]


class SettingsTests(unittest.TestCase):
    def run_settings(self, overrides=None):
        env = os.environ.copy()
        for name in ("APP_ENV", "ENABLE_EMAIL_VERIFICATION", "ALLOW_SYNTHETIC_DATA"):
            env.pop(name, None)
        env.update(overrides or {})
        code = (
            "import json; from config import load_settings; "
            "s = load_settings(); "
            "print(json.dumps({'app_env': s.app_env, "
            "'enable_email_verification': s.enable_email_verification, "
            "'allow_synthetic_data': s.allow_synthetic_data}))"
        )
        return subprocess.run(
            [sys.executable, "-c", code],
            cwd=WEBSITE_DIR,
            env=env,
            capture_output=True,
            text=True,
        )

    def test_defaults_are_safe_for_public_deployment(self):
        result = self.run_settings()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {
            "app_env": "production",
            "enable_email_verification": False,
            "allow_synthetic_data": False,
        })

    def test_local_development_can_explicitly_enable_full_features(self):
        result = self.run_settings({
            "APP_ENV": "development",
            "ENABLE_EMAIL_VERIFICATION": "true",
            "ALLOW_SYNTHETIC_DATA": "true",
        })

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {
            "app_env": "development",
            "enable_email_verification": True,
            "allow_synthetic_data": True,
        })

    def test_production_rejects_synthetic_data_opt_in(self):
        result = self.run_settings({
            "APP_ENV": "production",
            "ALLOW_SYNTHETIC_DATA": "true",
        })

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ALLOW_SYNTHETIC_DATA", result.stderr)

    def test_production_rejects_email_verification_opt_in(self):
        result = self.run_settings({
            "APP_ENV": "production",
            "ENABLE_EMAIL_VERIFICATION": "true",
        })

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ENABLE_EMAIL_VERIFICATION", result.stderr)

    def test_invalid_boolean_is_rejected(self):
        result = self.run_settings({"ENABLE_EMAIL_VERIFICATION": "sometimes"})

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ENABLE_EMAIL_VERIFICATION", result.stderr)

    def test_unknown_app_environment_is_rejected(self):
        result = self.run_settings({"APP_ENV": "staging"})

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("APP_ENV", result.stderr)


if __name__ == "__main__":
    unittest.main()
