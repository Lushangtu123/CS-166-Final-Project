import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

from config import load_settings


class SettingsTests(unittest.TestCase):
    def test_trusted_authentication_services_are_normalized(self):
        settings = load_settings({
            "APP_ENV": "test",
            "TRUSTED_AUTHSERV_IDS": " MX.Receiver.Example, auth.example ",
        })

        self.assertEqual(
            settings.trusted_authserv_ids,
            frozenset({"mx.receiver.example", "auth.example"}),
        )

    def test_content_model_artifact_settings_are_explicit(self):
        settings = load_settings({
            "APP_ENV": "test",
            "CONTENT_MODEL_ENABLED": "true",
            "CONTENT_MODEL_ARTIFACT": "/models/content-model.pkl",
            "CONTENT_MODEL_ARTIFACT_SHA256": "a" * 64,
        })

        self.assertEqual(settings.content_model_artifact, "/models/content-model.pkl")
        self.assertEqual(settings.content_model_artifact_sha256, "a" * 64)

    def run_settings(self, overrides=None):
        env = os.environ.copy()
        for name in (
            "APP_ENV", "ENABLE_EMAIL_VERIFICATION",
            "VERIFICATION_MODE", "ENABLE_DOMAIN_VERIFICATION",
            "ENABLE_SMTP_VERIFICATION",
            "CONTENT_MODEL_ENABLED", "CONTENT_MODEL_ARTIFACT",
            "CONTENT_MODEL_ARTIFACT_SHA256", "TRUSTED_AUTHSERV_IDS",
        ):
            env.pop(name, None)
        env.update(overrides or {})
        code = (
            "import json; from config import load_settings; "
            "s = load_settings(); "
            "print(json.dumps({'app_env': s.app_env, "
            "'enable_email_verification': s.enable_email_verification, "
            "'content_model_enabled': s.content_model_enabled}))"
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
            "content_model_enabled": False,
        })

    def test_local_development_can_explicitly_enable_full_features(self):
        result = self.run_settings({
            "APP_ENV": "development",
            "ENABLE_EMAIL_VERIFICATION": "true",
            "CONTENT_MODEL_ENABLED": "true",
        })

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {
            "app_env": "development",
            "enable_email_verification": True,
            "content_model_enabled": True,
        })

    def test_content_model_can_be_disabled_without_disabling_rules(self):
        result = self.run_settings({"CONTENT_MODEL_ENABLED": "false"})

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIs(json.loads(result.stdout)["content_model_enabled"], False)

    def test_public_lite_verification_enables_domain_checks_without_smtp(self):
        settings = load_settings({
            "APP_ENV": "production",
            "VERIFICATION_MODE": "lite",
        })

        self.assertTrue(settings.enable_email_verification)
        self.assertTrue(settings.domain_verification_enabled)
        self.assertFalse(settings.smtp_verification_enabled)
        self.assertEqual(settings.effective_verification_mode, "lite")

    def test_production_rejects_email_verification_opt_in(self):
        result = self.run_settings({
            "APP_ENV": "production",
            "ENABLE_EMAIL_VERIFICATION": "true",
        })

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ENABLE_EMAIL_VERIFICATION", result.stderr)

    def test_public_demo_rejects_verification(self):
        allowed = self.run_settings({"APP_ENV": "demo"})
        self.assertEqual(allowed.returncode, 0, allowed.stderr)
        self.assertEqual(json.loads(allowed.stdout)["app_env"], "demo")

        rejected = self.run_settings({
            "APP_ENV": "demo",
            "ENABLE_EMAIL_VERIFICATION": "true",
        })
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("ENABLE_EMAIL_VERIFICATION", rejected.stderr)

    def test_invalid_boolean_is_rejected(self):
        result = self.run_settings({"ENABLE_EMAIL_VERIFICATION": "sometimes"})

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ENABLE_EMAIL_VERIFICATION", result.stderr)

    def test_invalid_verification_mode_is_rejected(self):
        result = self.run_settings({"VERIFICATION_MODE": "almost"})

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("VERIFICATION_MODE", result.stderr)

    def test_unknown_app_environment_is_rejected(self):
        result = self.run_settings({"APP_ENV": "staging"})

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("APP_ENV", result.stderr)


if __name__ == "__main__":
    unittest.main()
