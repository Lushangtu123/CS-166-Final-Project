import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

from config import Settings, load_settings


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
            "SENDER_HISTORY_ENABLED", "UPSTASH_REDIS_REST_URL",
            "UPSTASH_REDIS_REST_TOKEN", "SENDER_HISTORY_HMAC_KEY",
            "SENDER_HISTORY_RETENTION_DAYS", "SENDER_HISTORY_TIMEOUT_SECONDS",
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

    def test_sender_history_is_disabled_safely_by_default(self):
        settings = load_settings({"APP_ENV": "test"})

        self.assertFalse(settings.sender_history_enabled)
        self.assertFalse(settings.sender_history_ready)
        self.assertIsNone(settings.sender_history_config_error)
        self.assertEqual(settings.sender_history_retention_days, 90)
        self.assertEqual(settings.sender_history_timeout_seconds, 1.0)

    def test_sender_history_readiness_requires_credentials_even_for_direct_settings(self):
        settings = Settings(
            app_env="test",
            enable_email_verification=False,
            sender_history_enabled=True,
        )

        self.assertFalse(settings.sender_history_ready)

    def test_sender_history_accepts_complete_upstash_configuration(self):
        settings = load_settings({
            "APP_ENV": "test",
            "SENDER_HISTORY_ENABLED": "true",
            "UPSTASH_REDIS_REST_URL": "https://example.upstash.io",
            "UPSTASH_REDIS_REST_TOKEN": "token-value",
            "SENDER_HISTORY_HMAC_KEY": "k" * 32,
            "SENDER_HISTORY_RETENTION_DAYS": "30",
            "SENDER_HISTORY_TIMEOUT_SECONDS": "0.5",
        })

        self.assertTrue(settings.sender_history_enabled)
        self.assertTrue(settings.sender_history_ready)
        self.assertIsNone(settings.sender_history_config_error)
        self.assertEqual(settings.sender_history_retention_days, 30)
        self.assertEqual(settings.sender_history_timeout_seconds, 0.5)

    def test_sender_history_partial_or_unsafe_configuration_fails_closed(self):
        cases = (
            {
                "SENDER_HISTORY_ENABLED": "true",
                "UPSTASH_REDIS_REST_URL": "https://example.upstash.io",
            },
            {
                "SENDER_HISTORY_ENABLED": "true",
                "UPSTASH_REDIS_REST_URL": "http://example.upstash.io",
                "UPSTASH_REDIS_REST_TOKEN": "secret-token",
                "SENDER_HISTORY_HMAC_KEY": "k" * 32,
            },
            {
                "SENDER_HISTORY_ENABLED": "true",
                "UPSTASH_REDIS_REST_URL": "https://example.upstash.io",
                "UPSTASH_REDIS_REST_TOKEN": "secret-token",
                "SENDER_HISTORY_HMAC_KEY": "too-short",
            },
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                settings = load_settings({"APP_ENV": "test", **overrides})
                self.assertTrue(settings.sender_history_enabled)
                self.assertFalse(settings.sender_history_ready)
                self.assertIsNotNone(settings.sender_history_config_error)
                self.assertNotIn("secret-token", settings.sender_history_config_error)
                self.assertNotIn("too-short", settings.sender_history_config_error)

    def test_sender_history_bounds_retention_and_timeout(self):
        base = {
            "APP_ENV": "test",
            "SENDER_HISTORY_ENABLED": "true",
            "UPSTASH_REDIS_REST_URL": "https://example.upstash.io",
            "UPSTASH_REDIS_REST_TOKEN": "token-value",
            "SENDER_HISTORY_HMAC_KEY": "k" * 32,
        }
        for name, value in (
            ("SENDER_HISTORY_RETENTION_DAYS", "0"),
            ("SENDER_HISTORY_RETENTION_DAYS", "366"),
            ("SENDER_HISTORY_TIMEOUT_SECONDS", "0.09"),
            ("SENDER_HISTORY_TIMEOUT_SECONDS", "3.1"),
        ):
            with self.subTest(name=name, value=value):
                settings = load_settings({**base, name: value})
                self.assertFalse(settings.sender_history_ready)
                self.assertIsNotNone(settings.sender_history_config_error)

    def test_sender_history_malformed_url_is_reported_without_crashing_startup(self):
        settings = load_settings({
            "APP_ENV": "test",
            "SENDER_HISTORY_ENABLED": "true",
            "UPSTASH_REDIS_REST_URL": "https://example.upstash.io:not-a-port",
            "UPSTASH_REDIS_REST_TOKEN": "secret-token",
            "SENDER_HISTORY_HMAC_KEY": "k" * 32,
        })

        self.assertFalse(settings.sender_history_ready)
        self.assertEqual(
            settings.sender_history_config_error,
            "Sender history configuration is invalid.",
        )

    def test_sender_history_malformed_enable_flag_disables_only_history(self):
        settings = load_settings({
            "APP_ENV": "test",
            "SENDER_HISTORY_ENABLED": "tru",
        })

        self.assertFalse(settings.sender_history_enabled)
        self.assertFalse(settings.sender_history_ready)
        self.assertEqual(
            settings.sender_history_config_error,
            "Sender history configuration is invalid.",
        )

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
