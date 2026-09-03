import asyncio
import json
import tempfile
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

from fastapi import HTTPException


WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app
from config import Settings


class VerificationFeatureGateTests(unittest.TestCase):
    def test_disabled_verification_stops_before_outbound_dns(self):
        request = app.VerifyRequest(email="user@example.com")

        with patch("dns.resolver.resolve", side_effect=AssertionError("DNS must not run")) as resolve:
            with self.assertRaises(HTTPException) as error:
                app.verify_email_endpoint(request)

        self.assertEqual(error.exception.status_code, 404)
        self.assertIn("local", error.exception.detail.lower())
        resolve.assert_not_called()

    def test_public_config_reports_verification_disabled(self):
        self.assertTrue(hasattr(app, "get_public_config"))

        response = asyncio.run(app.get_public_config())
        payload = json.loads(response.body)

        self.assertEqual(payload, {
            "email_verification_enabled": False,
            "full_version_local_only": True,
        })


class DatasetSafetyTests(unittest.TestCase):
    def test_explicit_local_fallback_is_reported_as_synthetic(self):
        local_settings = Settings(
            app_env="development",
            enable_email_verification=False,
            allow_synthetic_data=True,
        )
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(app, "DATA_DIR", Path(directory)):
                with patch.object(app, "SETTINGS", local_settings):
                    app._load_and_train()

        self.assertEqual(getattr(app, "_model_data_source", None), "synthetic")

    def test_missing_real_data_fails_when_synthetic_data_is_disabled(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(app, "DATA_DIR", Path(directory)):
                with self.assertRaises(RuntimeError) as error:
                    app._load_and_train()

        self.assertIn("ALLOW_SYNTHETIC_DATA", str(error.exception))

    def test_real_dataset_is_reported_as_real(self):
        rows = 20
        data = {name: [1 if i % 2 else -1 for i in range(rows)] for name in app.FEATURE_NAMES}
        data["result"] = [1 if i % 2 else -1 for i in range(rows)]

        with tempfile.TemporaryDirectory() as directory:
            app.pd.DataFrame(data).to_csv(Path(directory) / "phishing_dataset.csv", index=False)
            with patch.object(app, "DATA_DIR", Path(directory)):
                app._load_and_train()

        self.assertEqual(app._model_data_source, "real")

    def test_health_reports_model_source_and_safe_feature_state(self):
        with patch.object(app, "_model", object()):
            with patch.object(app, "_scaler", object()):
                with patch.object(app, "_model_data_source", "real"):
                    response = asyncio.run(app.health())

        payload = json.loads(response.body)
        self.assertEqual(payload.get("model_data_source"), "real")
        self.assertIs(payload.get("email_verification_enabled"), False)


if __name__ == "__main__":
    unittest.main()
