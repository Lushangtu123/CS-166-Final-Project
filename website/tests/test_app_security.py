import asyncio
from collections import deque
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
import content_model
from config import Settings


class VerificationFeatureGateTests(unittest.TestCase):
    def test_smtp_probe_rejects_private_target_before_opening_a_socket(self):
        with patch.object(
            app.smtplib,
            "SMTP",
            side_effect=AssertionError("private target must not open SMTP"),
        ):
            result = app._smtp_probe(
                "user@example.com",
                "mail.example.com",
                "127.0.0.1",
            )

        self.assertFalse(result["connectable"])
        self.assertEqual(result["result"], "unverifiable")
        self.assertIn("non-public", result["message"].lower())

    def test_mixed_dns_answers_keep_only_global_smtp_targets(self):
        answers = [
            (app.socket.AF_INET, app.socket.SOCK_STREAM, 6, "", ("10.0.0.5", 25)),
            (app.socket.AF_INET, app.socket.SOCK_STREAM, 6, "", ("8.8.8.8", 25)),
            (app.socket.AF_INET6, app.socket.SOCK_STREAM, 6, "", ("::1", 25, 0, 0)),
        ]

        addresses = app._resolve_public_smtp_addresses(
            "mail.example.com",
            resolver=lambda *_args, **_kwargs: answers,
        )

        self.assertEqual(addresses, ["8.8.8.8"])

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
            "content_model_enabled": False,
            "full_version_local_only": True,
        })


class RateLimitBoundaryTests(unittest.TestCase):
    def test_forwarded_header_does_not_override_framework_client_address(self):
        request = app.Request({
            "type": "http",
            "method": "POST",
            "path": "/api/analyze-content",
            "raw_path": b"/api/analyze-content",
            "query_string": b"",
            "headers": [(b"x-forwarded-for", b"198.51.100.77")],
            "client": ("203.0.113.9", 43100),
            "server": ("testserver", 80),
            "scheme": "http",
        })

        self.assertEqual(
            app._rate_limit_key(request),
            "203.0.113.9:/api/analyze-content",
        )

    def test_bucket_store_evicts_oldest_entry_at_hard_capacity(self):
        buckets = {
            "old:/api/a": deque([10.0]),
            "new:/api/a": deque([20.0]),
        }

        allowed = app._record_rate_limit_hit(
            "third:/api/a",
            now=30.0,
            buckets=buckets,
            limit=20,
            capacity=2,
            window_seconds=60.0,
        )

        self.assertTrue(allowed)
        self.assertEqual(len(buckets), 2)
        self.assertNotIn("old:/api/a", buckets)
        self.assertIn("third:/api/a", buckets)


class ContentModelArtifactTests(unittest.TestCase):
    def test_artifact_round_trip_requires_matching_sha256(self):
        pipeline = {
            "vectorizer": "vectorizer-fixture",
            "clf": "classifier-fixture",
            "decision_threshold": 0.4,
            "metrics": {"model": "fixture"},
            "top_terms": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "content-model.pkl"
            digest = content_model.save_content_pipeline_artifact(pipeline, path)

            loaded = content_model.load_content_pipeline_artifact(path, digest)
            with self.assertRaises(ValueError) as error:
                content_model.load_content_pipeline_artifact(path, "0" * 64)

        self.assertEqual(loaded, pipeline)
        self.assertIn("sha-256", str(error.exception).lower())

    def test_enabled_lifespan_loads_artifact_without_training(self):
        pipeline = {
            "vectorizer": "vectorizer-fixture",
            "clf": "classifier-fixture",
            "decision_threshold": 0.4,
            "metrics": {"model": "fixture"},
            "top_terms": [],
        }
        artifact_settings = Settings(
            app_env="test",
            enable_email_verification=False,
            content_model_enabled=True,
            content_model_artifact="/models/content-model.pkl",
            content_model_artifact_sha256="a" * 64,
        )

        async def run_lifespan():
            async with app.lifespan(app.app):
                return json.loads((await app.health()).body)

        with patch.object(app, "SETTINGS", artifact_settings):
            with patch.object(
                app,
                "load_content_pipeline_artifact",
                return_value=pipeline,
            ) as load_artifact:
                with patch.object(
                    content_model,
                    "build_content_pipeline_from_env",
                    side_effect=AssertionError("web startup must not train"),
                ):
                    payload = asyncio.run(run_lifespan())

        load_artifact.assert_called_once()
        self.assertTrue(payload["content_model_loaded"])
        self.assertIsNone(payload["content_model_error"])

    def test_invalid_artifact_degrades_to_rules_without_failing_startup(self):
        artifact_settings = Settings(
            app_env="test",
            enable_email_verification=False,
            content_model_enabled=True,
            content_model_artifact="/models/content-model.pkl",
            content_model_artifact_sha256="a" * 64,
        )

        async def run_lifespan():
            async with app.lifespan(app.app):
                return json.loads((await app.health()).body)

        with patch.object(app, "SETTINGS", artifact_settings):
            with patch.object(
                app,
                "load_content_pipeline_artifact",
                side_effect=ValueError("digest mismatch"),
            ):
                payload = asyncio.run(run_lifespan())

        self.assertEqual(payload["status"], "ok")
        self.assertFalse(payload["content_model_loaded"])
        self.assertIn("digest mismatch", payload["content_model_error"])

    def test_missing_artifact_health_error_does_not_expose_local_path(self):
        private_path = "/sensitive/private/content-model.pkl"
        artifact_settings = Settings(
            app_env="test",
            enable_email_verification=False,
            content_model_enabled=True,
            content_model_artifact=private_path,
            content_model_artifact_sha256="a" * 64,
        )

        async def run_lifespan():
            async with app.lifespan(app.app):
                return json.loads((await app.health()).body)

        with patch.object(app, "SETTINGS", artifact_settings):
            payload = asyncio.run(run_lifespan())

        self.assertFalse(payload["content_model_loaded"])
        self.assertNotIn(private_path, payload["content_model_error"])

    def test_legacy_raw_feature_prediction_route_is_absent(self):
        route_paths = {
            route.path
            for route in app.app.routes
            if hasattr(route, "path")
        }

        self.assertNotIn("/api/predict", route_paths)


if __name__ == "__main__":
    unittest.main()
