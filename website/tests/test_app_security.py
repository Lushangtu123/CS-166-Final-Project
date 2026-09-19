import asyncio
from collections import deque
import json
import os
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

from fastapi import HTTPException


WEBSITE_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = WEBSITE_DIR.parent
sys.path.insert(0, str(WEBSITE_DIR))

import app
import content_model
from config import Settings


class VercelEntrypointTests(unittest.TestCase):
    def test_root_entrypoint_starts_lite_profile_without_training_stack(self):
        environment = os.environ.copy()
        environment.update({
            "APP_ENV": "production",
            "VERIFICATION_MODE": "lite",
            "CONTENT_MODEL_ENABLED": "false",
            "VERIFICATION_WORKERS": "4",
        })
        code = (
            "import asyncio,json,sys,app; backend=sys.modules['website.app']; "
            "config=json.loads(asyncio.run(backend.get_public_config()).body); "
            "print(json.dumps({'title': app.app.title, 'config': config, "
            "'heavy': [name for name in ('pandas','numpy','sklearn') if name in sys.modules]}))"
        )

        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=PROJECT_ROOT,
            env=environment,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["title"], "Phishing Email Detector")
        self.assertEqual(payload["config"]["verification_mode"], "lite")
        self.assertTrue(payload["config"]["domain_verification_enabled"])
        self.assertFalse(payload["config"]["smtp_verification_enabled"])
        self.assertEqual(payload["heavy"], [])


class VerificationFeatureGateTests(unittest.TestCase):
    def test_busy_verification_returns_retryable_error_without_starting_dns(self):
        from verification_runtime import BoundedExecutor
        pool = BoundedExecutor(workers=1)
        gate = threading.Event()
        started = threading.Event()
        def occupied():
            started.set()
            gate.wait(2)
        held = pool.submit(occupied)
        self.assertTrue(started.wait(1))
        try:
            with patch.object(app, '_verification_pool', pool), \
                 patch.object(app, 'SETTINGS', Settings(app_env='development', enable_email_verification=True)), \
                 patch('dns.resolver.resolve', side_effect=AssertionError('Busy request must not query DNS')):
                with self.assertRaises(HTTPException) as error:
                    app.verify_email_endpoint(app.VerifyRequest(email='user@example.com'))
                self.assertEqual(error.exception.status_code, 503)
                self.assertIn('Retry-After', error.exception.headers)
        finally:
            gate.set()
            held.result(timeout=2)
            pool.shutdown()

    def test_verification_deadline_also_covers_initial_dns(self):
        import dns.exception
        gate = threading.Event()
        def slow_dns(*args, **kwargs):
            gate.wait(1)
            raise dns.exception.Timeout
        try:
            with patch.object(app, 'SETTINGS', Settings(app_env='development', enable_email_verification=True)), \
                 patch.object(app, 'VERIFICATION_TIMEOUT', 0.05), \
                 patch('dns.resolver.resolve', side_effect=slow_dns):
                start = time.monotonic()
                result = json.loads(app.verify_email_endpoint(app.VerifyRequest(email='user@example.com')).body)
                self.assertLess(time.monotonic() - start, 0.5)
                self.assertEqual(result['overall'], 'unverifiable')
                self.assertFalse(result['verification_complete'])
        finally:
            gate.set()

    def test_verification_pool_has_no_unbounded_pending_queue(self):
        from verification_runtime import BoundedExecutor
        pool = BoundedExecutor(workers=2)
        gate = threading.Event()
        try:
            first = pool.submit(gate.wait, 1)
            second = pool.submit(gate.wait, 1)
            self.assertIsNone(pool.submit(lambda: 'must not queue'))
            self.assertFalse(first.cancel())
            self.assertIsNone(pool.submit(lambda: 'timeout does not free a running slot'))
            gate.set()
            first.result(timeout=2)
            second.result(timeout=2)
            self.assertEqual(pool.submit(lambda: 'recovered').result(timeout=2), 'recovered')
        finally:
            gate.set()
            pool.shutdown()

    def test_verification_deadline_does_not_wait_for_slow_whois(self):
        import dns.resolver
        gate = threading.Event()
        def resolve(_domain, kind, **kwargs):
            if kind == 'MX':
                return [SimpleNamespace(preference=0, exchange='127.0.0.1.')]
            raise dns.resolver.NoAnswer
        def slow_whois(*args, **kwargs):
            gate.wait(1)
            return SimpleNamespace(creation_date=None)
        try:
            with patch.object(app, 'SETTINGS', Settings(app_env='development', enable_email_verification=True)), \
                 patch.object(app, 'VERIFICATION_TIMEOUT', 0.05, create=True), \
                 patch('dns.resolver.resolve', side_effect=resolve), \
                 patch('whois.whois', side_effect=slow_whois), \
                 patch('smtplib.SMTP', side_effect=AssertionError('No real SMTP')):
                start = time.monotonic()
                result = json.loads(app.verify_email_endpoint(app.VerifyRequest(email='user@example.com')).body)
                elapsed = time.monotonic() - start
                self.assertLess(elapsed, 0.5)
                self.assertIn('timed out', result['domain_age']['message'].lower())
                self.assertFalse(result['verification_complete'])
        finally:
            gate.set()

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
            "deployment_profile": app.SETTINGS.app_env,
            "email_verification_enabled": False,
            "verification_mode": "off",
            "domain_verification_enabled": False,
            "smtp_verification_enabled": False,
            "content_model_enabled": False,
            "full_version_local_only": True,
        })

    def test_public_config_distinguishes_local_disabled_and_enabled(self):
        for enabled in (False, True):
            with patch.object(app, "SETTINGS", Settings(
                app_env="development", enable_email_verification=enabled,
            )):
                payload = json.loads(asyncio.run(app.get_public_config()).body)
                self.assertEqual(payload["deployment_profile"], "development")
                self.assertEqual(payload["email_verification_enabled"], enabled)


class RateLimitBoundaryTests(unittest.TestCase):
    def test_actual_request_bytes_are_bounded_with_or_without_length_header(self):
        async def request(size, declared_length=None):
            payload = json.dumps({'body': 'Hello', 'padding': 'x' * size}).encode()
            remaining = [payload[:30000], payload[30000:]]
            done = asyncio.Event()
            output = []
            headers = [(b'host', b'localhost'), (b'content-type', b'application/json')]
            if declared_length is not None:
                headers.append((b'content-length', str(declared_length).encode()))
            scope = {'type': 'http', 'asgi': {'version': '3.0'}, 'http_version': '1.1',
                     'method': 'POST', 'scheme': 'http', 'path': '/api/analyze-content',
                     'raw_path': b'/api/analyze-content', 'root_path': '', 'query_string': b'',
                     'headers': headers, 'client': ('127.0.0.1', 12345), 'server': ('localhost', 8000)}
            async def receive():
                if remaining:
                    part = remaining.pop(0)
                    return {'type': 'http.request', 'body': part, 'more_body': bool(remaining)}
                await done.wait()
                return {'type': 'http.disconnect'}
            async def send(message):
                output.append(message)
                if message['type'] == 'http.response.body' and not message.get('more_body'):
                    done.set()
            await asyncio.wait_for(app.app(scope, receive, send), 2)
            return next(m for m in output if m['type'] == 'http.response.start')
        for declared in (None, 1):
            response = asyncio.run(request(app.MAX_REQUEST_BYTES + 100, declared))
            self.assertEqual(response['status'], 413)
            self.assertIn(b'x-content-type-options', dict(response['headers']))
        self.assertEqual(asyncio.run(request(100))['status'], 200)

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
    def test_inference_runtime_does_not_import_pandas(self):
        code = (
            "import builtins; original=builtins.__import__; "
            "builtins.__import__=lambda name,*a,**k: "
            "(_ for _ in ()).throw(ImportError('pandas unavailable')) "
            "if name == 'pandas' or name.startswith('pandas.') else original(name,*a,**k); "
            "import content_inference; print('ok')"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=WEBSITE_DIR,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "ok")

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
            from content_inference import load_content_pipeline_artifact
            runtime_loaded = load_content_pipeline_artifact(path, digest)
            with self.assertRaises(ValueError) as error:
                content_model.load_content_pipeline_artifact(path, "0" * 64)

        self.assertEqual(loaded, pipeline)
        self.assertEqual(runtime_loaded, pipeline)
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
