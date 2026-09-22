import asyncio
from collections import deque
import hashlib
import json
import os
import pickle
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


class AllowedHostConfigurationTests(unittest.TestCase):
    def test_custom_domains_are_merged_with_base_allowed_hosts(self):
        builder = getattr(app, "_build_allowed_hosts", None)
        self.assertIsNotNone(builder, "custom-domain host configuration is missing")

        self.assertEqual(
            builder(
                "*.vercel.app,localhost",
                "phishguard.example, www.phishguard.example,phishguard.example",
            ),
            [
                "*.vercel.app",
                "localhost",
                "phishguard.example",
                "www.phishguard.example",
            ],
        )

    def test_custom_domains_reject_urls_and_paths(self):
        invalid_domains = (
            "https://phishguard.example/settings",
            ".",
            "a" * 250 + ".com",
        )
        for invalid in invalid_domains:
            with self.subTest(domain=invalid), self.assertRaisesRegex(ValueError, "hostname"):
                app._build_allowed_hosts("*.vercel.app,localhost", invalid)


class VercelEntrypointTests(unittest.TestCase):
    def test_committed_vercel_profile_has_a_runtime_smoke_test(self):
        deployment_python = (PROJECT_ROOT / ".python-version").read_text().strip()
        current_python = f"{sys.version_info.major}.{sys.version_info.minor}"
        if current_python != deployment_python:
            self.skipTest(
                f"Vercel artifact targets Python {deployment_python}, not {current_python}"
            )
        smoke_test = WEBSITE_DIR / "tests" / "vercel_runtime_smoke.py"
        self.assertTrue(smoke_test.is_file(), "Vercel runtime smoke test is missing")

        result = subprocess.run(
            [sys.executable, str(smoke_test)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout.splitlines()[-1])
        self.assertTrue(payload["model_loaded"])
        self.assertEqual(payload["verification_mode"], "lite")
        self.assertIn(payload["risk_level"], {"high", "critical"})
        self.assertEqual(len(payload["legitimate_risk_levels"]), 2)
        self.assertTrue(
            all(
                risk_level not in {"high", "critical"}
                for risk_level in payload["legitimate_risk_levels"]
            )
        )

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

        with patch.dict(os.environ, {'PHISHGUARD_JEV_ENABLED': 'false'}):
            response = asyncio.run(app.get_public_config())
        payload = json.loads(response.body)
        self.assertIsInstance(payload.pop("feedback_enabled"), bool)

        self.assertEqual(payload, {
            "jev_enabled": False,
            "jev_configured": False,
            "deployment_profile": app.SETTINGS.app_env,
            "email_verification_enabled": False,
            "verification_mode": "off",
            "domain_verification_enabled": False,
            "smtp_verification_enabled": False,
            "content_model_enabled": False,
            "sender_history_enabled": False,
            "sender_history_available": False,
            "sender_history_configured": False,
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

    def test_vercel_uses_the_platform_client_ip_instead_of_the_proxy_peer(self):
        def request(ip):
            return app.Request({
                "type": "http",
                "method": "POST",
                "path": "/api/analyze-content",
                "raw_path": b"/api/analyze-content",
                "query_string": b"",
                "headers": [(b"x-forwarded-for", ip.encode())],
                "client": ("10.0.0.8", 43100),
                "server": ("testserver", 80),
                "scheme": "https",
            })

        with patch.dict(
            os.environ,
            {"PHISHGUARD_DEPLOYMENT_PROFILE": "vercel-free"},
        ):
            first = app._rate_limit_key(request("203.0.113.9"))
            second = app._rate_limit_key(request("198.51.100.77"))

        self.assertEqual(first, "203.0.113.9:/api/analyze-content")
        self.assertEqual(second, "198.51.100.77:/api/analyze-content")
        self.assertNotEqual(first, second)

    def test_vercel_rejects_ambiguous_or_invalid_forwarded_addresses(self):
        def request(value):
            return app.Request({
                "type": "http",
                "method": "POST",
                "path": "/api/analyze-content",
                "raw_path": b"/api/analyze-content",
                "query_string": b"",
                "headers": [(b"x-forwarded-for", value.encode())],
                "client": ("10.0.0.8", 43100),
                "server": ("testserver", 80),
                "scheme": "https",
            })

        with patch.dict(
            os.environ,
            {"PHISHGUARD_DEPLOYMENT_PROFILE": "vercel-free"},
        ):
            for value in ("203.0.113.9, 198.51.100.77", "not-an-ip", ""):
                with self.subTest(value=value):
                    self.assertEqual(
                        app._rate_limit_key(request(value)),
                        "10.0.0.8:/api/analyze-content",
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

    def test_upstash_distributed_limit_blocks_across_serverless_instances(self):
        class _BlockedStore:
            def __init__(self):
                self.calls = []

            async def check_rate_limit(self, identity, *, limit, window_seconds):
                self.calls.append((identity, limit, window_seconds))
                return SimpleNamespace(allowed=False, retry_after=23)

        async def request():
            payload = json.dumps({"subject": "Hello", "body": "World"}).encode()
            delivered = False
            output = []
            scope = {
                "type": "http", "asgi": {"version": "3.0"},
                "http_version": "1.1", "method": "POST", "scheme": "http",
                "path": "/api/analyze-content",
                "raw_path": b"/api/analyze-content", "root_path": "",
                "query_string": b"",
                "headers": [
                    (b"host", b"localhost"),
                    (b"content-type", b"application/json"),
                ],
                "client": ("203.0.113.9", 12345),
                "server": ("localhost", 8000),
            }

            async def receive():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {
                        "type": "http.request", "body": payload,
                        "more_body": False,
                    }
                return {"type": "http.disconnect"}

            async def send(message):
                output.append(message)

            await app.app(scope, receive, send)
            return next(
                message for message in output
                if message["type"] == "http.response.start"
            )

        store = _BlockedStore()
        with patch.object(app, "_sender_history_store", store):
            response = asyncio.run(request())

        self.assertEqual(response["status"], 429)
        headers = dict(response["headers"])
        self.assertEqual(headers[b"retry-after"], b"23")
        self.assertEqual(store.calls, [
            ("203.0.113.9:/api/analyze-content", app.RATE_LIMIT_PER_MINUTE, 60),
        ])


class ContentModelArtifactTests(unittest.TestCase):
    def test_artifact_loaders_reject_different_sklearn_patch(self):
        from sklearn.linear_model import LogisticRegression
        from content_inference import load_content_pipeline_artifact

        pipeline = {
            "vectorizer": "vectorizer-fixture",
            "clf": LogisticRegression(),
            "decision_threshold": 0.4,
            "metrics": {},
            "top_terms": [],
        }
        other_patch = (
            "1.9.1" if content_model.sklearn.__version__ == "1.9.0" else "1.9.0"
        )
        with patch("sklearn.base.__version__", other_patch):
            payload = pickle.dumps({
                "schema": "phishguard-content-model-v1",
                "python": content_model._major_minor(sys.version.split()[0]),
                "scikit_learn": content_model._major_minor(
                    content_model.sklearn.__version__
                ),
                "pipeline": pipeline,
            })
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "older-model.pkl"
            path.write_bytes(payload)
            digest = hashlib.sha256(payload).hexdigest()
            for loader in (load_content_pipeline_artifact,
                           content_model.load_content_pipeline_artifact):
                with self.subTest(loader=loader.__module__):
                    with self.assertRaisesRegex(ValueError, "scikit-learn"):
                        loader(path, digest)

    def test_health_exposes_only_valid_deployment_commit_sha(self):
        with patch.dict(os.environ, {"VERCEL_GIT_COMMIT_SHA": "A" * 40}):
            health = json.loads(asyncio.run(app.health()).body)
        self.assertEqual(health["commit_sha"], "a" * 40)
        with patch.dict(os.environ, {"VERCEL_GIT_COMMIT_SHA": "not-a-commit"}):
            health = json.loads(asyncio.run(app.health()).body)
        self.assertIsNone(health["commit_sha"])

    def test_committed_model_abstains_on_unsupported_text_and_passes_hard_negatives(self):
        deployment_python = (PROJECT_ROOT / ".python-version").read_text().strip()
        current_python = f"{sys.version_info.major}.{sys.version_info.minor}"
        if current_python != deployment_python:
            self.skipTest(
                f"Committed artifact targets Python {deployment_python}, not "
                f"{current_python}"
            )
        profile = json.loads(
            (PROJECT_ROOT / "vercel.json").read_text(encoding="utf-8")
        )
        from content_inference import load_content_pipeline_artifact, predict_content
        from content_model import _CACHE_VERSION
        pipeline = load_content_pipeline_artifact(
            PROJECT_ROOT / profile["env"]["CONTENT_MODEL_ARTIFACT"],
            profile["env"]["CONTENT_MODEL_ARTIFACT_SHA256"],
        )
        self.assertEqual(
            pipeline["metrics"]["build_provenance"]["cache_version"],
            _CACHE_VERSION,
        )

        unsupported_messages = (
            ("会议提醒", "大家好，明天下午三点开会，请提前阅读项目文档。"),
            ("会議のお知らせ", "明日の午後三時にチーム会議を開きます。資料を確認してください。"),
            ("🪐🧿", "🫧🪻🧬🗿"),
        )
        for subject, body in unsupported_messages:
            with self.subTest(unsupported_subject=subject):
                unsupported = predict_content(pipeline, subject, body)
                self.assertEqual(
                    unsupported["ml_status"],
                    "insufficient_context",
                )

        short_legitimate_subjects = (
            "Hello",
            "Meeting notes",
            "File shared with you",
            "Your receipt",
            "Document available",
        )
        for subject in short_legitimate_subjects:
            with self.subTest(short_legitimate_subject=subject):
                result = predict_content(pipeline, subject, "")
                self.assertEqual(result["ml_status"], "insufficient_context")
                self.assertIsNone(result["ml_prediction"])
                self.assertIsNone(result["ml_phishing_probability"])

        hard_negatives = (
            (
                "Hi team",
                "Please review the project notes before our meeting tomorrow.",
            ),
            (
                "Hey",
                "I loved the photos from the trip. See you this weekend.",
            ),
            (
                "Monthly project update",
                "Attached is the monthly report. Revenue increased and the team "
                "completed the scheduled maintenance.",
            ),
            (
                "Project notes for tomorrow",
                "Hello everyone, please review the agenda before our scheduled meeting.",
            ),
            (
                "Weekend photos",
                "I really enjoyed the trip photos. See you for lunch this weekend.",
            ),
            (
                "Operations summary",
                "The team completed scheduled maintenance and the monthly report is attached.",
            ),
        )
        for subject, body in hard_negatives:
            with self.subTest(subject=subject):
                result = predict_content(pipeline, subject, body)
                self.assertEqual(result["ml_status"], "available")
                self.assertEqual(result["ml_prediction"], 0)

        from email_structure import analyze_raw_email

        provider_fixtures = (
            b"From: Alice <alice@gmail.com>\r\n"
            b"To: Bob <bob@outlook.com>\r\n"
            b"Subject: Dinner plans for Saturday\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Hi Bob, are we still meeting at the cafe at seven? I can bring "
            b"the photos from our hike.\r\n",
            b"From: Project Team <team@outlook.com>\r\n"
            b"To: member@gmail.com\r\n"
            b"Subject: Notes from today's planning session\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Hello, the meeting notes are attached. We moved the design review "
            b"to Thursday and kept the current owners.\r\n",
        )
        for raw_message in provider_fixtures:
            structure = analyze_raw_email(raw_message)
            with self.subTest(provider_subject=structure["subject"]):
                result = predict_content(
                    pipeline,
                    structure["subject"],
                    structure["body"],
                )
                self.assertEqual(result["ml_status"], "available")
                self.assertEqual(result["ml_prediction"], 0)

        phishing_controls = (
            (
                "Wire transfer request",
                "I am in a meeting. Please purchase gift cards for the client "
                "and send me the codes today.",
            ),
            (
                "Invoice problem - call support",
                "Your subscription renewal of $499 is complete. If you did not "
                "authorize this charge, call 1-888-555-0199 immediately.",
            ),
            (
                "Scan to avoid suspension",
                "Scan the QR code below to verify your Microsoft 365 password "
                "and keep your mailbox active.",
            ),
        )
        for subject, body in phishing_controls:
            with self.subTest(phishing_subject=subject):
                result = predict_content(pipeline, subject, body)
                self.assertEqual(result["ml_status"], "available")
                self.assertEqual(result["ml_prediction"], 1)

    def test_metrics_identify_the_loaded_artifact(self):
        pipeline = {
            "metrics": {"model": "fixture"},
            "top_terms": [],
        }
        with patch.object(app, "_content_pipeline", pipeline), patch.object(
            app, "_content_model_artifact_sha256", "a" * 64, create=True
        ):
            payload = json.loads(asyncio.run(app.get_metrics()).body)

        content_model = payload["content_model"]
        self.assertEqual(content_model.get("artifact_sha256"), "a" * 64)
        self.assertEqual(content_model.get("model_id"), "sha256:aaaaaaaaaaaa")

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
        from model_environment import RUNTIME_PACKAGE_NAMES, package_versions
        pipeline = {
            "vectorizer": "vectorizer-fixture",
            "clf": "classifier-fixture",
            "decision_threshold": 0.4,
            "metrics": {"model": "fixture", "build_provenance": {
                "python_version": content_model.platform.python_version(),
                "package_versions": package_versions((*RUNTIME_PACKAGE_NAMES, "pandas")),
            }},
            "top_terms": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "content-model.pkl"
            digest = content_model.save_content_pipeline_artifact(pipeline, path)
            envelope = pickle.loads(path.read_bytes())

            loaded = content_model.load_content_pipeline_artifact(path, digest)
            from content_inference import load_content_pipeline_artifact
            runtime_loaded = load_content_pipeline_artifact(path, digest)
            with self.assertRaises(ValueError) as error:
                content_model.load_content_pipeline_artifact(path, "0" * 64)

        self.assertEqual(loaded, pipeline)
        self.assertEqual(runtime_loaded, pipeline)
        self.assertEqual(envelope["scikit_learn"], content_model.sklearn.__version__)
        self.assertEqual(
            set(envelope["runtime_package_versions"]),
            {"numpy", "scipy", "scikit-learn", "joblib", "threadpoolctl"},
        )
        self.assertIn("sha-256", str(error.exception).lower())

    def test_artifact_loaders_reject_a_changed_runtime_dependency(self):
        from model_environment import RUNTIME_PACKAGE_NAMES, package_versions
        pipeline = {
            "vectorizer": "vectorizer-fixture",
            "clf": "classifier-fixture",
            "decision_threshold": 0.4,
            "metrics": {"model": "fixture", "build_provenance": {
                "python_version": content_model.platform.python_version(),
                "package_versions": package_versions((*RUNTIME_PACKAGE_NAMES, "pandas")),
            }},
            "top_terms": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "content-model.pkl"
            content_model.save_content_pipeline_artifact(pipeline, path)
            envelope = pickle.loads(path.read_bytes())
            envelope["runtime_package_versions"]["numpy"] = "0.0.0"
            payload = pickle.dumps(envelope)
            path.write_bytes(payload)
            digest = hashlib.sha256(payload).hexdigest()
            from content_inference import load_content_pipeline_artifact
            for loader in (load_content_pipeline_artifact,
                           content_model.load_content_pipeline_artifact):
                with self.subTest(loader=loader.__module__):
                    with self.assertRaisesRegex(ValueError, "numpy"):
                        loader(path, digest)

    def test_saving_an_unversioned_pipeline_does_not_claim_training_versions(self):
        pipeline = {
            "vectorizer": "vectorizer-fixture",
            "clf": "classifier-fixture",
            "decision_threshold": 0.4,
            "metrics": {"model": "fixture"},
            "top_terms": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unversioned-model.pkl"
            content_model.save_content_pipeline_artifact(pipeline, path)
            envelope = pickle.loads(path.read_bytes())
        self.assertNotIn("runtime_package_versions", envelope)

    def test_saving_rejects_dependency_changes_since_training(self):
        from model_environment import RUNTIME_PACKAGE_NAMES, package_versions
        versions = package_versions((*RUNTIME_PACKAGE_NAMES, "pandas"))
        versions["numpy"] = "0.0.0"
        pipeline = {
            "vectorizer": "vectorizer-fixture",
            "clf": "classifier-fixture",
            "decision_threshold": 0.4,
            "metrics": {"build_provenance": {
                "python_version": content_model.platform.python_version(),
                "package_versions": versions,
            }},
            "top_terms": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "changed-model.pkl"
            with self.assertRaisesRegex(ValueError, "numpy changed since training"):
                content_model.save_content_pipeline_artifact(pipeline, path)
            self.assertFalse(path.exists())

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
        self.assertEqual(payload.get("content_model_artifact_sha256"), "a" * 64)
        self.assertEqual(payload.get("content_model_id"), "sha256:aaaaaaaaaaaa")

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
