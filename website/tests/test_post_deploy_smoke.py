import json
from pathlib import Path
import sys
import unittest
from urllib.error import HTTPError, URLError


WEBSITE_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = WEBSITE_DIR.parent
sys.path.insert(0, str(WEBSITE_DIR))

try:
    from tools import post_deploy_smoke
except ImportError:
    post_deploy_smoke = None


class _Response:
    def __init__(
        self,
        payload,
        *,
        content_type="application/json",
        final_url="https://project.vercel.app/health",
    ):
        self.payload = payload
        self.headers = {"Content-Type": content_type}
        self._final_url = final_url

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        if isinstance(self.payload, bytes):
            return self.payload
        return json.dumps(self.payload).encode("utf-8")

    def geturl(self):
        return self._final_url


class PostDeploySmokeTests(unittest.TestCase):
    def test_jev_configuration_gate_is_read_only_and_requires_both_contracts(self):
        health = {'status': 'ok', 'content_model_loaded': True, 'commit_sha': 'c' * 40,
                  'content_model_artifact_sha256': 'a' * 64, 'jev_enabled': True, 'jev_configured': True}
        config = {'verification_mode': 'lite', 'content_model_enabled': True,
                  'jev_enabled': True, 'jev_configured': True}
        calls = []
        def opener(request, timeout):
            calls.append((request.get_method(), request.full_url))
            return _Response(health if request.full_url.endswith('/health') else config)
        def check():
            return post_deploy_smoke._read_deployment_readiness('https://project.vercel.app',
                expected_commit_sha='c' * 40, expected_model_sha256='a' * 64, opener=opener,
                require_sender_history=False, require_jev=True)
        check()
        for payload in (health, config):
            for field in ('jev_enabled', 'jev_configured'):
                for value in (False, None):
                    payload[field] = value
                    with self.assertRaisesRegex(RuntimeError, 'Jev'):
                        check()
                payload[field] = True
        self.assertTrue(all(method == 'GET' and url.endswith(('/health', '/api/config')) for method, url in calls))

    def test_case_auth_boundary_requires_anonymous_denial(self):
        requests = []
        def rejected(request, timeout):
            requests.append((request.full_url, timeout))
            raise HTTPError(request.full_url, 401, 'unauthorized', {}, None)
        post_deploy_smoke._check_case_auth_boundary('https://project.vercel.app', opener=rejected)
        self.assertEqual(requests, [('https://project.vercel.app/api/cases/me', 20)])
        for status in (404, 503):
            with self.subTest(status=status):
                def failed(request, timeout):
                    raise HTTPError(request.full_url, status, 'not ready', {}, None)
                with self.assertRaisesRegex(RuntimeError, f'HTTP {status}'):
                    post_deploy_smoke._check_case_auth_boundary('https://project.vercel.app', opener=failed)
        with self.assertRaisesRegex(RuntimeError, 'allowed anonymous'):
            post_deploy_smoke._check_case_auth_boundary(
                'https://project.vercel.app', opener=lambda *_args, **_kwargs: _Response({}))

    def test_smoke_checks_health_config_and_prediction(self):
        self.assertIsNotNone(post_deploy_smoke, "post-deploy smoke module is missing")
        requests = []
        history_observations = 0

        def opener(request, timeout):
            nonlocal history_observations
            requests.append((request.full_url, request.get_method(), timeout))
            if request.full_url.endswith("/health"):
                return _Response({
                    "status": "ok",
                    "commit_sha": "c" * 40,
                    "content_model_loaded": True,
                    "content_model_id": "sha256:abc123",
                    "content_model_artifact_sha256": "a" * 64,
                    "sender_history_enabled": True,
                    "sender_history_available": True,
                    "sender_history_configured": True,
                })
            if request.full_url.endswith("/api/config"):
                return _Response({
                    "verification_mode": "lite",
                    "content_model_enabled": True,
                    "sender_history_enabled": True,
                    "sender_history_available": True,
                    "sender_history_configured": True,
                })
            if request.full_url.endswith("/api/analyze-eml"):
                self.assertEqual(request.headers["Content-type"], "message/rfc822")
                self.assertIn(b"multipart/alternative", request.data)
                return _Response({
                    "risk_level": "critical", "ml_prediction": 1,
                    "ml_status": "available",
                })
            if request.full_url.endswith("/api/analyze-content"):
                body = json.loads(request.data.decode("utf-8"))
                if body.get("raw_email"):
                    history_observations += 1
                    return _Response({
                        "risk_level": "safe",
                        "sender_analysis": {
                            "sender_history_status": (
                                "first_seen"
                                if history_observations == 1
                                else "previously_seen"
                            ),
                            "sender_history_scope": "this_service_history",
                        },
                    })
                if body["subject"] in {
                    "Monthly project update",
                    "Notes from today's planning session",
                }:
                    return _Response({
                        "risk_level": "safe",
                        "ml_prediction": 0,
                        "ml_status": "available",
                    })
                return _Response({
                    "risk_level": "critical",
                    "ml_prediction": 1,
                    "ml_status": "available",
                })
            raise URLError("unexpected URL")

        result = post_deploy_smoke.validate_deployment(
            "https://project.vercel.app",
            expected_model_sha256="a" * 64,
            expected_commit_sha="c" * 40,
            opener=opener,
            require_sender_history=True,
            history_probe_id="test-probe",
        )

        self.assertEqual(result["risk_level"], "critical")
        self.assertEqual(result["legitimate_risk_level"], "safe")
        self.assertEqual(result["legitimate_control_count"], 2)
        self.assertEqual(result["sender_history_probe"], "previously_seen")
        self.assertEqual(result["commit_sha"], "c" * 40)
        self.assertEqual(result["mime_phishing_risk_level"], "critical")
        self.assertEqual(
            [method for _, method, _ in requests],
            ["GET", "GET", "POST", "POST", "POST", "POST", "POST", "POST"],
        )
        self.assertTrue(all(timeout == 20 for _, _, timeout in requests))

    def test_readiness_retries_do_not_repeat_stateful_controls(self):
        self.assertIsNotNone(post_deploy_smoke, "post-deploy smoke module is missing")
        requests = []
        sleeps = []
        health_attempts = 0

        def opener(request, timeout):
            nonlocal health_attempts
            requests.append((request.full_url, request.get_method()))
            if request.full_url.endswith("/health"):
                health_attempts += 1
                return _Response({
                    "status": "ok",
                    "commit_sha": "c" * 40,
                    "content_model_loaded": True,
                    "content_model_id": "sha256:abc123",
                    "content_model_artifact_sha256": (
                        "b" * 64 if health_attempts == 1 else "a" * 64
                    ),
                    "sender_history_enabled": True,
                    "sender_history_available": True,
                    "sender_history_configured": True,
                })
            if request.full_url.endswith("/api/config"):
                return _Response({
                    "verification_mode": "lite",
                    "content_model_enabled": True,
                    "sender_history_enabled": True,
                    "sender_history_available": True,
                    "sender_history_configured": True,
                })
            if request.full_url.endswith("/api/analyze-eml"):
                return _Response({
                    "risk_level": "critical", "ml_prediction": 1,
                    "ml_status": "available",
                })
            body = json.loads(request.data.decode("utf-8"))
            if body.get("raw_email"):
                repeated = sum(
                    method == "POST" and url.endswith("/api/analyze-content")
                    for url, method in requests
                ) >= 5
                return _Response({
                    "risk_level": "safe",
                    "sender_analysis": {
                        "sender_history_status": (
                            "previously_seen" if repeated else "first_seen"
                        ),
                        "sender_history_scope": "this_service_history",
                    },
                })
            if body["subject"] in {
                "Monthly project update",
                "Notes from today's planning session",
            }:
                return _Response({
                    "risk_level": "safe", "ml_prediction": 0,
                    "ml_status": "available",
                })
            return _Response({
                "risk_level": "critical", "ml_prediction": 1,
                "ml_status": "available",
            })

        result = post_deploy_smoke.validate_deployment(
            "https://project.vercel.app",
            expected_model_sha256="a" * 64,
            expected_commit_sha="c" * 40,
            opener=opener,
            require_sender_history=True,
            history_probe_id="retry-probe",
            readiness_attempts=2,
            retry_delay=3,
            sleeper=sleeps.append,
        )

        self.assertEqual(result["sender_history_probe"], "previously_seen")
        self.assertEqual(sleeps, [3])
        self.assertEqual(
            sum(method == "POST" for _, method in requests),
            6,
        )
        self.assertEqual(
            [method for _, method in requests[:3]],
            ["GET", "GET", "GET"],
        )

    def test_smoke_rejects_non_vercel_targets(self):
        self.assertIsNotNone(post_deploy_smoke, "post-deploy smoke module is missing")
        with self.assertRaisesRegex(ValueError, "vercel.app"):
            post_deploy_smoke.validate_deployment(
                "https://internal.example",
                expected_model_sha256="a" * 64,
                expected_commit_sha="c" * 40,
                opener=lambda *_args, **_kwargs: self.fail("network should not run"),
            )

    def test_smoke_reports_protected_or_non_json_deployments_clearly(self):
        self.assertIsNotNone(post_deploy_smoke, "post-deploy smoke module is missing")

        with self.assertRaisesRegex(RuntimeError, "non-JSON|redirected"):
            post_deploy_smoke.validate_deployment(
                "https://project.vercel.app",
                expected_model_sha256="a" * 64,
                expected_commit_sha="c" * 40,
                opener=lambda *_args, **_kwargs: _Response(
                    b"<html>Log in to Vercel</html>",
                    content_type="text/html; charset=utf-8",
                    final_url="https://vercel.com/login",
                ),
            )

    def test_smoke_rejects_stale_alias_before_sending_controls(self):
        for deployed_commit in ("b" * 40, None):
            with self.subTest(deployed_commit=deployed_commit):
                requests = []

                def opener(request, timeout):
                    requests.append(request.get_method())
                    return _Response({
                        "status": "ok", "content_model_loaded": True,
                        "content_model_artifact_sha256": "a" * 64,
                        "commit_sha": deployed_commit,
                    })

                with self.assertRaisesRegex(RuntimeError, "commit"):
                    post_deploy_smoke.validate_deployment(
                        "https://project.vercel.app",
                        expected_model_sha256="a" * 64,
                        expected_commit_sha="c" * 40,
                        opener=opener,
                    )
                self.assertEqual(requests, ["GET"])

    def test_deployment_status_workflow_runs_the_smoke(self):
        workflow = PROJECT_ROOT / ".github" / "workflows" / "post-deploy-smoke.yml"
        self.assertTrue(workflow.is_file(), "post-deploy workflow is missing")
        source = workflow.read_text(encoding="utf-8")
        self.assertIn("deployment_status:", source)
        self.assertIn("github.event.deployment.environment == 'Production'", source)
        self.assertNotIn("github.event.deployment_status.environment ==", source)
        self.assertIn("website/tools/post_deploy_smoke.py", source)
        self.assertIn("github.event.deployment.sha", source)
        self.assertIn("EXPECTED_COMMIT_SHA: ${{ github.event.deployment.sha }}", source)
        self.assertIn('--expected-commit-sha "$EXPECTED_COMMIT_SHA"', source)
        self.assertIn(
            "DEPLOYMENT_URL: https://phishguard-email-analyzer.vercel.app",
            source,
        )
        self.assertNotIn("github.event.deployment_status.environment_url", source)
        self.assertNotIn("github.event.deployment_status.target_url", source)
        self.assertIn("DEPLOYMENT_URL:", source)
        self.assertIn('--base-url "$DEPLOYMENT_URL"', source)
        self.assertIn("--require-sender-history", source)
        self.assertIn("--require-cases", source)
        self.assertIn("--require-jev", source)
        self.assertNotIn(
            '--base-url "${{ github.event.deployment_status.target_url }}"',
            source,
        )


if __name__ == "__main__":
    unittest.main()
