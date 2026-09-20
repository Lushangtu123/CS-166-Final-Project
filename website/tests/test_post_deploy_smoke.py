import json
from pathlib import Path
import sys
import unittest
from urllib.error import URLError


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
                    "content_model_loaded": True,
                    "content_model_id": "sha256:abc123",
                    "content_model_artifact_sha256": "a" * 64,
                    "sender_history_enabled": True,
                    "sender_history_available": True,
                })
            if request.full_url.endswith("/api/config"):
                return _Response({
                    "verification_mode": "lite",
                    "content_model_enabled": True,
                    "sender_history_enabled": True,
                    "sender_history_available": True,
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
            opener=opener,
            require_sender_history=True,
            history_probe_id="test-probe",
        )

        self.assertEqual(result["risk_level"], "critical")
        self.assertEqual(result["legitimate_risk_level"], "safe")
        self.assertEqual(result["legitimate_control_count"], 2)
        self.assertEqual(result["sender_history_probe"], "previously_seen")
        self.assertEqual(
            [method for _, method, _ in requests],
            ["GET", "GET", "POST", "POST", "POST", "POST", "POST"],
        )
        self.assertTrue(all(timeout == 20 for _, _, timeout in requests))

    def test_smoke_rejects_non_vercel_targets(self):
        self.assertIsNotNone(post_deploy_smoke, "post-deploy smoke module is missing")
        with self.assertRaisesRegex(ValueError, "vercel.app"):
            post_deploy_smoke.validate_deployment(
                "https://internal.example",
                expected_model_sha256="a" * 64,
                opener=lambda *_args, **_kwargs: self.fail("network should not run"),
            )

    def test_smoke_reports_protected_or_non_json_deployments_clearly(self):
        self.assertIsNotNone(post_deploy_smoke, "post-deploy smoke module is missing")

        with self.assertRaisesRegex(RuntimeError, "non-JSON|redirected"):
            post_deploy_smoke.validate_deployment(
                "https://project.vercel.app",
                expected_model_sha256="a" * 64,
                opener=lambda *_args, **_kwargs: _Response(
                    b"<html>Log in to Vercel</html>",
                    content_type="text/html; charset=utf-8",
                    final_url="https://vercel.com/login",
                ),
            )

    def test_deployment_status_workflow_runs_the_smoke(self):
        workflow = PROJECT_ROOT / ".github" / "workflows" / "post-deploy-smoke.yml"
        self.assertTrue(workflow.is_file(), "post-deploy workflow is missing")
        source = workflow.read_text(encoding="utf-8")
        self.assertIn("deployment_status:", source)
        self.assertIn("website/tools/post_deploy_smoke.py", source)
        self.assertIn("github.event.deployment.sha", source)
        self.assertIn(
            "DEPLOYMENT_URL: https://phishguard-email-analyzer.vercel.app",
            source,
        )
        self.assertNotIn("github.event.deployment_status.environment_url", source)
        self.assertNotIn("github.event.deployment_status.target_url", source)
        self.assertIn("DEPLOYMENT_URL:", source)
        self.assertIn('--base-url "$DEPLOYMENT_URL"', source)
        self.assertIn("--require-sender-history", source)
        self.assertNotIn(
            '--base-url "${{ github.event.deployment_status.target_url }}"',
            source,
        )


if __name__ == "__main__":
    unittest.main()
