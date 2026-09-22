"""Smoke-test the committed Vercel profile using runtime-only dependencies."""

from __future__ import annotations

import asyncio
from email.message import EmailMessage
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import Mock, patch


PROJECT_ROOT = Path(__file__).resolve().parents[2]
profile = json.loads((PROJECT_ROOT / "vercel.json").read_text(encoding="utf-8"))
os.environ.update(profile["env"])
sys.path.insert(0, str(PROJECT_ROOT))

artifact_path = PROJECT_ROOT / os.environ["CONTENT_MODEL_ARTIFACT"]
artifact_digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
if artifact_digest != os.environ["CONTENT_MODEL_ARTIFACT_SHA256"]:
    raise SystemExit("Committed Vercel model digest does not match the artifact")

import app as root_entrypoint  # noqa: E402


async def main() -> None:
    backend = sys.modules["website.app"]

    async def check_auxiliary_route():
        # Exercise the real route after importing the root Vercel entrypoint.
        # A private temporary SQLite control verifies reservation + route wiring.
        # Case retrieval and TypeSafe transport remain mocked.
        from case_api import CaseService
        from case_store import CaseStore
        from jev_control import JevControl
        from jev import JevClient
        sys.path.insert(0, str(PROJECT_ROOT / 'website' / 'tests'))
        from test_case_api import request, TOKEN
        case = {'id': 'synthetic', 'version': 1,
                'source': {'subject': 'Test', 'auxiliary_text': 'Visit <https://example.com> data:image/png;base64,c2VjcmV0'},
                'analysis': {'analysis_complete': True}}
        client = JevClient(key='synthetic', enabled=True)
        client.evaluate = Mock(return_value={'status': 'available', 'affects_risk': False})
        service = CaseService(Mock(get=Mock(return_value=case)),
                              {'smoke': hashlib.sha256(TOKEN.encode()).hexdigest()})
        with tempfile.TemporaryDirectory() as directory:
            service.jev_control = JevControl(CaseStore(Path(directory) / 'control.sqlite3'))
            with patch.object(backend.app.state, 'case_service', service), patch('case_api.jev_client', return_value=client):
                status, result, headers = await request('POST', '/api/cases/synthetic/auxiliary',
                                                        payload={'allow_external_processing': True})
                _, repeated, _ = await request('POST', '/api/cases/synthetic/auxiliary',
                                               payload={'allow_external_processing': True})
                assert repeated['reused'] is True
                client.evaluate.assert_called_once()
        assert status == 200 and result['status'] == 'available'
        assert result['affects_risk'] is False and headers[b'cache-control'] == b'no-store'
        prepared = client.evaluate.call_args.kwargs
        assert '<https://example.com>' in prepared['body'] and 'c2VjcmV0' not in prepared['body']

    async def upload_eml(message: EmailMessage) -> dict:
        raw = message.as_bytes()

        async def receive() -> dict:
            return {'type': 'http.request', 'body': raw, 'more_body': False}

        request = backend.Request({
            'type': 'http',
            'headers': [(b'content-type', b'message/rfc822')],
        }, receive)
        return json.loads((await backend.analyze_eml_endpoint(request)).body)

    async with backend.lifespan(root_entrypoint.app):
        await check_auxiliary_route()
        health = json.loads((await backend.health()).body)
        config = json.loads((await backend.get_public_config()).body)
        response = await backend.analyze_content_endpoint(backend.ContentRequest(
            subject="Urgent: verify your account",
            body=(
                "Your account will be suspended. Sign in now at "
                "http://paypa1-secure.example/login"
            ),
        ))
        analysis = json.loads(response.body)
        visual_response = await backend.analyze_visual_endpoint(backend.VisualRequest(observations=[{
            'name': 'synthetic-qr.png', 'mime_type': 'image/png', 'source': 'upload',
            'sha256': 'a' * 64, 'status': 'processed',
            'qr_payloads': ['https://paypa1.example/login'],
        }]))
        visual = json.loads(visual_response.body)
        if visual['risk_level'] not in {'high', 'critical'} or visual['analysis_complete']:
            raise SystemExit('Visual QR evidence was missed or incorrectly marked complete')
        legitimate_controls = []
        for subject, body in (
            (
                "Monthly project update",
                "Attached is the monthly report. Revenue increased and the "
                "team completed the scheduled maintenance.",
            ),
            (
                "Notes from today's planning session",
                "Hello, the meeting notes are attached. We moved the design "
                "review to Thursday and kept the current owners.",
            ),
        ):
            legitimate_response = await backend.analyze_content_endpoint(
                backend.ContentRequest(subject=subject, body=body)
            )
            legitimate_controls.append(json.loads(legitimate_response.body))

        mime_phishing = EmailMessage()
        mime_phishing['Subject'] = 'Urgent: verify your account'
        mime_phishing.set_content(
            'Your account will be suspended. Sign in now at '
            'http://paypa1-secure.example/login'
        )
        mime_phishing.add_alternative(
            '<p>Please review the project notes before our meeting tomorrow.</p>',
            subtype='html',
        )
        mime_phishing_analysis = await upload_eml(mime_phishing)

        mime_uncertain = EmailMessage()
        mime_uncertain['Subject'] = 'Monthly project update'
        mime_uncertain.set_content(
            'Attached is the monthly report. Revenue increased and the '
            'team completed the scheduled maintenance.'
        )
        mime_uncertain.add_alternative(
            '<style>.pad{display:none}</style><p>Routine meeting agenda.</p>',
            subtype='html',
        )
        mime_uncertain_analysis = await upload_eml(mime_uncertain)
        if not health["content_model_loaded"]:
            raise SystemExit(f"Vercel content model did not load: {health['content_model_error']}")
        if analysis["risk_level"] not in {"high", "critical"}:
            raise SystemExit(
                f"Phishing positive control was missed: {analysis['risk_level']}"
            )
        if analysis.get("ml_status") != "available" or analysis.get(
            "ml_prediction"
        ) != 1:
            raise SystemExit("Content model missed the phishing positive control")
        for legitimate in legitimate_controls:
            if legitimate["risk_level"] in {"high", "critical"}:
                raise SystemExit(
                    "Legitimate negative control was flagged: "
                    f"{legitimate['risk_level']}"
                )
            if legitimate.get("ml_status") == "available" and legitimate.get(
                "ml_prediction"
            ) != 0:
                raise SystemExit(
                    "Content model flagged the legitimate negative control"
                )
        if (mime_phishing_analysis['risk_level'] not in {'high', 'critical'}
                or mime_phishing_analysis.get('ml_status') != 'available'
                or mime_phishing_analysis.get('ml_prediction') != 1):
            raise SystemExit('Raw MIME phishing positive control was missed')
        if (mime_uncertain_analysis['risk_level'] != 'unknown'
                or mime_uncertain_analysis['analysis_complete']
                or mime_uncertain_analysis.get('ml_status') != 'available'):
            raise SystemExit('Raw MIME uncertain-rendering control was misclassified')
        print(json.dumps({
            "model_loaded": health["content_model_loaded"],
            "visual_qr_risk_level": visual["risk_level"],
            "model_id": f"sha256:{health['content_model_artifact_sha256'][:12]}",
            "verification_mode": config["verification_mode"],
            "risk_level": analysis["risk_level"],
            "legitimate_risk_levels": [
                item["risk_level"] for item in legitimate_controls
            ],
            "mime_phishing_risk_level": mime_phishing_analysis['risk_level'],
            "mime_phishing_ml_prediction": mime_phishing_analysis['ml_prediction'],
            "mime_uncertain_risk_level": mime_uncertain_analysis['risk_level'],
            "mime_uncertain_ml_status": mime_uncertain_analysis['ml_status'],
            "mime_uncertain_analysis_complete": mime_uncertain_analysis['analysis_complete'],
        }))


if __name__ == "__main__":
    asyncio.run(main())
