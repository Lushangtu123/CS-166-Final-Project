"""Smoke-test the committed Vercel profile using runtime-only dependencies."""

from __future__ import annotations

import asyncio
from email.message import EmailMessage
import hashlib
import json
import os
from pathlib import Path
import sys


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
