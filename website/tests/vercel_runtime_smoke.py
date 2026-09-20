"""Smoke-test the committed Vercel profile using runtime-only dependencies."""

from __future__ import annotations

import asyncio
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
        print(json.dumps({
            "model_loaded": health["content_model_loaded"],
            "model_id": f"sha256:{health['content_model_artifact_sha256'][:12]}",
            "verification_mode": config["verification_mode"],
            "risk_level": analysis["risk_level"],
            "legitimate_risk_levels": [
                item["risk_level"] for item in legitimate_controls
            ],
        }))


if __name__ == "__main__":
    asyncio.run(main())
