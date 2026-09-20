"""Verify a completed Vercel deployment through its public HTTP contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PHISHING_SAMPLE = {
    "subject": "Urgent: verify your Microsoft 365 account",
    "body": (
        "Your mailbox will be closed. Sign in immediately at "
        "https://example.test/login and confirm your password."
    ),
}
LEGITIMATE_SAMPLES = (
    {
        "subject": "Monthly project update",
        "body": (
            "Attached is the monthly report. Revenue increased and the team "
            "completed the scheduled maintenance."
        ),
    },
    {
        "subject": "Notes from today's planning session",
        "body": (
            "Hello, the meeting notes are attached. We moved the design review "
            "to Thursday and kept the current owners."
        ),
    },
)


def _validated_base_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    hostname = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "https"
        or not hostname.endswith(".vercel.app")
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Deployment URL must be an HTTPS host under vercel.app")
    return f"https://{hostname}"


def _request_json(
    request: Request,
    *,
    opener: Callable = urlopen,
) -> dict:
    with opener(request, timeout=20) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"{request.full_url} did not return a JSON object")
    return payload


def validate_deployment(
    base_url: str,
    *,
    expected_model_sha256: str,
    opener: Callable = urlopen,
) -> dict:
    """Check health, public flags, and positive/negative control predictions."""
    base_url = _validated_base_url(base_url)
    health = _request_json(Request(base_url + "/health"), opener=opener)
    if health.get("status") != "ok" or health.get("content_model_loaded") is not True:
        raise RuntimeError(f"Deployment is not model-ready: {health!r}")
    deployed_digest = str(health.get("content_model_artifact_sha256") or "").lower()
    expected_digest = expected_model_sha256.lower()
    if deployed_digest != expected_digest:
        raise RuntimeError(
            "Deployed model does not match this revision: "
            f"expected sha256:{expected_digest}, got sha256:{deployed_digest}"
        )

    config = _request_json(Request(base_url + "/api/config"), opener=opener)
    if config.get("verification_mode") != "lite":
        raise RuntimeError(f"Deployment is not using Lite verification: {config!r}")
    if config.get("content_model_enabled") is not True:
        raise RuntimeError(f"Deployment does not expose content ML: {config!r}")

    analysis = _request_json(Request(
        base_url + "/api/analyze-content",
        data=json.dumps(PHISHING_SAMPLE).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    ), opener=opener)
    if analysis.get("risk_level") not in {"high", "critical"}:
        raise RuntimeError(f"Positive control was not detected: {analysis!r}")
    if analysis.get("ml_prediction") != 1:
        raise RuntimeError(f"Content model missed the positive control: {analysis!r}")

    legitimate_results = []
    for sample in LEGITIMATE_SAMPLES:
        legitimate = _request_json(Request(
            base_url + "/api/analyze-content",
            data=json.dumps(sample).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        ), opener=opener)
        if legitimate.get("risk_level") in {"high", "critical"}:
            raise RuntimeError(
                f"Legitimate negative control was flagged: {legitimate!r}"
            )
        if legitimate.get("ml_status") == "available" and legitimate.get(
            "ml_prediction"
        ) != 0:
            raise RuntimeError(
                "Content model flagged the legitimate negative control: "
                f"{legitimate!r}"
            )
        legitimate_results.append(legitimate)

    return {
        "base_url": base_url,
        "model_id": health["content_model_id"],
        "verification_mode": config["verification_mode"],
        "risk_level": analysis["risk_level"],
        "legitimate_risk_level": legitimate_results[0]["risk_level"],
        "legitimate_control_count": len(legitimate_results),
    }


def _expected_model_sha256() -> str:
    profile = json.loads((PROJECT_ROOT / "vercel.json").read_text(encoding="utf-8"))
    return profile["env"]["CONTENT_MODEL_ARTIFACT_SHA256"]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    args = parser.parse_args()
    result = validate_deployment(
        args.base_url,
        expected_model_sha256=_expected_model_sha256(),
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
