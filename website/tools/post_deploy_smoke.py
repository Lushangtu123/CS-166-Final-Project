"""Verify a completed Vercel deployment through its public HTTP contract."""

from __future__ import annotations

import argparse
from email.message import EmailMessage
import json
from pathlib import Path
import re
import time
from typing import Callable
import uuid
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


def _validated_commit_sha(value: str) -> str:
    if not re.fullmatch(r"[0-9a-fA-F]{40}", value or ""):
        raise ValueError("A full 40-character deployment commit SHA is required")
    return value.lower()


def _request_json(
    request: Request,
    *,
    opener: Callable = urlopen,
) -> dict:
    with opener(request, timeout=20) as response:
        final_url = response.geturl() if hasattr(response, "geturl") else request.full_url
        expected_host = (urlsplit(request.full_url).hostname or "").lower()
        final_host = (urlsplit(final_url).hostname or "").lower()
        if final_host != expected_host:
            raise RuntimeError(
                f"{request.full_url} redirected away from the deployment host "
                f"to {final_host or 'an unknown host'}"
            )
        content_type = str(response.headers.get("Content-Type", "")).lower()
        if not content_type.startswith("application/json"):
            raise RuntimeError(
                f"{request.full_url} returned non-JSON content ({content_type or 'unknown'}); "
                "the deployment may be protected or misrouted"
            )
        raw = response.read()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"{request.full_url} did not return valid UTF-8 JSON"
        ) from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"{request.full_url} did not return a JSON object")
    return payload


def _read_deployment_readiness(
    base_url: str,
    *,
    expected_model_sha256: str,
    expected_commit_sha: str,
    opener: Callable,
    require_sender_history: bool,
) -> tuple[dict, dict]:
    """Perform the retry-safe, read-only portion of deployment validation."""
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
    deployed_commit = str(health.get("commit_sha") or "").lower()
    if deployed_commit != expected_commit_sha:
        raise RuntimeError(
            "Deployment commit does not match this revision: "
            f"expected {expected_commit_sha}, got {deployed_commit[:64] or 'missing'}"
        )

    config = _request_json(Request(base_url + "/api/config"), opener=opener)
    if config.get("verification_mode") != "lite":
        raise RuntimeError(f"Deployment is not using Lite verification: {config!r}")
    if config.get("content_model_enabled") is not True:
        raise RuntimeError(f"Deployment does not expose content ML: {config!r}")
    if require_sender_history:
        for name, payload in (("health", health), ("config", config)):
            if payload.get("sender_history_enabled") is not True:
                raise RuntimeError(f"Sender history is not enabled in {name}: {payload!r}")
            if payload.get("sender_history_configured") is not True:
                raise RuntimeError(f"Sender history is not configured in {name}: {payload!r}")
            if payload.get("sender_history_available") is not True:
                raise RuntimeError(f"Sender history is not available in {name}: {payload!r}")
    return health, config


def _wait_for_deployment_readiness(
    base_url: str,
    *,
    expected_model_sha256: str,
    expected_commit_sha: str,
    opener: Callable,
    require_sender_history: bool,
    attempts: int,
    retry_delay: float,
    sleeper: Callable[[float], None],
) -> tuple[dict, dict]:
    if attempts < 1:
        raise ValueError("readiness_attempts must be at least 1")
    if retry_delay < 0:
        raise ValueError("retry_delay must not be negative")

    for attempt in range(attempts):
        try:
            return _read_deployment_readiness(
                base_url,
                expected_model_sha256=expected_model_sha256,
                expected_commit_sha=expected_commit_sha,
                opener=opener,
                require_sender_history=require_sender_history,
            )
        except Exception:
            if attempt + 1 >= attempts:
                raise
            sleeper(retry_delay)
    raise AssertionError("readiness retry loop exited unexpectedly")


def validate_deployment(
    base_url: str,
    *,
    expected_model_sha256: str,
    expected_commit_sha: str,
    opener: Callable = urlopen,
    require_sender_history: bool = False,
    history_probe_id: str | None = None,
    readiness_attempts: int = 1,
    retry_delay: float = 0,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict:
    """Check health, public flags, and positive/negative control predictions."""
    base_url = _validated_base_url(base_url)
    expected_commit_sha = _validated_commit_sha(expected_commit_sha)
    health, config = _wait_for_deployment_readiness(
        base_url,
        expected_model_sha256=expected_model_sha256,
        expected_commit_sha=expected_commit_sha,
        opener=opener,
        require_sender_history=require_sender_history,
        attempts=readiness_attempts,
        retry_delay=retry_delay,
        sleeper=sleeper,
    )

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

    mime_message = EmailMessage()
    mime_message["Subject"] = "Urgent: verify your account"
    mime_message.set_content(
        "Your account will be suspended. Sign in now at "
        "http://paypa1-secure.example/login"
    )
    mime_message.add_alternative(
        "<p>Please review the project notes before our meeting tomorrow.</p>",
        subtype="html",
    )
    mime_analysis = _request_json(Request(
        base_url + "/api/analyze-eml",
        data=mime_message.as_bytes(),
        headers={"Content-Type": "message/rfc822"},
        method="POST",
    ), opener=opener)
    if (mime_analysis.get("risk_level") not in {"high", "critical"}
            or mime_analysis.get("ml_status") != "available"
            or mime_analysis.get("ml_prediction") != 1):
        raise RuntimeError(f"Raw MIME positive control was missed: {mime_analysis!r}")

    sender_history_probe = "not_checked"
    if require_sender_history:
        probe_id = history_probe_id or uuid.uuid4().hex
        sender = f"post-deploy-smoke-{probe_id}@example.com"

        def observe(sequence: int) -> dict:
            raw_email = (
                f"From: Deployment Smoke <{sender}>\r\n"
                "To: recipient@example.net\r\n"
                "Subject: Sender history deployment check\r\n"
                f"Message-ID: <{probe_id}-{sequence}@example.com>\r\n\r\n"
                "This is a benign automated deployment check."
            )
            return _request_json(Request(
                base_url + "/api/analyze-content",
                data=json.dumps({"raw_email": raw_email}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            ), opener=opener)

        first = observe(1).get("sender_analysis") or {}
        second = observe(2).get("sender_analysis") or {}
        if first.get("sender_history_status") != "first_seen":
            raise RuntimeError(f"Sender-history first observation failed: {first!r}")
        if second.get("sender_history_status") != "previously_seen":
            raise RuntimeError(f"Sender-history repeat observation failed: {second!r}")
        if second.get("sender_history_scope") != "this_service_history":
            raise RuntimeError(f"Sender-history scope is incorrect: {second!r}")
        sender_history_probe = second["sender_history_status"]

    return {
        "base_url": base_url,
        "commit_sha": health["commit_sha"],
        "model_id": health["content_model_id"],
        "verification_mode": config["verification_mode"],
        "risk_level": analysis["risk_level"],
        "legitimate_risk_level": legitimate_results[0]["risk_level"],
        "legitimate_control_count": len(legitimate_results),
        "mime_phishing_risk_level": mime_analysis["risk_level"],
        "sender_history_probe": sender_history_probe,
    }


def _expected_model_sha256() -> str:
    profile = json.loads((PROJECT_ROOT / "vercel.json").read_text(encoding="utf-8"))
    return profile["env"]["CONTENT_MODEL_ARTIFACT_SHA256"]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--expected-commit-sha", required=True)
    parser.add_argument("--require-sender-history", action="store_true")
    parser.add_argument("--readiness-attempts", type=int, default=6)
    parser.add_argument("--retry-delay", type=float, default=5.0)
    args = parser.parse_args()
    result = validate_deployment(
        args.base_url,
        expected_model_sha256=_expected_model_sha256(),
        expected_commit_sha=args.expected_commit_sha,
        require_sender_history=args.require_sender_history,
        readiness_attempts=args.readiness_attempts,
        retry_delay=args.retry_delay,
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
