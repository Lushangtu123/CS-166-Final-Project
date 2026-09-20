"""Runtime configuration with safe defaults for public deployments."""

from dataclasses import dataclass, field
import os
from typing import Mapping
from urllib.parse import urlsplit


TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off"}
VALID_ENVIRONMENTS = {"development", "demo", "production", "test"}
VALID_VERIFICATION_MODES = {"off", "lite", "full"}


def _parse_bool(environ: Mapping[str, str], name: str, default: bool = False) -> bool:
    raw = environ.get(name)
    if raw is None:
        return default

    value = raw.strip().lower()
    if value in TRUE_VALUES:
        return True
    if value in FALSE_VALUES:
        return False
    accepted = ", ".join(sorted(TRUE_VALUES | FALSE_VALUES))
    raise ValueError(f"{name} must be one of: {accepted}")


@dataclass(frozen=True)
class Settings:
    app_env: str
    enable_email_verification: bool
    content_model_enabled: bool = False
    trusted_authserv_ids: frozenset[str] = frozenset()
    content_model_artifact: str | None = None
    content_model_artifact_sha256: str | None = None
    verification_mode: str | None = None
    sender_history_enabled: bool = False
    sender_history_rest_url: str | None = None
    sender_history_rest_token: str | None = field(default=None, repr=False)
    sender_history_hmac_key: str | None = field(default=None, repr=False)
    sender_history_retention_days: int = 90
    sender_history_timeout_seconds: float = 1.0
    sender_history_config_error: str | None = None

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def is_public_service(self) -> bool:
        return self.app_env in {"demo", "production"}

    @property
    def effective_verification_mode(self) -> str:
        if self.verification_mode is not None:
            return self.verification_mode
        return "full" if self.enable_email_verification else "off"

    @property
    def domain_verification_enabled(self) -> bool:
        return self.effective_verification_mode in {"lite", "full"}

    @property
    def smtp_verification_enabled(self) -> bool:
        return self.effective_verification_mode == "full"

    @property
    def sender_history_ready(self) -> bool:
        return bool(
            self.sender_history_enabled
            and self.sender_history_config_error is None
            and self.sender_history_rest_url
            and self.sender_history_rest_token
            and self.sender_history_hmac_key
        )


def _sender_history_configuration(source: Mapping[str, str]) -> dict:
    values = {
        "sender_history_enabled": False,
        "sender_history_rest_url": None,
        "sender_history_rest_token": None,
        "sender_history_hmac_key": None,
        "sender_history_retention_days": 90,
        "sender_history_timeout_seconds": 1.0,
        "sender_history_config_error": None,
    }
    try:
        enabled = _parse_bool(source, "SENDER_HISTORY_ENABLED", False)
    except ValueError:
        values["sender_history_config_error"] = (
            "Sender history configuration is invalid."
        )
        return values
    values["sender_history_enabled"] = enabled
    if not enabled:
        return values

    url = source.get("UPSTASH_REDIS_REST_URL", "").strip().rstrip("/")
    token = source.get("UPSTASH_REDIS_REST_TOKEN", "").strip()
    hmac_key = source.get("SENDER_HISTORY_HMAC_KEY", "")
    error = None

    try:
        retention_days = int(source.get("SENDER_HISTORY_RETENTION_DAYS", "90"))
        timeout_seconds = float(source.get("SENDER_HISTORY_TIMEOUT_SECONDS", "1.0"))
    except ValueError:
        retention_days = 90
        timeout_seconds = 1.0
        error = "Sender history configuration is invalid."

    try:
        parsed = urlsplit(url)
        valid_url = bool(
            parsed.scheme == "https"
            and parsed.hostname
            and parsed.hostname.lower().endswith(".upstash.io")
            and parsed.username is None
            and parsed.password is None
            and parsed.port in (None, 443)
            and parsed.path in ("", "/")
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        valid_url = False
    if not url or not token or not hmac_key:
        error = "Sender history configuration is incomplete."
    elif not valid_url or len(hmac_key.encode("utf-8")) < 32:
        error = "Sender history configuration is invalid."
    elif not 1 <= retention_days <= 365 or not 0.1 <= timeout_seconds <= 3.0:
        error = "Sender history configuration is outside the allowed bounds."

    values.update({
        "sender_history_rest_url": url or None,
        "sender_history_rest_token": token or None,
        "sender_history_hmac_key": hmac_key or None,
        "sender_history_retention_days": retention_days,
        "sender_history_timeout_seconds": timeout_seconds,
        "sender_history_config_error": error,
    })
    return values


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    source = os.environ if environ is None else environ
    app_env = source.get("APP_ENV", "production").strip().lower()
    if app_env not in VALID_ENVIRONMENTS:
        accepted = ", ".join(sorted(VALID_ENVIRONMENTS))
        raise ValueError(f"APP_ENV must be one of: {accepted}")

    legacy_verification = _parse_bool(source, "ENABLE_EMAIL_VERIFICATION")
    domain_verification = _parse_bool(source, "ENABLE_DOMAIN_VERIFICATION")
    smtp_verification = _parse_bool(source, "ENABLE_SMTP_VERIFICATION")
    verification_mode = source.get("VERIFICATION_MODE", "").strip().lower()
    if verification_mode:
        if verification_mode not in VALID_VERIFICATION_MODES:
            accepted = ", ".join(sorted(VALID_VERIFICATION_MODES))
            raise ValueError(f"VERIFICATION_MODE must be one of: {accepted}")
    elif legacy_verification or smtp_verification:
        verification_mode = "full"
    elif domain_verification:
        verification_mode = "lite"
    else:
        verification_mode = "off"

    sender_history = _sender_history_configuration(source)
    settings = Settings(
        app_env=app_env,
        enable_email_verification=verification_mode != "off",
        content_model_enabled=_parse_bool(source, "CONTENT_MODEL_ENABLED", False),
        trusted_authserv_ids=frozenset(
            item.strip().lower()
            for item in source.get("TRUSTED_AUTHSERV_IDS", "").split(",")
            if item.strip()
        ),
        content_model_artifact=(source.get("CONTENT_MODEL_ARTIFACT", "").strip() or None),
        content_model_artifact_sha256=(
            source.get("CONTENT_MODEL_ARTIFACT_SHA256", "").strip().lower() or None
        ),
        verification_mode=verification_mode,
        **sender_history,
    )
    if settings.is_public_service and settings.smtp_verification_enabled:
        raise ValueError(
            "ENABLE_EMAIL_VERIFICATION/full SMTP verification cannot be enabled when "
            "APP_ENV is demo or production; use VERIFICATION_MODE=lite"
        )
    return settings
