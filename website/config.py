"""Runtime configuration with safe defaults for public deployments."""

from dataclasses import dataclass
import os
from typing import Mapping


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
    )
    if settings.is_public_service and settings.smtp_verification_enabled:
        raise ValueError(
            "ENABLE_EMAIL_VERIFICATION/full SMTP verification cannot be enabled when "
            "APP_ENV is demo or production; use VERIFICATION_MODE=lite"
        )
    return settings
