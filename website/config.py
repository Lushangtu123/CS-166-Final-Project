"""Runtime configuration with safe defaults for public deployments."""

from dataclasses import dataclass
import os
from typing import Mapping


TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off"}
VALID_ENVIRONMENTS = {"development", "production", "test"}


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
    allow_synthetic_data: bool

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    source = os.environ if environ is None else environ
    app_env = source.get("APP_ENV", "production").strip().lower()
    if app_env not in VALID_ENVIRONMENTS:
        accepted = ", ".join(sorted(VALID_ENVIRONMENTS))
        raise ValueError(f"APP_ENV must be one of: {accepted}")

    settings = Settings(
        app_env=app_env,
        enable_email_verification=_parse_bool(source, "ENABLE_EMAIL_VERIFICATION"),
        allow_synthetic_data=_parse_bool(source, "ALLOW_SYNTHETIC_DATA"),
    )
    if settings.is_production and settings.allow_synthetic_data:
        raise ValueError("ALLOW_SYNTHETIC_DATA cannot be enabled when APP_ENV=production")
    if settings.is_production and settings.enable_email_verification:
        raise ValueError("ENABLE_EMAIL_VERIFICATION cannot be enabled when APP_ENV=production")
    return settings
