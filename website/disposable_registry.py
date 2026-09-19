"""Validated loading for the versioned disposable-domain registry."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
import re


REGISTRY_SCHEMA = "phishguard-disposable-domains-v1"
DEFAULT_REGISTRY_PATH = Path(__file__).parent / "data" / "disposable_domains.json"
REGISTRY_DOMAIN_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)


def normalize_disposable_domain(value: str) -> str:
    """Normalize one registry entry or raise when it is not a domain."""
    if not isinstance(value, str):
        raise ValueError("Disposable-domain registry entries must be strings")
    domain = value.strip().lower().rstrip(".")
    if not REGISTRY_DOMAIN_RE.fullmatch(domain):
        raise ValueError(f"Invalid disposable-domain registry entry: {value!r}")
    return domain


def validate_disposable_registry(payload: object) -> tuple[frozenset[str], dict]:
    """Validate a registry payload before runtime loading or file replacement."""
    if not isinstance(payload, dict) or payload.get("schema") != REGISTRY_SCHEMA:
        raise ValueError("Unsupported disposable-domain registry schema")

    version = payload.get("version")
    if not isinstance(version, str) or not re.fullmatch(r"\d{4}\.\d{2}\.\d{2}", version):
        raise ValueError("Disposable-domain registry version must use YYYY.MM.DD")
    try:
        datetime.strptime(version, "%Y.%m.%d")
    except ValueError as exc:
        raise ValueError("Disposable-domain registry version is not a valid date") from exc

    provenance = payload.get("provenance")
    if not isinstance(provenance, str) or not provenance.strip():
        raise ValueError("Disposable-domain registry provenance must be a non-empty string")

    domains = payload.get("domains")
    if not isinstance(domains, list) or not domains:
        raise ValueError("Disposable-domain registry must contain a non-empty domain list")
    if domains != sorted(set(domains)):
        raise ValueError("Disposable-domain registry must be sorted and duplicate-free")
    if any(normalize_disposable_domain(domain) != domain for domain in domains):
        raise ValueError("Disposable-domain registry contains a non-normalized domain")

    domain_count = payload.get("domain_count")
    if type(domain_count) is not int or domain_count != len(domains):
        raise ValueError("Disposable-domain registry count does not match its contents")

    metadata = {key: value for key, value in payload.items() if key != "domains"}
    return frozenset(domains), metadata


def load_disposable_registry(
    path: Path | str = DEFAULT_REGISTRY_PATH,
) -> tuple[frozenset[str], dict]:
    """Load a normalized, duplicate-free registry and its provenance metadata."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return validate_disposable_registry(payload)
