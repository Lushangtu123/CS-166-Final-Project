"""Build the checked-in disposable-domain registry from offline line files."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

WEBSITE_DIR = Path(__file__).resolve().parents[1]
if str(WEBSITE_DIR) not in sys.path:
    sys.path.insert(0, str(WEBSITE_DIR))

from disposable_registry import (
    REGISTRY_SCHEMA,
    normalize_disposable_domain,
    validate_disposable_registry,
)


def build_registry(
    input_paths: list[Path],
    *,
    version: str,
    provenance: str,
) -> dict:
    domains: set[str] = set()
    for path in input_paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            value = line.split("#", 1)[0].strip()
            if value:
                domains.add(normalize_disposable_domain(value))
    ordered = sorted(domains)
    payload = {
        "schema": REGISTRY_SCHEMA,
        "version": version,
        "domain_count": len(ordered),
        "provenance": provenance,
        "domains": ordered,
    }
    validate_disposable_registry(payload)
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--provenance", required=True)
    args = parser.parse_args()
    payload = build_registry(
        args.input,
        version=args.version,
        provenance=args.provenance,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=args.output.parent,
            prefix=f".{args.output.name}.",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            json.dump(payload, temporary, indent=2, ensure_ascii=True)
            temporary.write("\n")
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, args.output)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


if __name__ == "__main__":
    main()
