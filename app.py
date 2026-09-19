"""Vercel ASGI entrypoint for PhishGuard."""

from __future__ import annotations

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
WEBSITE_DIR = PROJECT_ROOT / "website"

if str(WEBSITE_DIR) not in sys.path:
    sys.path.insert(0, str(WEBSITE_DIR))

from website.app import app  # noqa: E402,F401
