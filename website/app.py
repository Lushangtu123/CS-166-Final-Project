"""
app.py – FastAPI backend for the Phishing Email Detector demo.

Sender addresses use explainable domain heuristics. Full messages additionally
use RFC 5322 structure/authentication signals and, when enabled, a separately
validated offline email-text classifier. Historical UCI website-model metrics
remain available only as a clearly scoped course benchmark.
Routes:
  GET  /                      → serve index.html
  GET  /api/metrics           → classifier performance metrics
  GET  /api/features          → feature metadata
  GET  /api/config            → public-safe feature configuration
  POST /api/analyze-email     → explainable sender/domain risk analysis
  POST /api/analyze-content   → message structure + content analysis
  POST /api/analyze-eml       → byte-preserving MIME upload analysis
"""

from __future__ import annotations

import os
import json
import hashlib
import ipaddress
import re
import math
import socket
import smtplib
import threading
import time
import unicodedata
import warnings
import tldextract
from collections import deque
from email.utils import getaddresses
from html.parser import HTMLParser
from html import escape as escape_html, unescape as unescape_html
from itertools import product
from urllib.parse import unquote, urlparse, urljoin

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field
from contextlib import asynccontextmanager
from config import load_settings
from case_api import build_case_service, make_case_router, public_jev_status
from feedback_api import make_feedback_router
from disposable_registry import REGISTRY_DOMAIN_RE as _REGISTRY_DOMAIN_RE
from disposable_registry import load_disposable_registry, load_privacy_relay_registry
from request_limits import RequestBodyLimitMiddleware
from visual_evidence import (VisualRequest, VISUAL_PATHS, MAX_VISUAL_REQUEST_BYTES,
                             bound_message_text, merge_visual_findings)
from language_coverage import (has_substantial_han_text as _has_substantial_han_text,
                               non_latin_script_segments)
from sender_history import (
    DisabledSenderHistoryStore,
    SenderHistoryResult,
    build_sender_history_store,
    canonicalize_sender_address,
    supports_plus_alias,
    uses_gmail_dot_aliasing,
)
from starlette.middleware.trustedhost import TrustedHostMiddleware

BASE_DIR = Path(__file__).parent
SETTINGS = load_settings()


def load_content_pipeline_artifact(path: Path, expected_sha256: str) -> dict:
    """Load the optional scientific stack only when ML is enabled."""
    from content_inference import load_content_pipeline_artifact as loader

    return loader(path, expected_sha256)


def predict_content(pipeline: dict, subject: str, body: str, *, canonical_text: bool = False) -> dict:
    """Run optional inference without importing training dependencies."""
    from content_inference import predict_content as predictor

    return predictor(pipeline, subject, body, canonical_text=canonical_text)


from email_structure import (
    _PROTECTED_BRAND_DOMAINS,
    _confusable_skeleton,
    _decode_idna_domain,
    _domains_align,
    analyze_raw_email,
    normalize_domain,
)

RATE_LIMIT_PER_MINUTE = max(1, int(os.getenv("RATE_LIMIT_PER_MINUTE", "20")))
RATE_LIMIT_BUCKET_CAPACITY = max(128, int(os.getenv("RATE_LIMIT_BUCKET_CAPACITY", "4096")))
MAX_REQUEST_BYTES = max(1024, int(os.getenv("MAX_REQUEST_BYTES", "65536")))

# ── Feature definitions (UCI Phishing Websites Dataset mapping) ───────────────
FEATURE_INFO = [
    {"name": "having_ip_address",
     "label": "IP Address Domain",        "group": "URL-based",
     "email_desc":     "Domain is a raw IP address instead of a proper hostname — highly suspicious",
     "email_desc_pos": "Domain uses a proper hostname, not a raw IP address"},
    {"name": "url_length",
     "label": "Address Length",           "group": "URL-based",
     "email_desc":     "Total email address is abnormally long — phishing addresses are often padded",
     "email_desc_pos": "Email address length is within normal limits"},
    {"name": "shortining_service",
     "label": "URL Shortener Domain",     "group": "URL-based",
     "email_desc":     "Domain belongs to a known URL shortening service — frequently abused in phishing",
     "email_desc_pos": "Domain is not a URL shortening service"},
    {"name": "having_at_symbol",
     "label": "Multiple @ Symbols",       "group": "URL-based",
     "email_desc":     "Address contains more than one @ symbol — invalid / malformed email",
     "email_desc_pos": "Address has exactly one @ symbol — correct format"},
    {"name": "double_slash_redirecting",
     "label": "Double Slash in Domain",   "group": "URL-based",
     "email_desc":     "Domain contains '//' — possible redirect deception trick",
     "email_desc_pos": "No double-slash redirect found in the domain"},
    {"name": "prefix_suffix",
     "label": "Hyphen in Domain",         "group": "URL-based",
     "email_desc":     "Base domain contains a hyphen — legitimate providers rarely use hyphens",
     "email_desc_pos": "Domain has no hyphens — consistent with legitimate mail providers"},
    {"name": "having_sub_domain",
     "label": "Subdomain Depth",          "group": "URL-based",
     "email_desc":     "Domain has multiple subdomain levels — phishing sites use deep subdomains to impersonate brands",
     "email_desc_pos": "Domain has normal subdomain depth (0–1 level)"},
    {"name": "https_token",
     "label": "'http' Token in Address",  "group": "URL-based",
     "email_desc":     "The string 'http' appears inside the email address — a visual confusion trick",
     "email_desc_pos": "No misleading 'http' token found in the address"},
    {"name": "sslfinal_state",
     "label": "Recognized Provider / Domain", "group": "Domain-based",
     "email_desc":     "Domain does not match the local provider or institutional-domain rules",
     "email_desc_pos": "Domain matches a provider registry or institutional-domain rule; this does not authenticate the sender"},
    {"name": "domain_registration_length",
     "label": "Recognized Public Suffix",  "group": "Domain-based",
     "email_desc":     "Domain suffix is not recognized by the bundled Public Suffix List",
     "email_desc_pos": "Domain suffix is recognized; this alone does not establish reputation"},
    {"name": "age_of_domain",
     "label": "Domain Label Length",      "group": "Domain-based",
     "email_desc":     "Domain label is abnormally long — may be disguising a legitimate domain name",
     "email_desc_pos": "Domain label length is within normal range"},
    {"name": "dnsrecord",
     "label": "Digits in Domain",         "group": "Domain-based",
     "email_desc":     "Domain name contains embedded digits — legitimate brand domains are usually letters only",
     "email_desc_pos": "Domain name contains no suspicious digit patterns"},
    {"name": "web_traffic",
     "label": "High-Traffic Mail Platform","group": "Domain-based",
     "email_desc":     "Domain is not in the high-traffic provider registry; this alone does not establish malicious intent",
     "email_desc_pos": "Domain matches a high-traffic provider or privacy relay; this does not authenticate the sender"},
    {"name": "page_rank",
     "label": "Phishing Keywords in Domain","group": "Domain-based",
     "email_desc":     "Domain part contains known phishing-related keywords",
     "email_desc_pos": "No phishing keywords detected in the domain"},
    {"name": "google_index",
     "label": "Phishing Keywords in Local","group": "Domain-based",
     "email_desc":     "Username (local part) contains known phishing-related keywords",
     "email_desc_pos": "No phishing keywords detected in the username"},
    {"name": "statistical_report",
     "label": "Suspicious TLD",           "group": "Domain-based",
     "email_desc":     "TLD is a known high-risk or free domain extension heavily used in phishing",
     "email_desc_pos": "TLD is not associated with high-risk or free domain registrations"},
    {"name": "favicon",
     "label": "High Digit Ratio in Local","group": "HTML/Content-based",
     "email_desc":     "Username has an unusually high proportion of digits",
     "email_desc_pos": "Username digit ratio is within normal limits"},
    {"name": "port",
     "label": "Username Randomness",      "group": "HTML/Content-based",
     "email_desc":     "Username has high Shannon entropy — likely randomly auto-generated",
     "email_desc_pos": "Username entropy is normal — does not appear randomly generated"},
    {"name": "request_url",
     "label": "Special Chars in Local",   "group": "HTML/Content-based",
     "email_desc":     "Username contains non-standard special characters",
     "email_desc_pos": "Username uses only standard alphanumeric characters"},
    {"name": "url_of_anchor",
     "label": "Username Length",          "group": "HTML/Content-based",
     "email_desc":     "Username exceeds 30 characters — abnormally long",
     "email_desc_pos": "Username length is within normal range (≤ 30 characters)"},
    {"name": "links_in_tags",
     "label": "Brand Domain Spoofing",    "group": "HTML/Content-based",
     "email_desc":     "Domain appears to impersonate a well-known brand (e.g. paypal, apple)",
     "email_desc_pos": "No brand domain spoofing detected"},
    {"name": "sfh",
     "label": "noreply Address",          "group": "HTML/Content-based",
     "email_desc":     "Sender is a noreply / no-reply / donotreply address — cannot receive replies",
     "email_desc_pos": "Normal sender address — not a noreply / donotreply"},
    {"name": "submitting_to_email",
     "label": "Repeated Characters",      "group": "HTML/Content-based",
     "email_desc":     "Username contains heavily repeated characters — possibly auto-generated",
     "email_desc_pos": "Username has no abnormal character repetition"},
    {"name": "abnormal_url",
     "label": "Digit-Letter Mix in Domain","group": "HTML/Content-based",
     "email_desc":     "Domain mixes digits and letters suspiciously (e.g. paypa1, g00gle)",
     "email_desc_pos": "No suspicious digit-letter mixing detected in the domain"},
    {"name": "redirect",
     "label": "Redirect Detection",       "group": "HTML/Content-based",
     "email_desc":     "Potential network-layer redirect detected",
     "email_desc_pos": "No network-layer redirect detected"},
    {"name": "on_mouseover",
     "label": "Abused Country-Code TLD",  "group": "HTML/Content-based",
     "email_desc":     "TLD is a country code commonly abused in phishing attacks",
     "email_desc_pos": "TLD is not a commonly abused country-code domain"},
    {"name": "rightclick",
     "label": "Auto-Generated Username",  "group": "HTML/Content-based",
     "email_desc":     "Username matches common auto-generated patterns (short prefix + digits)",
     "email_desc_pos": "Username does not match typical auto-generated patterns"},
    {"name": "popupwindow",
     "label": "Domain Word Segments",     "group": "HTML/Content-based",
     "email_desc":     "Domain label contains too many word segments — suspicious construction",
     "email_desc_pos": "Domain label word structure is normal"},
    {"name": "iframe",
     "label": "Composite Risk Score",     "group": "HTML/Content-based",
     "email_desc":     "Multiple risk factors detected — composite score indicates elevated phishing risk",
     "email_desc_pos": "Composite risk score is low — few phishing indicators present"},
    {"name": "links_pointing_to_page",
     "label": "Valid Email Format",       "group": "HTML/Content-based",
     "email_desc":     "Email address fails RFC format validation — potentially invalid or malformed",
     "email_desc_pos": "Email address passes standard RFC format validation"},
]

FEATURE_NAMES = [f["name"] for f in FEATURE_INFO]

# ── Known domains ─────────────────────────────────────────────────────────────
LEGIT_PROVIDERS = {
     # Email providers
    'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com',
    'aol.com', 'protonmail.com', 'zoho.com', 'mail.com', 'yandex.com',
    'live.com', 'msn.com', 'me.com', 'apple.com', 'google.com',
    'microsoft.com', 'amazon.com', 'qq.com', '163.com', '126.com',
    'sina.com', 'sohu.com', 'foxmail.com',
    # Big tech companies
    'paypal.com', 'netflix.com', 'facebook.com', 'twitter.com',
    'instagram.com', 'linkedin.com', 'github.com', 'adobe.com',
    'dropbox.com', 'spotify.com', 'uber.com', 'airbnb.com',
    'salesforce.com', 'slack.com', 'zoom.us', 'stripe.com',
    # Banks
    'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com',
    'capitalone.com', 'americanexpress.com', 'discover.com',
    # Shipping
    'fedex.com', 'ups.com', 'dhl.com', 'usps.com',
    # Education
    'stanford.edu', 'mit.edu', 'harvard.edu', 'berkeley.edu',
}
HIGH_TRAFFIC = {
     'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
    'icloud.com', 'protonmail.com', 'live.com', 'qq.com', '163.com',
    'paypal.com', 'netflix.com', 'microsoft.com', 'apple.com',
    'google.com', 'amazon.com', 'facebook.com', 'linkedin.com',
    'github.com', 'spotify.com', 'chase.com', 'bankofamerica.com',
}
MAJOR_MAILBOX_PROVIDERS = {
    'gmail.com', 'googlemail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
    'icloud.com', 'mac.com', 'aol.com', 'proton.me', 'protonmail.com',
    'zoho.com', 'mail.com', 'yandex.com', 'live.com', 'msn.com', 'me.com',
    'qq.com', '163.com', '126.com', 'sina.com', 'sohu.com', 'foxmail.com',
}
HOMOGLYPH_MAP = {
    '0': 'o',   # amaz0n → amazon
    '1': 'l',   # paypa1 → paypal, app1e → apple
    '3': 'e',   # n3tflix → netflix
    '4': 'a',   # p4ypal → paypal
    '5': 's',   # micro5oft → microsoft
    '6': 'g',   # 6oogle → google
    '8': 'b',   # 8ank → bank
    '@': 'a',   # p@ypal → paypal
    'vv': 'w',  # vvindows → windows
    'rn': 'm',  # rnicro → micro
    'nn': 'm',  # nnicrosoft → microsoft
    'ii': 'u',  # giithub → github (rare)
    'cl': 'd',  # clomain → domain (rare)
}
SUSPICIOUS_KEYWORDS = [
    'verify', 'verification', 'secure', 'security', 'bank', 'account',
    'update', 'confirm', 'login', 'signin', 'password', 'credential',
    'ebay', 'service', 'admin', 'official', 'alert', 'notice',
    'suspended', 'blocked', 'urgent', 'important', 'limited', 'claim',
    'prize', 'winner', 'free', 'bonus', 'reward',
    # Extended: action / account management keywords
    'recover', 'recovery', 'restore', 'reactivate', 'unlock', 'validate',
    'authenticate', 'protect', 'notification', 'warning', 'billing',
    'invoice', 'refund', 'payment', 'subscri', 'renew', 'expir',
    # Extended: financial / crypto
    'crypto', 'bitcoin', 'wallet', 'token', 'trading', 'invest',
    # Extended: impersonation signals in domain/username
    'no-reply', 'donotreply', 'postmaster', 'mailer',
    'webmaster', 'hostmaster', 'abuse',
]

BRAND_DOMAINS = {
    # Consumer tech / social
    'paypal', 'google', 'microsoft', 'amazon', 'apple', 'netflix',
    'facebook', 'twitter', 'instagram', 'linkedin', 'ebay', 'alibaba',
    'dropbox', 'adobe', 'docusign', 'salesforce', 'stripe', 'shopify',
    # Banks & financial
    'chase', 'citibank', 'wellsfargo', 'bankofamerica', 'barclays',
    'hsbc', 'santander', 'natwest', 'lloyds', 'capitalone', 'usbank',
    'schwab', 'fidelity', 'vanguard', 'robinhood',
    # Crypto
    'coinbase', 'binance', 'kraken', 'metamask',
    # Government / regulatory (non-.gov impersonation)
    'irs', 'fbi', 'dhs', 'interpol', 'europol',
    # Logistics
    'fedex', 'ups', 'dhl', 'usps',
}

# Financial-sector keywords commonly embedded in phishing domain labels
FINANCIAL_DOMAIN_KEYWORDS = {
    'bank', 'banking', 'banc', 'credit', 'debit', 'loan', 'mortgage',
    'invest', 'investment', 'capital', 'fund', 'finance', 'financial',
    'wealth', 'trading', 'forex', 'crypto', 'bitcoin', 'blockchain',
    'insurance', 'ins', 'assurance', 'revenue', 'treasury', 'fiscal',
    'pension', 'savings', 'wallet', 'transfer', 'remit', 'clearing',
    'brokerage', 'exchange', 'escrow', 'leasing', 'billing', 'refund',
    'invoice', 'payroll', 'accounting', 'audit', 'taxserv', 'taxrefund',
    # Government/regulatory impersonation
    'federal', 'national', 'official', 'government', 'regulatory',
    'authority', 'ministry', 'bureau',
}

# Business entity suffixes that scammers append to fake-brand abbreviations
BUSINESS_SUFFIX_KEYWORDS = {
    'group', 'corp', 'corporation', 'inc', 'incorporated', 'ltd', 'limited',
    'llc', 'plc', 'holdings', 'holding', 'management', 'enterprise', 'enterprises',
    'solutions', 'service', 'services', 'associates', 'association',
    'partners', 'partnership', 'international', 'global',
    'agency', 'institute', 'trust', 'ventures', 'systems', 'technologies',
    'administration', 'department', 'commission', 'organisation', 'organization',
    'centre', 'center', 'network', 'networks', 'alliance', 'union',
    'foundation', 'consultants', 'consulting', 'advisory',
}
SPAM_TLDS = {'xyz', 'top', 'click', 'loan', 'win', 'gq', 'tk', 'ml', 'cf', 'ga', 'pw', 'cc'}
COMMON_TLDS = {'com', 'org', 'net', 'edu', 'gov', 'mil', 'io', 'co', 'cn'}
ABUSED_CCTLDS = {'ru', 'cn', 'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'xyz'}
SHORT_SERVICES = {'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'short.io'}

# ── Versioned disposable / temporary email domain registry ────────────────────
_DISPOSABLE_DOMAIN_SOURCE, DISPOSABLE_REGISTRY_METADATA = load_disposable_registry()
PRIVACY_RELAY_DOMAINS, PRIVACY_RELAY_REGISTRY_METADATA = load_privacy_relay_registry()
DISPOSABLE_DOMAINS = _DISPOSABLE_DOMAIN_SOURCE - PRIVACY_RELAY_DOMAINS

# Always use tldextract's bundled Public Suffix List snapshot. Runtime sender
# analysis must remain deterministic and must never perform a network refresh.
_DOMAIN_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_DISPOSABLE_DOMAIN_PATTERNS = tuple(re.compile(pattern) for pattern in (
    r"^(?:temp|temporary)-?(?:mail|email|inbox|box)\d*$",
    r"^(?:trash|discard|throwaway|burner)-?(?:mail|email|inbox|box)\d*$",
    r"^(?:mail)-?(?:temp|trash|drop)\d*$",
    r"^(?:fake)-?(?:mail|email|inbox)\d*$",
    r"^(?:10|20|30|60)(?:minute|min)-?mail(?:box)?\d*$",
))


def _match_domain_registry(domain: str, candidates) -> str | None:
    """Return the most specific exact or subdomain-boundary registry match."""
    normalized = (domain or "").strip().lower().rstrip(".")
    matches = [
        candidate
        for candidate in candidates
        if normalized == candidate or normalized.endswith("." + candidate)
    ]
    return max(matches, key=len, default=None)


def _matches_disposable_domain_pattern(domain: str) -> bool:
    labels = (domain or "").strip().lower().rstrip(".").split(".")
    return any(
        pattern.fullmatch(label)
        for label in labels
        for pattern in _DISPOSABLE_DOMAIN_PATTERNS
    )

# ── Pre-computed model metrics ────────────────────────────────────────────────
MODEL_METRICS = {
    "Random Forest":      {"Accuracy": 0.9747, "Precision": 0.9748, "Recall": 0.9747, "F1": 0.9746, "ROC_AUC": 0.9977},
    "SVM (RBF)":          {"Accuracy": 0.9516, "Precision": 0.9520, "Recall": 0.9516, "F1": 0.9515, "ROC_AUC": 0.9893},
    "Decision Tree":      {"Accuracy": 0.9480, "Precision": 0.9481, "Recall": 0.9480, "F1": 0.9480, "ROC_AUC": 0.9865},
    "Logistic Regression":{"Accuracy": 0.9285, "Precision": 0.9287, "Recall": 0.9285, "F1": 0.9284, "ROC_AUC": 0.9808},
}

# ── Global optional model state ───────────────────────────────────────────────
_content_model_error: str | None = None
_content_model_artifact_sha256: str | None = None

def normalize_homoglyphs(text: str) -> str:
    """Convert typosquatting characters back to normal letters."""
    result = text.lower()
    # Multi-char substitutions first
    result = result.replace('vv', 'w')
    result = result.replace('rn', 'm')
    result = result.replace('nn', 'm')
    result = result.replace('cl', 'd')
    # Single char substitutions
    result = result.replace('0', 'o')
    result = result.replace('1', 'l')
    result = result.replace('3', 'e')
    result = result.replace('4', 'a')
    result = result.replace('5', 's')
    result = result.replace('6', 'g')
    result = result.replace('8', 'b')
    result = result.replace('@', 'a')
    return result


# Optional email-content text classifier (TF-IDF + selected linear model).
# Populated at startup only from a verified offline artifact.
_content_pipeline: dict | None = None
_sender_history_store = DisabledSenderHistoryStore()

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((f / len(s)) * math.log2(f / len(s)) for f in freq.values())


def extract_email_features(email: str) -> tuple[dict, list, bool, bool, str | None, dict]:
    """
    Extract 30 phishing-indicator features from an email address.
    Returns feature data plus the compatible booleans and detailed disposable classification.
    Each feature value ∈ {-1 (phishing), 0 (suspicious), 1 (legitimate)}.
    """
    email = email.strip().lower()
    risk_indicators = []

    # Parse local part and domain
    at_count = email.count('@')
    if at_count == 0:
        raw_local, domain = email, ''
    else:
        parts = email.split('@')
        raw_local = parts[0]
        domain = parts[-1]

    base_local, plus_separator, alias_tag = raw_local.partition("+")
    is_subaddress = bool(
        supports_plus_alias(domain)
        and plus_separator
        and base_local
        and alias_tag
        and re.fullmatch(r"[a-z0-9._%+\-]+", alias_tag)
    )
    address_alias_type = "subaddress" if is_subaddress else None
    tag_stripped_local = base_local if is_subaddress else raw_local
    local = tag_stripped_local
    if uses_gmail_dot_aliasing(domain):
        local = local.replace(".", "")
    scoring_local = local if uses_gmail_dot_aliasing(domain) else tag_stripped_local
    scoring_email = (
        f"{scoring_local}@{domain}"
        if at_count == 1
        else email
    )

    # Check for IP address domain before splitting
    is_ip_domain = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain))
    public_suffix = ""
    if is_ip_domain:
        domain_parts = [domain]
        tld = ''
        base_domain = domain
        domain_label = domain
        subdomain_count = 0
    else:
        domain_parts = domain.split('.') if domain else ['']
        extracted_domain = _DOMAIN_EXTRACTOR(domain)
        public_suffix = extracted_domain.suffix
        tld = public_suffix.rsplit('.', 1)[-1] if public_suffix else domain_parts[-1]
        if extracted_domain.domain and public_suffix:
            base_domain = extracted_domain.top_domain_under_public_suffix
            domain_label = extracted_domain.domain
            subdomain_count = len([
                label for label in extracted_domain.subdomain.split('.') if label
            ])
        else:
            base_domain = '.'.join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain
            domain_label = domain_parts[-2] if len(domain_parts) >= 2 else domain
            subdomain_count = max(0, len(domain_parts) - 2)

    matched_disposable_domain = _match_domain_registry(domain, DISPOSABLE_DOMAINS)
    matched_privacy_relay = _match_domain_registry(domain, PRIVACY_RELAY_DOMAINS)
    matched_legit_provider = _match_domain_registry(domain, LEGIT_PROVIDERS)
    matched_high_traffic = _match_domain_registry(domain, HIGH_TRAFFIC)
    matched_mail_service = matched_disposable_domain or matched_privacy_relay

    features = {}

    # 1. having_ip_address
    is_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain))
    features['having_ip_address'] = -1 if is_ip else 1
    if is_ip:
        risk_indicators.append({"level": "high", "msg": f"Domain is a raw IP address ({domain}) instead of a hostname"})

    # 2. url_length
    total_len = len(scoring_email)
    features['url_length'] = -1 if total_len > 50 else (0 if total_len > 30 else 1)
    if total_len > 50:
        risk_indicators.append({"level": "medium", "msg": f"Email address is unusually long ({total_len} chars) — typical addresses are under 50 characters"})

    # 3. shortining_service
    features['shortining_service'] = -1 if base_domain in SHORT_SERVICES else 1
    if base_domain in SHORT_SERVICES:
        risk_indicators.append({"level": "high", "msg": f"Domain ({base_domain}) is a known URL shortening service frequently abused in phishing"})

    # 4. having_at_symbol
    features['having_at_symbol'] = -1 if at_count > 1 else 1
    if at_count > 1:
        risk_indicators.append({"level": "high", "msg": f"Address contains {at_count} @ symbols — invalid email format"})

    # 5. double_slash_redirecting
    features['double_slash_redirecting'] = -1 if '//' in domain else 1
    if '//' in domain:
        risk_indicators.append({"level": "high", "msg": "Domain contains '//' — possible redirect deception trick"})

    # 6. prefix_suffix (hyphen in base domain)
    has_hyphen = '-' in base_domain
    features['prefix_suffix'] = -1 if has_hyphen else 1
    if has_hyphen:
        risk_indicators.append({"level": "low", "msg": f"Domain contains a hyphen ({base_domain}) — major providers typically do not use hyphens in their domains"})

    # 7. having_sub_domain
    if matched_privacy_relay:
        subdomain_count = 0
    features['having_sub_domain'] = -1 if subdomain_count > 1 else (0 if subdomain_count == 1 else 1)
    if subdomain_count > 1:
        risk_indicators.append({"level": "medium", "msg": f"Domain has {subdomain_count} subdomain levels — phishing sites commonly use deep subdomains to impersonate brands"})

    # 8. https_token
    has_http_in_email = 'http' in scoring_email
    features['https_token'] = -1 if has_http_in_email else 1
    if has_http_in_email:
        risk_indicators.append({"level": "medium", "msg": "Email address contains the token 'http' — used to create visual confusion"})

    # 9. sslfinal_state (known legitimate provider)
    is_known = bool(
        matched_legit_provider
        or matched_disposable_domain
        or matched_privacy_relay
        or domain.endswith('.edu')
        or domain.endswith('.gov')
    )
    features['sslfinal_state'] = 1 if is_known else -1
    if not is_known:
        risk_indicators.append({"level": "medium", "msg": f"Domain ({base_domain}) is not a recognized legitimate mail provider"})

    # 10. domain_registration_length (TLD)
    has_common_tld = bool(public_suffix) or tld in COMMON_TLDS or bool(matched_privacy_relay)
    features['domain_registration_length'] = 1 if has_common_tld else -1
    if tld and not has_common_tld:
        risk_indicators.append({"level": "medium", "msg": f"TLD '.{tld}' is uncommon — phishing emails often use obscure or cheap TLDs"})

    # 11. age_of_domain (domain length as proxy)
    dom_len = len(domain_label)
    features['age_of_domain'] = -1 if dom_len > 20 else (0 if dom_len > 12 else 1)
    if dom_len > 20:
        risk_indicators.append({"level": "low", "msg": f"Domain label is unusually long ({dom_len} characters)"})

    # 12. dnsrecord (digits in domain)
    has_digits_domain = bool(re.search(r'\d', domain_label)) and not matched_privacy_relay
    features['dnsrecord'] = -1 if has_digits_domain else 1
    if has_digits_domain:
        risk_indicators.append({"level": "low", "msg": f"Domain label contains digits ({domain_label}) — legitimate brand domains are usually letters only"})

    # 13. web_traffic (high-traffic provider)
    features['web_traffic'] = 1 if (matched_high_traffic or matched_privacy_relay) else -1

    # 14. page_rank (suspicious keywords in domain)
    domain_susp = [] if matched_privacy_relay else [
        kw for kw in SUSPICIOUS_KEYWORDS if kw in domain.replace('.', '')
    ]
    features['page_rank'] = -1 if domain_susp else 1
    if domain_susp:
        risk_indicators.append({"level": "high", "msg": f"Domain contains phishing keywords: {', '.join(domain_susp[:3])}"})

    # 15. google_index (suspicious keywords in local part)
    local_susp = [kw for kw in SUSPICIOUS_KEYWORDS if kw in local]
    features['google_index'] = -1 if local_susp else 1
    if local_susp:
        risk_indicators.append({"level": "high", "msg": f"Username contains phishing keywords: {', '.join(local_susp[:3])}"})

    # 16. statistical_report (spam TLDs)
    features['statistical_report'] = -1 if tld in SPAM_TLDS else 1
    if tld in SPAM_TLDS:
        risk_indicators.append({"level": "high", "msg": f"TLD '.{tld}' is a known high-risk or free domain extension heavily used in phishing campaigns"})

    # 17. favicon (excessive digits in local)
    num_ratio = sum(c.isdigit() for c in local) / max(len(local), 1)
    features['favicon'] = 1

    # 18. port (entropy of local part) — threshold matches the auto-gen heuristic
    local_entropy = _shannon_entropy(local)
    features['port'] = 1

    # 19. request_url (special chars in local)
    allowed = set('abcdefghijklmnopqrstuvwxyz0123456789._-+')
    special = set(local) - allowed
    features['request_url'] = -1 if special else 1
    if special:
        risk_indicators.append({"level": "medium", "msg": f"Username contains non-standard special characters: {''.join(sorted(special))}"})

    # 20. url_of_anchor (local part length)
    local_len = len(local)
    features['url_of_anchor'] = (
        1 if matched_mail_service
        else (-1 if local_len > 30 else (0 if local_len > 15 else 1))
    )
    if local_len > 30 and not matched_mail_service:
        risk_indicators.append({"level": "low", "msg": f"Username is unusually long ({local_len} characters) — typical usernames are under 30 characters"})

    # 21. links_in_tags (brand spoofing)
    brand_spoof = None
    brand_substitution_detected = False
    normalized_domain = normalize_homoglyphs(domain_label)

    for brand in (() if matched_privacy_relay else BRAND_DOMAINS):
        canonical_domains = set(_PROTECTED_BRAND_DOMAINS.get(brand, set()))
        canonical_domains.update({brand + '.com', brand + '.net', brand + '.org'})
        is_official_domain = base_domain in canonical_domains
        # Check original domain
        original_match = brand in domain_label and not is_official_domain
        # Check normalized domain (catches paypa1, vvindows, amaz0n etc)
        normalized_match = (
            normalized_domain != domain_label
            and brand in normalized_domain
            and not is_official_domain
        )
        
        if original_match or normalized_match:
            brand_spoof = brand
            # Show which substitution was used
            if normalized_match and not original_match:
                brand_substitution_detected = True
                risk_indicators.append({
                    "level": "high",
                    "msg": f"Homoglyph attack detected — '{domain_label}' uses character substitution to impersonate '{brand}' (e.g. 1→l, 0→o, vv→w)"
                })
            break
    features['links_in_tags'] = -1 if brand_spoof else 1
    features['_brand_substitution_detected'] = brand_substitution_detected
    # 22. sfh (noreply address — neutral)
    features['sfh'] = 0 if ('noreply' in local or 'no-reply' in local or 'donotreply' in local) else 1

    # 23. submitting_to_email (repeated chars)
    max_repeat = max((local.count(c) for c in set(local)), default=0)
    repeat_ratio = max_repeat / max(len(local), 1)
    repeated_local = repeat_ratio > 0.5 and len(local) > 3
    features['submitting_to_email'] = 1

    # 24. abnormal_url (digit-letter mix + homoglyph in domain label)
    digit_letter_mix = (
        bool(re.search(r'(?<=[a-z])\d|(?<=\d)[a-z]', domain_label))
        and not matched_privacy_relay
    )
    # Also check if normalizing changes the domain significantly (indicates substitution)
    normalized = normalize_homoglyphs(domain_label)
    homoglyph_detected = (
        not matched_privacy_relay
        and normalized != domain_label
        and any(brand in normalized for brand in BRAND_DOMAINS)
    )
    features['abnormal_url'] = -1 if (digit_letter_mix or homoglyph_detected) else 1
    if homoglyph_detected and not digit_letter_mix:
        risk_indicators.append({
            "level": "high",
            "msg": f"Character substitution detected in domain '{domain_label}' — normalized to '{normalized}'"
        })

    # 25. redirect (default legit — can't check without network)
    features['redirect'] = 1

    # 26. on_mouseover (abused ccTLD)
    features['on_mouseover'] = -1 if tld in ABUSED_CCTLDS else 1
    if tld in ABUSED_CCTLDS:
        risk_indicators.append({"level": "medium", "msg": f"TLD '.{tld}' is a country-code domain commonly abused in phishing attacks"})

    # 27. rightclick (auto-generated pattern: lowercase letters + digits)
    auto_gen = bool(re.match(r'^[a-z]{2,5}\d{4,12}$', local))
    features['rightclick'] = 1

    # 28. popupwindow (too many domain word segments)
    domain_words = re.findall(r'[a-z]+', domain_label)
    features['popupwindow'] = -1 if len(domain_words) > 3 else 1

    # 29. iframe (overall phishing count as cumulative risk)
    phish_count = sum(1 for v in features.values() if v == -1)
    features['iframe'] = -1 if phish_count > 8 else (0 if phish_count > 4 else 1)

    # 30. links_pointing_to_page (basic email format validity)
    email_valid = bool(re.match(
        r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', scoring_email
    ))
    features['links_pointing_to_page'] = 1 if email_valid else -1
    if not email_valid:
        risk_indicators.append({"level": "high", "msg": "Email address does not pass RFC format validation — invalid address"})

    # ── Extended semantic domain analysis (extra risk signals beyond ML) ──────
    if not is_known:
        fin_kw_found  = sorted({kw for kw in FINANCIAL_DOMAIN_KEYWORDS if kw in domain_label}, key=len, reverse=True)
        biz_sfx_found = sorted({kw for kw in BUSINESS_SUFFIX_KEYWORDS  if kw in domain_label}, key=len, reverse=True)

        # Detect the fake-business-name compound pattern:
        #   [short abbreviation 0-4 chars] + [financial keyword] + [business suffix]
        # e.g. bpinsgroup → bp + ins + group
        fake_biz_breakdown = None
        for fkw in fin_kw_found:
            idx = domain_label.find(fkw)
            if idx < 0:
                continue
            prefix    = domain_label[:idx]
            remainder = domain_label[idx + len(fkw):]
            if len(prefix) <= 4 and prefix.isalpha() and any(bkw == remainder for bkw in biz_sfx_found):
                fake_biz_breakdown = f"'{prefix or '(none)'}' + '{fkw}' + '{remainder}'"
                break
            # Also catch: financial keyword at start, business suffix follows
            if idx == 0 and any(bkw == remainder for bkw in biz_sfx_found):
                fake_biz_breakdown = f"[start] + '{fkw}' + '{remainder}'"
                break

        if fake_biz_breakdown:
            risk_indicators.insert(0, {
                "level": "high",
                "msg": (
                    f"Domain '{base_domain}' follows an [abbreviation]+[financial term]+"
                    f"[business suffix] pattern ({fake_biz_breakdown}) — a known technique "
                    f"used to fabricate fake financial institution email domains"
                ),
            })
        elif fin_kw_found and biz_sfx_found:
            risk_indicators.append({
                "level": "high",
                "msg": (
                    f"Domain '{base_domain}' combines financial keywords "
                    f"({', '.join(fin_kw_found[:2])}) with business entity suffixes "
                    f"({', '.join(biz_sfx_found[:2])}) — pattern commonly seen in "
                    f"financial phishing and business email compromise (BEC) domains"
                ),
            })
        elif fin_kw_found:
            risk_indicators.append({
                "level": "medium",
                "msg": (
                    f"Domain '{base_domain}' contains financial-sector keywords "
                    f"({', '.join(fin_kw_found[:3])}) on an unverified provider — "
                    f"verify the sender before sharing financial or personal information"
                ),
            })
        elif biz_sfx_found:
            risk_indicators.append({
                "level": "low",
                "msg": (
                    f"Domain '{base_domain}' uses a business entity suffix "
                    f"({', '.join(biz_sfx_found[:2])}) but is not a recognized "
                    f"or verified organization"
                ),
            })

        # Detect domain that embeds a known brand name as a sub-string
        # (catches cases not handled by exact-match brand spoofing check above)
        if not brand_spoof:
            partial_brands = [b for b in BRAND_DOMAINS if b in domain_label and b != domain_label]
            if partial_brands:
                risk_indicators.append({
                    "level": "high",
                    "msg": (
                        f"Domain '{base_domain}' contains the name of a well-known brand "
                        f"({', '.join(partial_brands[:2])}) as a substring but is not the "
                        f"official domain — possible typosquatting or brand impersonation"
                    ),
                })

        # Detect government/regulatory keyword on a non-.gov domain
        gov_kw = {'federal', 'national', 'authority', 'ministry', 'government',
                  'regulatory', 'commission', 'bureau', 'department', 'administration'}
        gov_hits = [kw for kw in gov_kw if kw in domain_label]
        if gov_hits and tld not in {'gov', 'mil'}:
            risk_indicators.append({
                "level": "high",
                "msg": (
                    f"Domain '{base_domain}' contains government/regulatory keywords "
                    f"({', '.join(gov_hits[:2])}) but is NOT a .gov/.mil domain — "
                    f"likely impersonating an official body"
                ),
            })

        # Detect very long domain label (>15 chars) that is a concatenated word chain
        if len(domain_label) > 15 and (fin_kw_found or biz_sfx_found):
            risk_indicators.append({
                "level": "medium",
                "msg": (
                    f"Domain label '{domain_label}' is long ({len(domain_label)} chars) and "
                    f"appears to be a compound of multiple words — bulk phishing campaigns "
                    f"often generate such domains to appear business-like"
                ),
            })

    # ── Disposable email classification (separate from the 30 ML features) ────
    disposable_status = "no_known_match"
    disposable_confidence = "unknown"
    matched_provider_domain = None
    if matched_disposable_domain:
        disposable_status = "known_disposable_provider"
        disposable_confidence = "confirmed"
        matched_provider_domain = matched_disposable_domain
    elif matched_privacy_relay:
        disposable_status = "privacy_relay"
        disposable_confidence = "confirmed"
        matched_provider_domain = matched_privacy_relay

    is_disposable = disposable_status == "known_disposable_provider"
    is_suspected_disposable = False

    # 2. Auto-generated username heuristic:
    #    High-entropy all-lowercase-letters username (no vowel pattern, no digits,
    #    length 8-20) on an unknown domain  →  very likely a randomly-generated
    #    disposable address even if the domain is not in the list.
    if not matched_disposable_domain and not matched_privacy_relay and local:
        is_unknown_domain = not matched_legit_provider and not matched_high_traffic

        # ── Multi-factor randomness scoring ───────────────────────────────────
        # Regex now allows . _ - separators (e.g. word.word, word-word patterns)
        # Unknown domains use threshold 2; recognized providers use threshold 4.
        if bool(re.fullmatch(r'[a-z0-9._-]{8,25}', local)):

            letters_only = ''.join(c for c in local if c.isalpha())
            digit_count  = sum(c.isdigit() for c in local)
            digit_ratio  = digit_count / max(len(local), 1)
            vowel_ratio  = sum(1 for c in letters_only if c in 'aeiou') / max(len(letters_only), 1)
            entropy      = _shannon_entropy(local)

            # ── Firstname.Lastname exemption ──────────────────────────────────
            # Legitimate users often use first.last@company.com patterns.
            # Skip the heuristic for confirmed real-name combinations.
            _FIRST = {
                'alice','john','jane','mark','mike','kate','jack','alex','adam',
                'luke','mary','anna','sara','lisa','emma','ryan','paul','eric',
                'alan','kyle','noah','liam','dave','owen','evan','peter','james',
                'chris','david','emily','grace','oliver','daniel','thomas','robert',
                'william','joseph','henry','samuel','joshua','andrew','michael',
                'jacob','ethan','mason','logan','lucas','sophia','isabella','mia',
                'charlotte','amelia','harper','evelyn','abigail','madison','ella',
                'chloe','riley','layla','zoey','nora','lily','eleanor','hannah',
                'addison','stella','natalie','zoe','leah','hazel','violet','claire',
                'skylar','lucy','anna','caroline','jennifer','jessica','ashley',
                'sarah','amanda','brittany','samantha','elizabeth','megan','rachel',
                'kayla','andrea','lauren','victoria','matthew','christopher',
                'justin','brandon','tyler','jonathan','nicholas','nathan','zachary',
                'kevin','timothy','steven','austin','travis','jordan','derek','dylan',
                'sean','brian','scott','patrick','keith','gary','dennis','frank',
                'harold','raymond','samuel','jerry','teresa','diana','joyce',
            }
            _LAST = {
                'smith','jones','brown','davis','wilson','taylor','anderson',
                'jackson','white','harris','martin','thompson','garcia','martinez',
                'robinson','clark','rodriguez','lewis','lee','walker','hall',
                'allen','young','hernandez','king','wright','lopez','hill','scott',
                'green','adams','baker','gonzalez','nelson','carter','mitchell',
                'perez','roberts','turner','phillips','campbell','parker','evans',
                'edwards','collins','stewart','sanchez','morris','rogers','reed',
                'cook','morgan','bell','murphy','bailey','rivera','cooper',
                'richardson','cox','howard','ward','torres','peterson','gray',
                'ramirez','watson','brooks','kelly','sanders','price','bennett',
                'wood','barnes','ross','henderson','coleman','jenkins','perry',
                'powell','long','patterson','hughes','flores','washington','butler',
                'simmons','foster','gonzales','bryant','alexander','russell',
                'griffin','diaz','hayes','fisher','cole','frank','owens',
                'reynolds','mills','grant','wells','ford','porter','hunt','stone',
                'dixon','hawkins','burns','berry','shaw','reyes','medina',
                'doe','johnson','williams','miller','moore','thomas','wright',
                'walker','hall','allen','young','adams','nelson','carter',
            }
            sep_parts = re.split(r'[._-]', tag_stripped_local)
            is_separated_real_name = (
                len(sep_parts) == 2 and
                all(p.isalpha() and len(p) >= 2 for p in sep_parts) and
                ((sep_parts[0] in _FIRST and sep_parts[1] in _LAST) or
                 (sep_parts[0] in _LAST  and sep_parts[1] in _FIRST))
            )
            canonical_name = re.sub(r'[._-]', '', tag_stripped_local)
            is_concatenated_real_name = any(
                (
                    canonical_name.startswith(first)
                    and canonical_name[len(first):] in _LAST
                )
                or (
                    canonical_name.endswith(first)
                    and canonical_name[:-len(first)] in _LAST
                )
                for first in _FIRST
            )
            is_real_name = is_separated_real_name or is_concatenated_real_name

            if not is_real_name:
                # Factor 1 – Shannon entropy indicates near-uniform character spread
                f_entropy = entropy > 3.0

                # Factor 2 – Low vowel ratio (random strings often lack vowels)
                f_vowels = vowel_ratio <= 0.30

                # Factor 3 – Digits scattered inside the string, not just at the end
                f_digits = (digit_count >= 2 and
                            bool(re.search(r'[a-z]\d[a-z]|\d[a-z]\d', local)))

                # Factor 4 – High unique-character ratio (random = few repeats)
                unique_ratio = len(set(local)) / max(len(local), 1)
                f_unique = unique_ratio >= 0.75

                # Factor 5 – No recognisable English word embedded
                _COMMON = {'user','mail','info','test','home','name','blog','help',
                           'shop','work','love','life','data','code','tech','site',
                           'link','post','news','real','best','john','jane','mark',
                           'mike','kate','jack','alex','adam','luke','mary','anna',
                           'sara','lisa','emma','ryan','paul','eric','alan','kyle',
                           'noah','liam','dave','owen','evan','alice','smith','jones',
                           'peter','james','chris','david','emily','grace','hello',
                           'world','super','admin','sales','brown','davis','thomas',
                           'robert','oliver','daniel','master','shadow','dragon','tiger',
                           'support','contact','service','secure','account','email',
                           'notify','alert','update','welcome','newsletter','webmaster',
                           'phoenix','mighty','dark','light','storm','fire','ice',
                           'wolf','hawk','eagle','falcon','raven','fox','bear','lion',
                           'night','star','moon','blue','red','black','white','gold',
                           'cyber','neon','nova','omega','alpha','prime','mega','ninja',
                           'king','queen','lord','knight','warrior','hunter','ranger',
                           'swift','brave','sharp','smart','bold','wild','free',}
                letters_lower = letters_only.lower()
                has_real_word = any(w in letters_lower for w in _COMMON)
                f_noword = not has_real_word

                # Factor 6 – word.word separator pattern where words are NOT real names
                #             (username generators often combine random words with dots)
                word_parts = [p for p in sep_parts if p.isalpha() and len(p) >= 3]
                f_word_combo = (
                    len(word_parts) >= 2 and
                    not any(w in (_FIRST | _LAST | _COMMON) for w in word_parts)
                )

                rnd_score = sum([f_entropy, f_vowels, f_digits, f_unique, f_noword, f_word_combo])

                threshold = 2 if is_unknown_domain else 4
                if rnd_score >= threshold:
                    disposable_status = "suspicious_mailbox_pattern"
                    disposable_confidence = "heuristic"
                    is_suspected_disposable = True
                    features['favicon'] = -1 if num_ratio > 0.4 else 1
                    features['port'] = -1 if local_entropy > 3.0 else 1
                    features['submitting_to_email'] = -1 if repeated_local else 1
                    features['rightclick'] = -1 if auto_gen else 1
                    factors_hit = []
                    if f_entropy:    factors_hit.append(f"entropy {entropy:.2f}")
                    if f_vowels:     factors_hit.append(f"vowel {vowel_ratio:.0%}")
                    if f_digits:     factors_hit.append("digits scattered")
                    if f_unique:     factors_hit.append(f"unique-ratio {unique_ratio:.0%}")
                    if f_noword:     factors_hit.append("no real word")
                    if f_word_combo: factors_hit.append("unusual word combo")
                    risk_indicators.insert(0, {
                        "level": "medium",
                        "msg": (
                            f"Username '{local}' matches {rnd_score}/6 randomness factors "
                            f"({', '.join(factors_hit)}) — the mailbox pattern looks "
                            f"automatically generated, but account age and lifetime "
                            f"cannot be confirmed"
                        ),
                    })

    if (
        disposable_status == "no_known_match"
        and _matches_disposable_domain_pattern(domain)
    ):
        disposable_status = "suspicious_domain_pattern"
        disposable_confidence = "heuristic"
        is_suspected_disposable = True
        risk_indicators.insert(0, {
            "level": "medium",
            "msg": (
                f"Domain ({domain}) resembles a temporary-email provider name, "
                f"but is not in the confirmed provider registry"
            ),
        })

    disposable_service = matched_disposable_domain if is_disposable else None
    if disposable_status == "known_disposable_provider":
        risk_indicators.insert(0, {
            "level": "info",
            "msg": (
                f"Known disposable-email provider detected ({matched_disposable_domain}). "
                "Provider category alone is not phishing evidence; mailbox lifetime is unknown."
            ),
        })
    elif disposable_status == "privacy_relay":
        risk_indicators.insert(0, {
            "level": "info",
            "msg": (
                f"Privacy relay or masked-address provider detected "
                f"({matched_privacy_relay}); this is not phishing evidence by itself."
            ),
        })

    if address_alias_type:
        risk_indicators.append({
            "level": "info",
            "msg": "Address uses plus subaddressing; the tag is not a phishing signal.",
        })

    classification = {
        "disposable_status": disposable_status,
        "disposable_confidence": disposable_confidence,
        "matched_provider_domain": matched_provider_domain,
        "address_alias_type": address_alias_type,
    }
    return (
        features,
        risk_indicators,
        is_disposable,
        is_suspected_disposable,
        disposable_service,
        classification,
    )


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _app.state.case_service = None
    _app.state.case_configuration_error = False
    try:
        _app.state.case_service = build_case_service(os.environ)
    except (ValueError, OSError):
        # Optional case configuration must fail closed without taking down
        # the independent transient analyzer. Never log configuration values.
        _app.state.case_configuration_error = True
        print('Case management unavailable: invalid configuration or inaccessible storage.')
    global _content_pipeline, _content_model_error, _content_model_artifact_sha256
    global _sender_history_store
    _sender_history_store = build_sender_history_store(SETTINGS)
    if SETTINGS.content_model_enabled:
        if not SETTINGS.content_model_artifact or not SETTINGS.content_model_artifact_sha256:
            _content_pipeline = None
            _content_model_error = (
                "Content ML is enabled but CONTENT_MODEL_ARTIFACT and "
                "CONTENT_MODEL_ARTIFACT_SHA256 are not both configured."
            )
            _content_model_artifact_sha256 = None
        else:
            try:
                _content_pipeline = load_content_pipeline_artifact(
                    Path(SETTINGS.content_model_artifact),
                    SETTINGS.content_model_artifact_sha256,
                )
                _content_model_error = None
                _content_model_artifact_sha256 = SETTINGS.content_model_artifact_sha256.lower()
                print("Loaded verified offline email-content model artifact.")
            except ValueError as exc:
                _content_pipeline = None
                _content_model_error = f"Content-model artifact rejected: {exc}"
                _content_model_artifact_sha256 = None
                print(_content_model_error)
            except Exception as exc:
                _content_pipeline = None
                _content_model_error = (
                    f"Content-model artifact unavailable ({type(exc).__name__})."
                )
                _content_model_artifact_sha256 = None
                print(_content_model_error)
    else:
        _content_pipeline = None
        _content_model_error = None
        _content_model_artifact_sha256 = None
        print("Content ML disabled; verified heuristic and message-structure analysis remain available.")
    yield


app = FastAPI(title="Phishing Email Detector", version="2.0.0", lifespan=lifespan)


def _build_allowed_hosts(base_hosts: str, custom_domains: str = "") -> list[str]:
    """Merge configured deployment hosts and custom domains without duplicates."""
    hosts: list[str] = []
    for host in base_hosts.split(","):
        normalized = host.strip().lower().rstrip(".")
        if normalized and normalized not in hosts:
            hosts.append(normalized)

    custom_host_re = re.compile(
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
    )
    for host in custom_domains.split(","):
        raw_host = host.strip().lower()
        if not raw_host:
            continue
        normalized = raw_host.rstrip(".")
        if (
            not normalized
            or len(normalized) > 253
            or not custom_host_re.fullmatch(normalized)
        ):
            raise ValueError(
                "CUSTOM_DOMAINS entries must be hostnames without a URL scheme, port, or path"
            )
        if normalized not in hosts:
            hosts.append(normalized)
    return hosts


allowed_hosts = _build_allowed_hosts(
    os.getenv("ALLOWED_HOSTS", "*.onrender.com,localhost,127.0.0.1,testserver"),
    os.getenv("CUSTOM_DOMAINS", ""),
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
app.add_middleware(RequestBodyLimitMiddleware, max_bytes=MAX_REQUEST_BYTES,
                   path_limits={**{path: MAX_VISUAL_REQUEST_BYTES for path in VISUAL_PATHS},
                                '/api/feedback': 100_000})

_rate_limit_lock = threading.Lock()
_rate_limit_buckets: dict[str, deque[float]] = {}


def _rate_limit_key(request: Request) -> str:
    """Use Vercel's normalized client address only in the Vercel profile."""
    client_ip = request.client.host if request.client else "unknown"
    if os.getenv("PHISHGUARD_DEPLOYMENT_PROFILE", "").strip().lower() == "vercel-free":
        forwarded_ip = request.headers.get("x-forwarded-for", "").strip()
        if forwarded_ip and "," not in forwarded_ip:
            try:
                client_ip = str(ipaddress.ip_address(forwarded_ip))
            except ValueError:
                pass
    return f"{client_ip}:{request.url.path}"


def _record_rate_limit_hit(
    bucket_key: str,
    *,
    now: float,
    buckets: dict[str, deque[float]],
    limit: int,
    capacity: int,
    window_seconds: float,
) -> bool:
    cutoff = now - window_seconds
    stale_keys = []
    for key, hits in buckets.items():
        while hits and hits[0] <= cutoff:
            hits.popleft()
        if not hits:
            stale_keys.append(key)
    for key in stale_keys:
        buckets.pop(key, None)

    if bucket_key not in buckets:
        if len(buckets) >= capacity:
            oldest_key = min(buckets, key=lambda key: buckets[key][-1])
            buckets.pop(oldest_key, None)
        buckets[bucket_key] = deque()

    bucket = buckets[bucket_key]
    if len(bucket) >= limit:
        return False
    bucket.append(now)
    return True


def _with_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    )
    return response


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """Bound request cost and add browser protections for the public demo."""
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            limit = (MAX_VISUAL_REQUEST_BYTES if request.url.path in VISUAL_PATHS
                     else 100_000 if request.url.path == '/api/feedback' else MAX_REQUEST_BYTES)
            if int(content_length) > limit:
                return _with_security_headers(JSONResponse(
                    status_code=413,
                    content={"detail": "Request body is too large"},
                ))
        except ValueError:
            return _with_security_headers(JSONResponse(
                status_code=400,
                content={"detail": "Invalid Content-Length"},
            ))

    if request.method in {"POST", "PATCH"} and request.url.path.startswith("/api/"):
        bucket_key = _rate_limit_key(request)
        now = time.monotonic()

        with _rate_limit_lock:
            if not _record_rate_limit_hit(
                bucket_key,
                now=now,
                buckets=_rate_limit_buckets,
                limit=RATE_LIMIT_PER_MINUTE,
                capacity=RATE_LIMIT_BUCKET_CAPACITY,
                window_seconds=60.0,
            ):
                return _with_security_headers(JSONResponse(
                    status_code=429,
                    content={"detail": "Too many requests; try again in a minute"},
                    headers={"Retry-After": "60"},
                ))

        distributed_decision = await _sender_history_store.check_rate_limit(
            bucket_key,
            limit=RATE_LIMIT_PER_MINUTE,
            window_seconds=60,
        )
        if distributed_decision is not None and not distributed_decision.allowed:
            return _with_security_headers(JSONResponse(
                status_code=429,
                content={"detail": "Too many requests; try again shortly"},
                headers={
                    "Retry-After": str(distributed_decision.retry_after),
                },
            ))

        if request.url.path == '/api/feedback':
            feedback_key = bucket_key + ':feedback'
            with _rate_limit_lock:
                allowed = _record_rate_limit_hit(
                    feedback_key, now=now, buckets=_rate_limit_buckets,
                    limit=5, capacity=RATE_LIMIT_BUCKET_CAPACITY, window_seconds=3600.0)
            if not allowed:
                return _with_security_headers(JSONResponse(
                    status_code=429, content={'detail': 'Too many reports; try again later'},
                    headers={'Retry-After': '3600'}))
            feedback_decision = await _sender_history_store.check_rate_limit(
                feedback_key, limit=5, window_seconds=3600)
            if feedback_decision is not None and not feedback_decision.allowed:
                return _with_security_headers(JSONResponse(
                    status_code=429, content={'detail': 'Too many reports; try again later'},
                    headers={'Retry-After': str(feedback_decision.retry_after)}))

    response = _with_security_headers(await call_next(request))
    if request.url.path in {'/static/vision-worker.mjs', '/static/vendor/vision/worker.min.js'}:
        response.headers['Content-Security-Policy'] = (
            "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; "
            "connect-src 'self'; worker-src 'self'; object-src 'none'")
    return response


@app.middleware("http")
async def private_case_responses(request: Request, call_next):
    response = await call_next(request)
    if request.url.path == '/cases' or request.url.path.startswith('/api/cases') or request.url.path == '/api/feedback':
        response.headers['Cache-Control'] = 'no-store'
    if request.url.path == '/cases' or request.url.path.startswith('/api/cases'):
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
            "connect-src 'self'; worker-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
    return response


@app.get('/cases', include_in_schema=False)
async def serve_cases():
    return FileResponse(str(BASE_DIR / 'static' / 'cases.html'))


VERCEL_COLLECTORS = frozenset({'insights', 'speed-insights'})


@app.get('/_vercel/{collector}/script.js', include_in_schema=False)
async def local_vercel_collector(collector: str):
    """Answer the page's Vercel collector tags off-platform instead of 404ing.

    On Vercel the platform serves these paths itself; if a request still reaches
    the app there, keep the original 404 so a misconfiguration stays visible.
    """
    if os.getenv('VERCEL') or collector not in VERCEL_COLLECTORS:
        raise HTTPException(status_code=404, detail='Not Found')
    return Response('', media_type='text/javascript', headers={'Cache-Control': 'no-store'})


# ── Static files ──────────────────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.get("/")
async def serve_index():
    return FileResponse(str(BASE_DIR / "static" / "index.html"))


@app.get("/health")
async def health():
    """Liveness/readiness probe for deployments and load balancers."""
    commit_sha = os.getenv("VERCEL_GIT_COMMIT_SHA", "")
    return JSONResponse(
        status_code=200,
        content={
            "status": "ok",
            **public_jev_status(app),
            "commit_sha": commit_sha.lower() if re.fullmatch(r"[0-9a-fA-F]{40}", commit_sha) else None,
            "model_loaded": _content_pipeline is not None,
            "content_model_loaded": _content_pipeline is not None,
            "content_model_error": _content_model_error,
            "content_model_artifact_sha256": _content_model_artifact_sha256,
            "content_model_id": (
                f"sha256:{_content_model_artifact_sha256[:12]}"
                if _content_model_artifact_sha256 else None
            ),
            "model_data_source": (
                _content_pipeline.get("metrics", {}).get("data_source")
                if _content_pipeline is not None else None
            ),
            "sender_analysis_method": "sender-domain-heuristics",
            "sender_history_enabled": SETTINGS.sender_history_enabled,
            "sender_history_configured": SETTINGS.sender_history_ready,
            "sender_history_available": SETTINGS.sender_history_ready,
            "sender_history_error": SETTINGS.sender_history_config_error,
            "deployment_profile": SETTINGS.app_env,
            "email_verification_enabled": SETTINGS.domain_verification_enabled,
            "verification_mode": SETTINGS.effective_verification_mode,
            "domain_verification_enabled": SETTINGS.domain_verification_enabled,
            "smtp_verification_enabled": SETTINGS.smtp_verification_enabled,
            "verification_workers": VERIFICATION_WORKERS,
        },
    )


# ── API ───────────────────────────────────────────────────────────────────────
@app.get("/api/metrics")
async def get_metrics():
    payload = {
        "metrics": MODEL_METRICS,
        "benchmark_scope": "uci-phishing-websites-only",
        "benchmark_note": (
            "These historical notebook metrics describe the UCI Phishing Websites "
            "dataset and are not email-sender accuracy claims."
        ),
    }
    if _content_pipeline is not None:
        m = _content_pipeline["metrics"]
        payload["content_model"] = {
            "name": f"TF-IDF (word + char n-gram) + {m.get('model', 'classifier')}",
            "metrics":     m,
            "data_source": m.get("data_source", ""),
            "top_terms":   _content_pipeline["top_terms"],
            "artifact_sha256": _content_model_artifact_sha256,
            "model_id": (
                f"sha256:{_content_model_artifact_sha256[:12]}"
                if _content_model_artifact_sha256 else None
            ),
        }
    return JSONResponse(payload)


@app.get("/api/features")
async def get_features():
    return JSONResponse({"features": FEATURE_INFO})


@app.get("/api/config")
async def get_public_config():
    return JSONResponse({
        **public_jev_status(app),
        "deployment_profile": SETTINGS.app_env,
        "email_verification_enabled": SETTINGS.domain_verification_enabled,
        "verification_mode": SETTINGS.effective_verification_mode,
        "domain_verification_enabled": SETTINGS.domain_verification_enabled,
        "smtp_verification_enabled": SETTINGS.smtp_verification_enabled,
        "content_model_enabled": SETTINGS.content_model_enabled,
        "sender_history_enabled": SETTINGS.sender_history_enabled,
        "sender_history_configured": SETTINGS.sender_history_ready,
        "sender_history_available": SETTINGS.sender_history_ready,
        "feedback_enabled": (getattr(app.state, 'case_service', None) is not None
                             and not getattr(app.state, 'case_configuration_error', False)),
        "full_version_local_only": True,
    })


class EmailRequest(BaseModel):
    email: str = Field(..., min_length=1, max_length=254)


def _analyze_sender_address(email: str) -> dict:
    """Return the shared explainable sender/domain heuristic result."""
    email = email.strip()
    if not email:
        raise HTTPException(status_code=400, detail="Email address is required")

    (
        feature_dict,
        risk_indicators,
        is_disposable,
        is_suspected_disposable,
        disposable_service,
        disposable_classification,
    ) = extract_email_features(_normalize_sender_address(email))

    # The UCI model is a phishing-*website* benchmark. Its URL/HTML feature
    # weights are not valid probabilities for sender addresses, so this API
    # deliberately reports an explainable heuristic risk score instead.
    cols = FEATURE_NAMES
    feature_values = [feature_dict.get(name, 0) for name in cols]
    info_map = {f["name"]: f for f in FEATURE_INFO}
    feature_breakdown = []
    for name in cols:
        info = info_map.get(name, {"label": name, "email_desc": "", "group": ""})
        val = int(float(feature_dict.get(name, 0)))
        # Choose description that matches the current value direction
        if val == 1:
            desc = info.get("email_desc_pos") or info.get("email_desc", "")
        else:
            desc = info.get("email_desc", "")
        feature_breakdown.append({
            "name": name,
            "label": info["label"],
            "email_desc": desc,
            "group": info["group"],
            "value": val,
        })
    feature_breakdown.sort(key=lambda item: {-1: 0, 0: 1, 1: 2}[item["value"]])

    high_risks = sum(1 for r in risk_indicators if r["level"] == "high")
    med_risks = sum(1 for r in risk_indicators if r["level"] == "medium")
    low_risks = sum(1 for r in risk_indicators if r["level"] == "low")
    phish_features = sum(1 for v in feature_values if v == -1)
    risk_score = min(
        100,
        high_risks * 28
        + med_risks * 10
        + low_risks * 3
    )
    if feature_dict.get("_brand_substitution_detected") is True:
        risk_score = max(risk_score, 60)
    if risk_score >= 80:
        verdict, label = "critical", "Critical Sender Risk"
    elif risk_score >= 60:
        verdict, label = "high", "High Sender Risk"
    elif risk_score >= 30:
        verdict, label = "medium", "Suspicious Sender"
    else:
        verdict, label = "low", "Low Sender Risk"

    return {
        "email": email,
        "analysis_method": "sender-domain-heuristics",
        "verdict": verdict,
        "label": label,
        "risk_score": risk_score,
        "risk_indicators": risk_indicators,
        "high_risk_count": high_risks,
        "med_risk_count": med_risks,
        "phish_feature_count": phish_features,
        "feature_breakdown": feature_breakdown[:10],
        "is_disposable": is_disposable,
        "is_suspected_disposable": is_suspected_disposable,
        "disposable_service": disposable_service,
        **disposable_classification,
    }


def _sender_account_observability(analysis: dict) -> str:
    if analysis.get("disposable_status") in {
        "known_disposable_provider", "privacy_relay",
    }:
        return "not_applicable"
    normalized = _normalize_sender_address(str(analysis.get("email", "")))
    domain = normalized.rsplit("@", 1)[-1].lower() if normalized else ""
    if _match_domain_registry(domain, MAJOR_MAILBOX_PROVIDERS):
        return "provider_account_unverifiable"
    return "unknown"


async def _analyze_and_observe_sender(address: str) -> dict:
    """Analyze one raw-message sender and record one retained observation."""
    analysis = _analyze_sender_address(address)
    normalized_address = _normalize_sender_address(address)
    history_address = canonicalize_sender_address(normalized_address or address)
    history = await _sender_history_store.observe(history_address)
    analysis["account_observability"] = _sender_account_observability(analysis)
    analysis.update(history.as_dict())
    return analysis


def _analyze_sender_without_history_lookup(address: str) -> dict:
    """Analyze an address without exposing retained service-wide history."""
    analysis = _analyze_sender_address(address)
    analysis["account_observability"] = _sender_account_observability(analysis)
    analysis.update(SenderHistoryResult(status="raw_message_required").as_dict())
    return analysis


_RAW_SENDER_LOCAL_RE = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+$"
)
_RAW_SENDER_DOMAIN_LABEL_RE = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)


def _normalize_sender_address(address: str) -> str:
    address = address.strip()
    if address.count('@') != 1 or any(c.isspace() for c in address):
        return ''
    local, domain = address.rsplit('@', 1)
    domain = normalize_domain(domain)
    labels = domain.split('.')
    if (not 0 < len(local) <= 64 or not _RAW_SENDER_LOCAL_RE.fullmatch(local)
            or local.startswith('.') or local.endswith('.') or '..' in local
            or len(domain) > 253 or len(labels) < 2
            or any(not _RAW_SENDER_DOMAIN_LABEL_RE.fullmatch(label) for label in labels)):
        return ''
    return f'{local}@{domain}'


def _raw_sender_addresses(from_header: str) -> list[str]:
    """Return unique, plausible public-mailbox addr-specs from a From header."""
    addresses: list[str] = []
    seen: set[str] = set()
    for _display_name, parsed_address in getaddresses([from_header or ""]):
        normalized = _normalize_sender_address(parsed_address)
        if not normalized:
            continue
        key = normalized.casefold()
        if key not in seen:
            seen.add(key)
            addresses.append(normalized)
    return addresses


@app.post("/api/analyze-email")
async def analyze_email(request: EmailRequest):
    address = request.email.strip()
    if not _normalize_sender_address(address):
        raise HTTPException(
            status_code=400,
            detail="Enter a single email address, such as user@example.com. Use Email Content to analyze a message.",
        )
    return JSONResponse(_analyze_sender_without_history_lookup(address))


# ─────────────────────────────────────────────────────────────────────────────
# Email Content Analysis (heuristic rule-based, no ML model required)
# ─────────────────────────────────────────────────────────────────────────────

CONTENT_RULES: dict = {
    "urgency": {
        "label": "Urgency & Pressure",
        "level": "high",
        "icon": "⏰",
        "description": "Phishing emails create artificial time pressure to prevent careful thinking.",
        "keywords": [
            "urgent", "immediately", "act now", "respond within", "respond today",
            "within 24 hours", "within 48 hours", "within 72 hours", "limited time",
            "today only", "expires soon", "expiring", "deadline", "last chance",
            "final notice", "final warning", "time sensitive", "time-sensitive",
            "asap", "do not delay", "action required", "response required",
            "reply immediately", "prompt action", "critical alert", "important notice",
            "account will be deleted", "service will be discontinued",
            "must respond", "failure to respond", "failure to act",
            "your access will be", "expiration notice",
        ],
    },
    "threats": {
        "label": "Threats & Fear Tactics",
        "level": "high",
        "icon": "🚨",
        "description": "Scammers use fear of account loss, legal trouble, or arrest to coerce victims.",
        "keywords": [
            "account suspended", "account blocked", "account terminated", "account closed",
            "access denied", "access revoked", "will be terminated", "will be suspended",
            "legal action", "lawsuit", "arrested", "penalty", "criminal charges",
            "your account has been", "unusual activity", "suspicious activity",
            "unauthorized access", "security breach", "compromised", "hacked",
            "report you", "law enforcement", "police", "fbi", "irs audit",
            "debt collection", "warrant issued", "court order",
            "face prosecution", "civil lawsuit", "criminal investigation",
            "your ip address", "your device has been", "data breach",
            "identity theft", "we have recorded", "we have detected",
        ],
    },
    "financial": {
        "label": "Financial Lure",
        "level": "high",
        "icon": "💰",
        "description": "Promises of unexpected money or urgent payment demands are classic scam patterns.",
        "keywords": [
            "free money", "lottery", "you won", "you have won", "prize winner",
            "million dollar", "billion dollar", "inheritance", "unclaimed funds",
            "transfer funds", "wire transfer", "bitcoin", "cryptocurrency", "crypto wallet",
            "investment opportunity", "guaranteed return", "100% profit", "risk-free",
            "send money", "western union", "moneygram", "gift card", "itunes card",
            "google play card", "steam card",
            "overdue payment", "unpaid invoice", "outstanding balance",
            "refund pending", "tax refund", "claim your refund", "unclaimed prize",
            "processing fee", "advance fee", "release fee", "activation fee",
            "donation", "charity fund", "humanitarian fund",
            "next of kin", "deceased customer", "deceased estate",
        ],
    },
    "credential": {
        "label": "Credential Harvesting",
        "level": "high",
        "icon": "🔑",
        "description": "Requests for passwords, card numbers, SSN, or account details are major red flags.",
        "keywords": [
            "click here to verify", "verify your account", "verify your email",
            "confirm your account", "confirm your identity", "confirm your details",
            "reset your password", "update your password", "enter your password",
            "provide your password", "validate your account", "re-enter your",
            "social security number", "ssn", "credit card number",
            "bank account number", "routing number", "date of birth",
            "mother's maiden name", "security question", "pin number",
            "login to your account", "sign in to verify", "update your information",
            "submit your details", "fill in the form below",
            "complete the form", "fill out the form", "enter your details",
            "passport number", "driver's license", "national id",
            "two-factor", "one-time password", "otp code",
        ],
    },
    "impersonation": {
        "label": "Possible Brand Impersonation",
        "level": "medium",
        "icon": "🎭",
        "description": "Mentions of well-known brands alongside action requests may indicate spoofing.",
        "keywords": [
            "paypal", "amazon", "apple id", "google account", "microsoft account",
            "netflix", "facebook", "instagram", "twitter", "linkedin", "ebay",
            "fedex", "ups delivery", "dhl express", "usps", "royal mail",
            "bank of america", "chase bank", "wells fargo", "citibank", "hsbc",
            "barclays", "santander", "natwest", "lloyds",
            "internal revenue service", "irs", "social security administration",
            "department of homeland security", "interpol", "europol",
            "world health organization", "united nations",
            "dropbox", "docusign", "adobe sign", "wetransfer",
        ],
    },
    "deception": {
        "label": "Deceptive Tactics",
        "level": "medium",
        "icon": "🎪",
        "description": "Phrases designed to manipulate behavior, bypass skepticism, or avoid scrutiny.",
        "keywords": [
            "do not share this", "keep this confidential", "keep this secret",
            "delete this email", "do not forward", "burn after reading",
            "you have been specially selected", "you have been chosen",
            "congratulations you are", "dear valued customer",
            "dear account holder", "dear user", "dear beneficiary",
            "dear friend", "dear sir", "dear madam", "dear sir/madam",
            "your package is waiting", "delivery attempt failed",
            "click the link below", "click the button below",
            "download the attachment", "open the attachment",
            "we will never ask for your password",
            "this is not spam", "this email is legitimate",
            "100% safe", "guaranteed secure", "verified by",
            "forward this email", "share with your friends",
            "as seen on cnn", "as seen on bbc",
        ],
    },
    # ── New categories ────────────────────────────────────────────────────────
    "attachments": {
        "label": "Suspicious Attachment References",
        "level": "high",
        "icon": "📎",
        "description": "References to file attachments, especially executables or documents with macros, are a primary malware delivery vector.",
        "keywords": [
            "see the attached", "please find attached", "open the attached file",
            "attached invoice", "attached document", "attached receipt",
            "download and run", "run the installer", "execute the file",
            "attached .exe", "attached .zip", "attached .doc", "attached .pdf",
            "scan the attached", "view the attached", "enable macros",
            "enable editing", "enable content", "allow this document",
            "extract the zip", "unzip the file", "password is attached",
            "attachment contains", "file attached",
        ],
    },
    "tech_scam": {
        "label": "Tech Support / Malware Scam",
        "level": "high",
        "icon": "💻",
        "description": "Fake security alerts claiming your device is infected, designed to make you call fraudulent 'support' numbers.",
        "keywords": [
            "your computer is infected", "your device is infected", "virus detected",
            "malware detected", "spyware detected", "ransomware detected",
            "call microsoft", "call apple support", "call our toll-free",
            "windows has detected", "microsoft security alert", "apple security alert",
            "your subscription has expired", "renew your antivirus",
            "your computer has been hacked", "hacker has access to your webcam",
            "your files have been encrypted", "pay to decrypt",
            "remote access", "allow remote connection", "install this software",
            "technical support", "tech support", "call immediately",
            "do not turn off your computer", "do not restart",
        ],
    },
    "job_scam": {
        "label": "Job / Money Mule Scam",
        "level": "medium",
        "icon": "💼",
        "description": "Fake job offers, work-from-home schemes, or requests to receive and forward money on behalf of others.",
        "keywords": [
            "work from home", "work at home", "home-based job", "remote job offer",
            "earn per day", "earn per week", "earn $", "make money online",
            "no experience required", "no experience needed",
            "part time job", "flexible hours", "be your own boss",
            "package forwarding", "parcel forwarding", "reshipping agent",
            "receive payment", "transfer the funds", "keep a commission",
            "money transfer agent", "financial agent", "payment processor",
            "lottery agent", "claims agent", "prize agent",
            "data entry job", "typing job", "easy job", "simple task",
            "multi-level marketing", "mlm", "pyramid scheme",
        ],
    },
    "social_engineering": {
        "label": "Social Engineering",
        "level": "medium",
        "icon": "🧠",
        "description": "Psychological manipulation tactics that exploit trust, authority, or reciprocity to bypass judgment.",
        "keywords": [
            "i am the ceo", "i am a doctor", "i am a lawyer", "i am an agent",
            "on behalf of", "acting on behalf",
            "god bless you", "may god bless", "in god we trust",
            "i need your help", "please help me", "only you can help",
            "i trust you", "you are the only person", "i chose you",
            "our mutual friend", "your friend recommended",
            "strictly confidential", "top secret", "classified information",
            "do not tell anyone", "between you and me",
            "i found your contact", "i got your email from",
            "dying of cancer", "terminal illness", "last wish",
            "refugee", "stranded abroad", "stuck in",
        ],
    },
}

CONTENT_SAFETY_SIGNALS: list = [
    ("unsubscribe", "Contains unsubscribe link — typical of legitimate bulk emails"),
    ("privacy policy", "Mentions privacy policy — sign of compliance"),
    ("terms of service", "References terms of service"),
    ("terms and conditions", "References terms and conditions"),
    ("to stop receiving", "Provides opt-out option"),
    ("if you did not request", "Acknowledges you may not have requested this"),
    ("if you didn't request", "Acknowledges you may not have requested this"),
    ("contact us at", "Provides official contact information"),
    ("© ", "Contains copyright notice"),
    ("all rights reserved", "Contains copyright notice"),
    ("sent from", "Identifies sender system transparently"),
    ("view in browser", "Provides web version link — common in legitimate newsletters"),
    ("manage preferences", "Offers subscription preference management"),
    ("update your preferences", "Offers subscription preference management"),
    ("you are receiving this", "Explains why the email was sent"),
    ("you subscribed", "Acknowledges subscription consent"),
    ("hello [name]", "Personalized greeting (legitimate systems use names)"),
    ("hi [name]", "Personalized greeting"),
]

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "short.link", "rb.gy", "cutt.ly", "is.gd", "buff.ly",
    "ift.tt", "dlvr.it", "wp.me", "tiny.cc", "clck.ru",
    "qr.ae", "su.pr", "lnkd.in", "db.tt", "qr.net",
]

_ASCII_BRAND_TRANSLATION = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
})
_BENIGN_BRAND_LABELS = {
    "apple": {"crabapple", "dapple", "grapple", "pineapple", "snapple"},
}

# Character obfuscation substitution map (leetspeak / homoglyph tricks)
_OBFUSCATION_PAIRS = [
    (r'p[@4]yp[@4]l', 'PayPal'),
    (r'am[@4]z[o0]n', 'Amazon'),
    (r'[a4]ppl[e3]', 'Apple'),
    (r'm[i1]cr[o0]s[o0]ft', 'Microsoft'),
    (r'g[o0][o0]gl[e3]', 'Google'),
    (r'n[e3]tfl[i1]x', 'Netflix'),
    (r'[i1]nst[@a4]gr[@a4]m', 'Instagram'),
    (r'f[@a4]c[e3]b[o0][o0]k', 'Facebook'),
    (r'[l1][o0]g[i1]n', 'login'),
    (r'v[e3]r[i1]fy', 'verify'),
    (r'[a4]cc[o0]unt', 'account'),
    (r'p[@a4]ssw[o0]rd', 'password'),
    (r'b[a4]nk', 'bank'),
]


def _count_urls(links: list[tuple[str, str]]) -> int:
    """Count inspected visible URLs and explicit destinations, not hidden prose."""
    return sum(bool(re.match(r'^https?://', destination, re.IGNORECASE))
               for _visible, destination in links)


def _has_ip_url(text: str, *, links=None) -> bool:
    for _visible, destination in (_extract_links(text) if links is None else links):
        try:
            parsed = _parse_link_target(destination)
            if parsed.scheme in {'http', 'https'} and _is_ip_host(_link_host(parsed)):
                return True
        except ValueError:
            continue
    return False


def _parse_link_target(destination: str, *, base: str | None = None):
    destination = re.sub(r'[\t\r\n]', '', destination.strip())
    destination = re.sub(r'^hxxp(s?)://', r'http\1://', destination, flags=re.IGNORECASE)
    scheme = re.match(r'^([a-z][a-z0-9+.-]*):', destination, re.IGNORECASE)
    if not scheme or scheme.group(1).lower() in {'http', 'https'}:
        # HTTP(S) uses backslashes as separators, but not inside query/fragment.
        # Normalize authority slashes BEFORE joining a base, otherwise urljoin
        # can turn an external host into an apparently same-origin path.
        pieces = re.split(r'([?#])', destination, maxsplit=1)
        pieces[0] = pieces[0].replace('\\', '/')
        destination = ''.join(pieces)
        if scheme:
            protocol = scheme.group(1).lower()
            rest = destination[scheme.end():]
            if not base or protocol != urlparse(base).scheme or rest.startswith('//'):
                destination = protocol + '://' + rest.lstrip('/')
        elif destination.startswith('//'):
            destination = '//' + destination.lstrip('/')
            if not base:
                destination = 'https:' + destination
    if (destination.startswith('//') or re.match(r'^https?://', destination, re.IGNORECASE)):
        if not urlparse(destination).hostname:
            raise ValueError('Explicit HTTP(S) authority has no host')
    if base:
        destination = urljoin(base, destination)
    parsed = urlparse(destination)
    if parsed.scheme in {'http', 'https'}:
        if not parsed.hostname:
            raise ValueError('HTTP(S) destination has no host')
        _ = parsed.port  # Validate ports as well as bracketed address syntax.
    return parsed


def _link_host(parsed) -> str:
    # Decode host escapes only after parsing authority; escaped separators must
    # not become a different userinfo/path boundary.
    return unquote(parsed.hostname or '').lower().rstrip('.')


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Also recognize legacy IPv4 URL forms: one integer, abbreviated dotted
    # components, and hex/octal numbers. Never resolve a hostname on the network.
    parts = host.split('.')
    if not 1 <= len(parts) <= 4:
        return False
    numbers = []
    for part in parts:
        if not re.fullmatch(r'(?:0x[0-9a-f]+|[0-9]+)', part):
            return False
        base = 16 if part.startswith('0x') else 8 if len(part) > 1 and part.startswith('0') else 10
        try:
            numbers.append(int(part, base))
        except ValueError:
            return False
    return all(number <= 255 for number in numbers[:-1]) and numbers[-1] < 256 ** (5 - len(parts))


def _has_shortener_url(text: str, *, links=None) -> bool:
    for _visible, destination in (_extract_links(text) if links is None else links):
        try:
            parsed = _parse_link_target(destination)
            host = _link_host(parsed)
            if parsed.scheme in {'http', 'https'} and any(
                host == shortener or host.endswith('.' + shortener) for shortener in SHORTENER_DOMAINS
            ):
                return True
        except ValueError:
            continue
    return False


def _excessive_caps_ratio(text: str) -> float:
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for c in letters if c.isupper()) / len(letters)


def _detect_obfuscation(text: str) -> list[str]:
    """Detect leetspeak / homoglyph substitution tricks (e.g. P@yP@l, Amaz0n)."""
    found = []
    for pattern, brand in _OBFUSCATION_PAIRS:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            matched = match.group(0).casefold()
            # The permissive patterns intentionally match both the original and
            # substituted spellings. Only report an evasion when normalization
            # actually changes the matched text into the protected term.
            if matched != brand.casefold() and normalize_homoglyphs(matched) == brand.casefold():
                found.append(brand)
                break
    return found


def _keyword_matches(text: str, keyword: str) -> bool:
    """Match phrases while preventing short tokens from firing inside words."""
    escaped = re.escape(keyword)
    prefix = r"(?<!\w)" if keyword and keyword[0].isalnum() else ""
    suffix = r"(?!\w)" if keyword and keyword[-1].isalnum() else ""
    return bool(re.search(prefix + escaped + suffix, text, re.IGNORECASE))


def _strip_invisible_format_controls(text: str) -> str:
    """Remove zero-width formatting controls commonly used to split keywords."""
    return "".join(character for character in text if unicodedata.category(character) != "Cf")


def _large_currency_amounts(text: str) -> list[str]:
    """Find patterns like $5,000,000 or USD 2000000 suggesting implausible winnings."""
    raw = re.finditer(r'(?:\$|usd|gbp|eur|€|£)\s*(\d[\d,.]*)', text, re.IGNORECASE)
    results = []
    for match in raw:
        number = ''.join(str(unicodedata.decimal(ch)) if ch.isdecimal() else ch
                         for ch in match.group(1)).rstrip('.,')
        # Common decimal styles have one/two fractional digits; grouping must
        # consist of three-digit groups. Reject malformed mixed grouping rather
        # than converting punctuation into a much larger integer.
        last_separator = max(number.rfind('.'), number.rfind(','))
        if last_separator >= 0 and len(number) - last_separator - 1 in {1, 2}:
            separator = number[last_separator]
            integer = number[:last_separator]
            if separator in integer:
                continue
        else:
            integer = number
        if '.' in integer or ',' in integer:
            if not (re.fullmatch(r'\d{1,3}(?:,\d{3})+', integer)
                    or re.fullmatch(r'\d{1,3}(?:\.\d{3})+', integer)):
                continue
        # No int/float conversion, including for arbitrarily long digit runs.
        digits = integer.replace(',', '').replace('.', '').lstrip('0')
        if len(digits) >= 5:
            amount = match.group(0).strip()
            results.append(amount[:80] + ('…' if len(amount) > 80 else ''))
            if len(results) == 4:
                break
    return results


def _count_generic_cta(text: str) -> int:
    """Count generic call-to-action phrases that hide real link destinations."""
    patterns = [
        r'\bclick here\b', r'\bclick now\b', r'\bclick below\b',
        r'\bclick this link\b', r'\bpress here\b', r'\btap here\b',
        r'\bfollow this link\b', r'\bopen this link\b',
    ]
    return sum(len(re.findall(p, text, re.IGNORECASE)) for p in patterns)


def _has_generic_salutation(text: str) -> bool:
    """Detect impersonal greetings that suggest bulk phishing campaigns."""
    generics = [
        r'\bdear\s+(sir|madam|sir/madam|customer|user|account\s+holder|'
        r'beneficiary|friend|winner|client|member|valued\s+customer|'
        r'valued\s+member|applicant)\b',
    ]
    return any(re.search(p, text, re.IGNORECASE) for p in generics)


def _detect_non_native_phrases(text: str) -> list[str]:
    """Report regional/formal English variants without treating them as risk."""
    markers = [
        "kindly revert", "kindly do", "kindly note", "kindly confirm",
        "kindly send", "kindly provide", "revert back to me",
        "do the needful", "at the earliest", "i am mr.", "i am mrs.",
        "i am barrister", "i am dr.", "attached herewith",
        "please do the", "for your kind", "your swift response",
        "your prompt response", "be informed that",
        "we wish to inform", "we are pleased to inform",
        "i write to inform", "i write to bring",
        "seeking for", "in need of your",
    ]
    lower = text.lower()
    return [m for m in markers if m in lower]


def _first_html_attributes(attrs):
    """Use HTML's first occurrence of each attribute, including empty values."""
    attributes = {}
    for name, value in attrs:
        attributes.setdefault(name, value)
    return attributes


class _AnalysisHTMLParser(HTMLParser):
    _marked_declaration = re.compile(r'<!\[([a-zA-Z][-_.a-zA-Z0-9]*)')
    _literal_elements = {'textarea', 'title', 'xmp'}
    CDATA_CONTENT_ELEMENTS = (*HTMLParser.CDATA_CONTENT_ELEMENTS, *_literal_elements)

    def set_cdata_mode(self, elem, *, escapable=False):
        # New CPython patch releases pass escapable here. Keep the base parser
        # in raw mode: handle_data owns the one-time RCDATA decoding below.
        # Omitting the keyword also supports older HTMLParser signatures.
        super().set_cdata_mode(elem)
        if elem in self._literal_elements:
            # Only the matching HTML end-tag name leaves RCDATA/RAWTEXT.
            # In particular, </textareax> and </ textarea> remain literal.
            self.interesting = re.compile(r'</' + elem + r'(?=[\t\n\f\r />])', re.I | re.ASCII)

    def parse_endtag(self, index):
        if self.cdata_elem in self._literal_elements:
            # End tags may have (ignored) attributes or a trailing slash. Keep
            # quoted '>' characters inside those attributes, including when
            # input arrives in separate feed() calls.
            ending = re.match(r'''</[a-z]+(?=[\t\n\f\r />])(?:[^'">]|"[^"]*"|'[^']*')*>''',
                              self.rawdata[index:], re.I | re.ASCII)
            if ending is None:
                return -1
            self.handle_endtag(self.cdata_elem)
            self.clear_cdata_mode()
            return index + ending.end()
        return super().parse_endtag(index)

    def handle_startendtag(self, tag, attrs):
        # A self-closing slash does not close a non-void HTML element.
        self.handle_starttag(tag, attrs)
        if tag in _HTML_VOID_ELEMENTS:
            self.handle_endtag(tag)
        elif tag in self.CDATA_CONTENT_ELEMENTS:
            self.set_cdata_mode(tag)

    def handle_data(self, data):
        # RCDATA decodes references once; RAWTEXT preserves them literally.
        # Collectors receive text tokens, never reparse them as nested markup.
        self.collect_data(unescape_html(data) if self.cdata_elem in {'textarea', 'title'} else data)

    def collect_data(self, data):
        pass

    def goahead(self, end):
        super().goahead(end)
        if end and self.cdata_elem in self._literal_elements and self.rawdata:
            # HTMLParser buffers unclosed CDATA even at EOF. A visible textarea
            # or xmp still has text in that case, so do not silently drop it.
            self.handle_data(self.rawdata)
            self.updatepos(0, len(self.rawdata))
            self.rawdata = ''

    def parse_html_declaration(self, index):
        # Recent CPython versions silently consume unknown marked declarations
        # as bogus comments. Detect them at the parser boundary, not by scanning
        # raw HTML (which would also match comments, attributes and scripts).
        if self.rawdata.startswith('<![', index):
            match = self._marked_declaration.match(self.rawdata, index)
            if not match or match.group(1).lower() not in {
                'temp', 'cdata', 'ignore', 'include', 'rcdata', 'if', 'else', 'endif',
            }:
                raise ValueError('Unrecognized HTML marked declaration')
        return super().parse_html_declaration(index)


_MSO_CONDITIONAL_WARNING = (
    'MSO conditional content has client-dependent rendering; analysis is incomplete.'
)


def _expand_mso_comments(text: str, parse_warnings=None) -> str:
    """Expose one bounded layer of conditional markup to every HTML collector.

    Parse actual comment tokens, not comment-like strings in attributes/scripts.
    The expanded document is evidence only, not a verified client rendering.
    Nested or malformed branches retain the incomplete-analysis warning.
    """
    comment_end = re.compile(r'--\s*>')
    offsets = [0]
    offsets.extend(match.end() for match in re.finditer(r'\n', text))

    class ConditionalComments(_AnalysisHTMLParser):
        def __init__(self):
            super().__init__()
            self.replacements = []

        def handle_comment(self, data):
            opening = re.match(r'\[if\s+([^\]]+)\]>', data.strip(), re.IGNORECASE)
            if not opening or not re.search(r'\bmso\b', opening.group(1), re.IGNORECASE):
                return
            condition = re.sub(r'\s+', '', opening.group(1).casefold())
            if (condition.count('(') == condition.count(')')
                    and re.fullmatch(r'\(*(?:!|not)\(*mso\)*', condition)):
                return
            if parse_warnings is not None and _MSO_CONDITIONAL_WARNING not in parse_warnings:
                parse_warnings.append(_MSO_CONDITIONAL_WARNING)
            conditional = re.fullmatch(r'\[if\s+[^\]]+\]>(.*?)<!\[endif\]',
                                       data.strip(), flags=re.IGNORECASE | re.DOTALL)
            if not conditional:
                return
            line, column = self.getpos()
            start = offsets[line - 1] + column
            close = comment_end.search(text, start + 4)
            if close:
                self.replacements.append((start, close.end(), conditional.group(1)))

    scanner = ConditionalComments()
    scanner.feed(text)
    scanner.close()
    parts = []
    cursor = 0
    for start, end, content in scanner.replacements:
        parts.extend((text[cursor:start], content))
        cursor = end
    parts.append(text[cursor:])
    return ''.join(parts)


def _collect_html(factory, text: str, parse_warnings=None):
    collector = factory()
    try:
        collector.feed(_expand_mso_comments(text, parse_warnings))
        collector.close()
    except (AssertionError, ValueError):
        warning = 'Malformed HTML required recovery; analysis is incomplete.'
        if parse_warnings is not None and warning not in parse_warnings:
            parse_warnings.append(warning)
        # Neutralize broken marked declarations, then start fresh so partially
        # collected text/forms/links are neither duplicated nor allowed to hide
        # the rest of the document. Final fallback is literal text, not success.
        collector = factory()
        try:
            collector.feed(_expand_mso_comments(text.replace('<![', '&lt;!['), parse_warnings))
            collector.close()
        except (AssertionError, ValueError):
            collector = factory()
            collector.feed(escape_html(text))
            collector.close()
    return collector


def _extract_links(text: str, *, parse_html: bool = True, parse_warnings=None,
                   visible_text: str | None = None) -> list[tuple[str, str]]:
    """Extract visible text and destination from Markdown and HTML links."""
    # Free-text URLs and Markdown links must come from visible prose, while
    # explicit href/action destinations remain inspectable even when hidden.
    scan_text = (visible_text if visible_text is not None else _visible_content_text(text, parse_warnings)) if parse_html else text
    links = list(re.findall(r'\[([^\]]+)\]\(((?:https?|hxxps?)://[^)]+)\)', scan_text, re.IGNORECASE))

    class LinkCollector(_AnalysisHTMLParser):
        def __init__(self):
            super().__init__()
            self.href = None
            self.label_markup = []
            self.links = []
            self.base_href = None

        def finish_anchor(self):
            if self.href is not None:
                self.links.append((_visible_content_text(''.join(self.label_markup)), self.href))
            self.href = None
            self.label_markup = []

        def handle_starttag(self, tag, attrs):
            attrs = list(_first_html_attributes(attrs).items())
            attributes = dict(attrs)
            if tag == 'base' and self.base_href is None and 'href' in attributes:
                self.base_href = attributes['href'] or ''
            if tag == 'form' and attributes.get('action'):
                self.links.append(('', attributes['action']))
            if tag in {'input', 'button'} and attributes.get('formaction') and 'disabled' not in attributes:
                self.links.append(('', attributes['formaction']))
            if tag.lower() == "a":
                if self.href is not None:
                    self.finish_anchor()
                self.href = next((value for name, value in attrs if name == 'href'), None)
                self.label_markup = [self.get_starttag_text() or '<a>']
            elif self.href is not None:
                self.label_markup.append(self.get_starttag_text() or f'<{tag}>')

        def collect_data(self, data):
            if self.href is not None:
                self.label_markup.append(escape_html(data))

        def handle_endtag(self, tag):
            if self.href is not None:
                self.label_markup.append(f'</{tag}>')
                if tag.lower() == 'a':
                    self.finish_anchor()

    collector = _collect_html(LinkCollector, text, parse_warnings) if parse_html else LinkCollector()
    try:
        if collector.href is not None:
            collector.finish_anchor()
        base = None
        try:
            candidate = _parse_link_target(collector.base_href or '')
            if candidate.scheme in {'http', 'https'} and candidate.hostname:
                base = candidate.geturl()
        except ValueError:
            pass
        for visible, destination in collector.links:
            try:
                # Only resolve HTML targets, not unrelated plain-text URLs.
                # Keep obfuscated schemes intact for their existing indicator.
                resolved = (_parse_link_target(destination, base=base).geturl()
                            if base and not re.match(r'^hxxps?:', destination, re.IGNORECASE)
                            else destination)
            except ValueError:
                resolved = destination  # Preserve malformed-target evidence.
            links.append((visible, resolved))
    except Exception:
        pass

    links.extend(
        ("", url.rstrip(".,;:)"))
        for url in re.findall(r"(?:https?|hxxps?)://[^\s<>\"']+", scan_text, re.IGNORECASE)
    )

    return [
        (str(visible or "").strip(), str(destination or "").strip())
        for visible, destination in links
        if destination
    ]


def _visible_link_host(link_text: str) -> str:
    match = re.search(
        r"(?:https?://|www\.)?"
        r"((?:xn--)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        r"(?:\.(?:xn--)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)",
        link_text,
        re.IGNORECASE,
    )
    return match.group(1).lower().rstrip(".") if match else ""


def _known_link_host(host: str) -> bool:
    return any(host == known or host.endswith("." + known) for known in LEGIT_PROVIDERS)


def _label_uses_brand_lookalike(label: str, brand: str) -> bool:
    """Match protected brands after separator and common digit normalization."""
    skeleton = _confusable_skeleton(label)
    translated = skeleton.translate(_ASCII_BRAND_TRANSLATION)
    tokens = [
        re.sub(r"[^a-z]", "", token)
        for token in re.findall(r"[a-z0-9]+", translated)
    ]
    if brand in tokens:
        return True
    compact = re.sub(r"[^a-z]", "", translated)
    if compact in _BENIGN_BRAND_LABELS.get(brand, set()):
        return False
    return brand in compact


def _analyze_link_destinations(text: str, *, links=None, parse_warnings=None) -> tuple[int, list[dict], str]:
    """Inspect actual link targets, including links with generic button text."""
    score = 0
    findings: list[dict] = []
    risk_floor = "safe"
    finding_types: set[str] = set()
    sensitive_host_terms = {
        "account", "credential", "login", "password", "reactivate",
        "secure", "security", "signin", "unlock", "verification", "verify",
        "wallet",
    }

    for link_text, url in (_extract_links(text) if links is None else links):
        lowered_url = url.lower()
        if lowered_url.startswith(("hxxp://", "hxxps://")):
            if "obfuscated-scheme" not in finding_types:
                score += 3
                risk_floor = "high"
                finding_types.add("obfuscated-scheme")
                findings.append({
                    "level": "high",
                    "msg": "Link uses an obfuscated hxxp/hxxps destination scheme.",
                })
            if lowered_url.startswith("hxxps://"):
                url = "https://" + url[8:]
            else:
                url = "http://" + url[7:]
        try:
            parsed = _parse_link_target(url)
        except ValueError:
            warning = 'A link destination could not be reliably parsed; analysis is incomplete.'
            if parse_warnings is not None and warning not in parse_warnings:
                parse_warnings.append(warning)
            if "malformed-target" not in finding_types:
                score += 2
                if risk_floor == "safe":
                    risk_floor = "medium"
                finding_types.add("malformed-target")
                findings.append({
                    "level": "medium",
                    "msg": "Link contains a malformed destination that could not be safely parsed.",
                })
            continue
        if parsed.scheme.lower() not in {"http", "https"}:
            if parsed.scheme.lower() in {"data", "file", "javascript"} and "unsafe-scheme" not in finding_types:
                score += 5
                risk_floor = "high"
                finding_types.add("unsafe-scheme")
                findings.append({
                    "level": "high",
                    "msg": f"Link uses an unsafe destination scheme ({parsed.scheme.lower()}:).",
                })
            continue

        if (
            bool(parsed.username or parsed.password)
            and "url-userinfo" not in finding_types
        ):
            score += 5
            risk_floor = "high"
            finding_types.add("url-userinfo")
            findings.append({
                "level": "high",
                "msg": (
                    "Link destination uses URL userinfo before the real host, "
                    "a common trusted-domain deception technique."
                ),
            })

        target_host = _link_host(parsed)
        if not target_host:
            continue
        if _is_ip_host(target_host) and 'ip-host' not in finding_types:
            score += 3
            risk_floor = 'high'
            finding_types.add('ip-host')
            findings.append({
                'level': 'high',
                'msg': 'Link destination uses an IP address instead of a domain name; inspect it before opening.',
            })
        decoded_host = _decode_idna_domain(target_host)

        visible_host = _visible_link_host(link_text)
        if (
            visible_host
            and not _domains_align(
                _decode_idna_domain(visible_host),
                decoded_host,
            )
            and "display-mismatch" not in finding_types
        ):
            score += 3
            risk_floor = "high"
            finding_types.add("display-mismatch")
            findings.append({
                "level": "high",
                "msg": (
                    f"Link display domain ({visible_host}) does not match the "
                    f"actual destination ({target_host})."
                ),
            })

        decoded_skeleton = _confusable_skeleton(decoded_host)
        first_label = decoded_skeleton.split(".", 1)[0]
        decoded_labels = [label for label in decoded_host.split(".") if label]
        for brand, canonical_domains in _PROTECTED_BRAND_DOMAINS.items():
            canonical = any(_domains_align(target_host, domain) for domain in canonical_domains)
            if (
                brand in first_label
                and not canonical
                and (
                    target_host.startswith("xn--")
                    or decoded_skeleton != decoded_host.casefold()
                )
                and "idn-confusable" not in finding_types
            ):
                score += 5
                risk_floor = "high"
                finding_types.add("idn-confusable")
                findings.append({
                    "level": "high",
                    "msg": (
                        f"Link destination ({target_host}) is an IDN/confusable "
                        f"lookalike for {brand}."
                    ),
                })
            elif (
                not canonical
                and any(
                    _label_uses_brand_lookalike(label, brand)
                    for label in decoded_labels
                )
                and "brand-lookalike" not in finding_types
            ):
                score += 5
                risk_floor = "high"
                finding_types.add("brand-lookalike")
                findings.append({
                    "level": "high",
                    "msg": (
                        f"Link destination ({target_host}) is a noncanonical "
                        f"lookalike for {brand}."
                    ),
                })

        host_tokens = set(re.findall(r"[a-z0-9]+", decoded_skeleton))
        credential_collection = bool(
            host_tokens & {"credential", "password", "passcode", "otp"}
            and host_tokens & {"capture", "harvest", "steal"}
        )
        host_finding = "credential-collection-host" if credential_collection else "sensitive-host"
        if (
            not _known_link_host(target_host)
            and host_tokens & sensitive_host_terms
            and host_finding not in finding_types
        ):
            # Login/account labels are ordinary on legitimate custom domains.
            # Keep them as weak context, not a stand-alone high-risk verdict.
            score += 4 if credential_collection else 2
            if credential_collection:
                risk_floor = "high"
            finding_types.add(host_finding)
            findings.append({
                "level": "high" if credential_collection else "low",
                "msg": (
                    f"Link destination ({target_host}) combines credential and collection wording."
                    if credential_collection else
                    f"Link destination ({target_host}) uses account-related wording on an "
                    "unrecognized domain; this alone does not establish phishing."
                ),
            })

    return score, findings, risk_floor


def _has_mismatched_link_text(text: str) -> bool:
    """Compatibility wrapper for callers that only need a mismatch boolean."""
    _score, findings, _floor = _analyze_link_destinations(text)
    return any("does not match" in finding["msg"] for finding in findings)


_HIDDEN_HTML_TEXT_WARNING = (
    'Hidden HTML text was excluded from text scoring; visual rendering was not '
    'fully verified, so analysis is incomplete.'
)
_STYLESHEET_VISIBILITY_WARNING = (
    'A stylesheet may hide or reveal text; CSS rendering was not verified, '
    'so the affected text-model view was not scored.'
)
_INLINE_CSS_VISIBILITY_WARNING = (
    'Inline CSS may conceal text; its rendering was not verified, '
    'so the affected text-model view was not scored.'
)
_IMAGE_ALT_FALLBACK_WARNING = (
    'Image alternative text may be shown when an image is unavailable; '
    'that rendering was not verified, so the affected text-model view was not scored.'
)
_MIME_ALTERNATIVE_LIMIT_WARNING = (
    'MIME alternative view limit reached; not every rendered version was model-scored. '
    'Analysis is incomplete.'
)
_MIME_ALTERNATIVE_MODEL_WARNING = (
    'At least one MIME alternative could not be model-scored; analysis is incomplete.'
)
_MAX_MIME_MODEL_VIEWS = 16
_HTML_VOID_ELEMENTS = {
    'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta',
    'param', 'source', 'track', 'wbr',
}
_P_IMPLIED_END_START_TAGS = {
    'address', 'article', 'aside', 'blockquote', 'details', 'dialog', 'div',
    'dl', 'fieldset', 'figcaption', 'figure', 'footer', 'form', 'h1', 'h2',
    'h3', 'h4', 'h5', 'h6', 'header', 'hgroup', 'hr', 'main', 'menu', 'nav',
    'ol', 'p', 'pre', 'search', 'section', 'table', 'ul',
}


def _inline_visibility(style: str) -> tuple[bool, bool | None, bool, bool]:
    """Read bounded visibility declarations, respecting !important."""
    # A semicolon inside quoted content, url(), or a CSS escape is not a
    # declaration boundary. Splitting it blindly can hide genuinely visible
    # text when an unrelated property contains the string "; display:none".
    declarations = []
    current = []
    quote = None
    depth = 0
    index = 0
    while index < len(style):
        character = style[index]
        following = style[index + 1] if index + 1 < len(style) else ''
        if quote:
            current.append(character)
            if character == '\\' and following:
                current.append(following)
                index += 1
            elif character == quote:
                quote = None
        elif character == '/' and following == '*':
            ending = style.find('*/', index + 2)
            if ending < 0:
                break
            index = ending + 1
        elif character == '\\' and following:
            current.extend((character, following))
            index += 1
        elif character in {'"', "'"}:
            quote = character
            current.append(character)
        elif character == '(':
            depth += 1
            current.append(character)
        elif character == ')':
            depth = max(0, depth - 1)
            current.append(character)
        elif character == ';' and depth == 0:
            declarations.append(''.join(current))
            current = []
        else:
            current.append(character)
        index += 1
    declarations.append(''.join(current))
    values = {}
    for declaration in declarations:
        name, separator, value = declaration.partition(':')
        name = _unescape_css(name).strip().lower()
        if not separator or name not in {'display', 'visibility', 'opacity', 'font-size', 'color'}:
            continue
        value = _unescape_css(value).strip().lower()
        important = bool(re.search(r'!\s*important\s*$', value))
        value = re.sub(r'!\s*important\s*$', '', value).strip()
        if name not in values or important or not values[name][1]:
            values[name] = (value, important)
    display_hidden = values.get('display', ('', False))[0] == 'none'
    visibility = values.get('visibility', ('', False))[0]
    if visibility in {'hidden', 'collapse'}:
        visibility_hidden = True
    elif visibility in {'visible', 'initial'}:
        visibility_hidden = False
    else:
        # inherit/unset/invalid values cannot clear a hidden parent.
        visibility_hidden = None
    opacity = values.get('opacity', ('', False))[0]
    # Zero opacity applies to the entire rendered subtree; children cannot
    # restore it with their own opacity declaration.
    opacity_number = opacity.removesuffix('%')
    opacity_hidden = bool(
        re.fullmatch(r'[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?', opacity_number)
        and float(opacity_number) <= 0
    ) or bool(re.fullmatch(r'calc\(\s*[+-]?0+(?:\.0+)?%?\s*\)', opacity))
    font_size = values.get('font-size', ('', False))[0]
    color = values.get('color', ('', False))[0]
    uncertain = bool(
        re.fullmatch(r'[+]?0+(?:\.0+)?(?:[a-z]+|%)?', font_size)
        or color == 'transparent'
        or re.fullmatch(r'(?:rgba|hsla)\([^)]*,\s*0+(?:\.0+)?\s*\)', color)
        or (opacity.startswith('calc(') and not opacity_hidden)
    )
    return display_hidden, visibility_hidden, opacity_hidden, uncertain


def _stylesheet_may_hide_text(css: str) -> bool:
    """Flag hiding declarations without claiming to implement CSS cascade."""
    # Remove real comments while preserving comment-like text in CSS strings.
    without_comments = []
    quote = None
    index = 0
    while index < len(css):
        character = css[index]
        following = css[index + 1] if index + 1 < len(css) else ''
        if quote:
            without_comments.append(character)
            if character == '\\' and following:
                without_comments.append(following)
                index += 1
            elif character == quote:
                quote = None
        elif character == '/' and following == '*':
            ending = css.find('*/', index + 2)
            if ending < 0:
                break
            index = ending + 1
        elif character in {'"', "'"}:
            quote = character
            without_comments.append(character)
        else:
            without_comments.append(character)
        index += 1
    # Find balanced rule bodies outside quoted CSS strings. A brace in
    # content:"}" must not end the rule before its hiding declaration.
    cleaned = ''.join(without_comments)
    depth = 0
    segment_start = 0
    quote = None
    index = 0
    while index < len(cleaned):
        character = cleaned[index]
        if character == '\\' and index + 1 < len(cleaned):
            index += 2
            continue
        if quote:
            if character == quote:
                quote = None
        elif character in {'"', "'"}:
            quote = character
        elif character == '{':
            if depth:
                display, visibility, opacity, uncertain = _inline_visibility(
                    cleaned[segment_start:index]
                )
                if display or visibility is True or opacity or uncertain:
                    return True
            depth += 1
            segment_start = index + 1
        elif character == '}' and depth:
            display, visibility, opacity, uncertain = _inline_visibility(
                cleaned[segment_start:index]
            )
            if display or visibility is True or opacity or uncertain:
                return True
            depth -= 1
            segment_start = index + 1
        index += 1
    return False


def _visible_content_text(text: str, parse_warnings=None, *, structure_stats=None) -> str:
    """Decode HTML text separately from destinations, preserving inline words."""
    class TextCollector(_AnalysisHTMLParser):
        head_elements = {'html', 'head', 'base', 'basefont', 'bgsound', 'link',
                         'meta', 'title', 'noscript', 'noframes', 'script', 'style', 'template'}

        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.parts = []
            self.hidden = []
            self.elements = []
            self.excluded_hidden_text = False
            self.hidden_characters = 0
            self.linked_visible_images = 0
            self.stylesheet_parts = []
            self.conditional_image_alt = False
            self.uncertain_inline_style = False
            self.open_paragraph = False

        def _visually_hidden(self):
            return bool(self.elements and (self.elements[-1][1] or self.elements[-1][2]))

        def _truncate_elements(self, index):
            if self.open_paragraph and any(item[0] == 'p' for item in self.elements[index:]):
                self.open_paragraph = False
            del self.elements[index:]

        def _implicitly_close(self, tag):
            if tag in {'td', 'th', 'tr'}:
                for index in range(len(self.elements) - 1, -1, -1):
                    existing = self.elements[index][0]
                    if existing == 'table':
                        break
                    if tag in {'td', 'th'} and existing == 'tr':
                        break
                    if existing in ({'td', 'th'} if tag in {'td', 'th'} else {'tr'}):
                        self._truncate_elements(index)
                        break
            if self.open_paragraph and tag in _P_IMPLIED_END_START_TAGS:
                for index in range(len(self.elements) - 1, -1, -1):
                    if self.elements[index][0] == 'p':
                        self._truncate_elements(index)
                        break
            if tag == 'li':
                for index in range(len(self.elements) - 1, -1, -1):
                    existing = self.elements[index][0]
                    if existing in {'ul', 'ol', 'menu'}:
                        break
                    if existing == 'li':
                        self._truncate_elements(index)
                        break
            if tag in {'dt', 'dd'}:
                for index in range(len(self.elements) - 1, -1, -1):
                    existing = self.elements[index][0]
                    if existing == 'dl':
                        break
                    if existing in {'dt', 'dd'}:
                        self._truncate_elements(index)
                        break

        def handle_starttag(self, tag, attrs):
            attrs = list(_first_html_attributes(attrs).items())
            # A head end tag is optional: body content implicitly closes it.
            # Do not do this inside title/script/style or inert template text.
            if self.hidden == ['head'] and tag not in self.head_elements:
                self.hidden.pop()
            if tag == 'head' and 'head' in self.hidden:
                return
            if tag in {'script', 'style', 'head', 'title', 'template', 'noframes'}:
                self.hidden.append(tag)
            if self.hidden:
                return
            self._implicitly_close(tag)
            if tag == 'a':
                # HTML closes a prior anchor when another anchor starts. Do not
                # inherit an old HTTP action through a nested mailto/fragment link.
                self.elements = [(*element[:4], False) if element[0] == 'a' else element
                                 for element in self.elements]
            # Browsers retain the first duplicate attribute, not the last.
            style = next((value for name, value in attrs if name == 'style'), '')
            display_hidden, visibility_hidden, opacity_hidden, uncertain_style = _inline_visibility(style or '')
            parent_display = self.elements[-1][1] if self.elements else False
            parent_visibility = self.elements[-1][2] if self.elements else False
            element_display = (parent_display or any(name == 'hidden' for name, _ in attrs)
                               or display_hidden or opacity_hidden)
            element_visibility = parent_visibility if visibility_hidden is None else visibility_hidden
            if uncertain_style and not (element_display or element_visibility):
                self.uncertain_inline_style = True
            if tag == 'source' and any(name == 'srcset' and value and value.strip()
                                       for name, value in attrs):
                for index in range(len(self.elements) - 1, -1, -1):
                    if self.elements[index][0] == 'picture':
                        picture = self.elements[index]
                        self.elements[index] = (*picture[:3], True, *picture[4:])
                        break
            if (tag == 'img' and not element_display and not element_visibility
                    and any(element[4] for element in self.elements)
                    and any(name in {'src', 'srcset'} and value and value.strip() for name, value in attrs)):
                self.linked_visible_images += 1
            if tag == 'img':
                alt = next((value for name, value in attrs if name == 'alt'), '') or ''
                if alt.strip():
                    if element_display or element_visibility:
                        self.excluded_hidden_text = True
                    elif (not any(name in {'src', 'srcset'} and value and value.strip()
                                  for name, value in attrs)
                          and not any(element[0] == 'picture' and element[3]
                                      for element in self.elements)):
                        # With no image resource, HTML's replacement text is
                        # the text the reader can see or hear.
                        self.parts.extend((' ', alt, ' '))
                    else:
                        # A two-word decorative label such as "Company logo"
                        # should not disable scoring of an otherwise text-rich
                        # email. Longer fallback instructions may change what a
                        # reader sees when images fail or are blocked.
                        self.conditional_image_alt |= (
                            bool(re.search(
                                r'\b(?:enter|provide|send|share|submit|type|verify|confirm|reset|update)\s+'
                                r'(?:(?:your|the|a)\s+)?(?:password|passcode|otp|one-time password|'
                                r'credit card number|account)\b', alt, re.IGNORECASE,
                            ))
                            or (sum(not char.isspace() for char in alt) >= 12
                                and (len(re.findall(r'\w+', alt, flags=re.UNICODE)) >= 3
                                     or bool(non_latin_script_segments(alt, 12))))
                        )
            if tag not in _HTML_VOID_ELEMENTS:
                href = dict(attrs).get('href') or ''
                actionable_anchor = False
                if tag == 'a' and re.sub(r'[\t\r\n]', '', href).strip().lower().startswith(('http://', 'https://')):
                    try:
                        target = _parse_link_target(href)
                        actionable_anchor = target.scheme.lower() in {'http', 'https'} and bool(target.hostname)
                    except ValueError:
                        pass
                self.elements.append((tag, element_display, element_visibility, False, actionable_anchor))
                if tag == 'p':
                    self.open_paragraph = True
            if not element_display and not element_visibility and tag in {'p', 'div', 'br', 'li', 'tr', 'td', 'hr', 'section'}:
                self.parts.append(' ')

        def handle_endtag(self, tag):
            if self.hidden == ['head'] and tag in {'body', 'html', 'br'}:
                self.hidden.pop()
            if self.hidden and tag == self.hidden[-1]:
                self.hidden.pop()
                return
            for index in range(len(self.elements) - 1, -1, -1):
                if self.elements[index][0] == tag:
                    self._truncate_elements(index)
                    break
            if not self.hidden and not self._visually_hidden() and tag in {'p', 'div', 'li', 'tr', 'td', 'section'}:
                self.parts.append(' ')

        def collect_data(self, data):
            if self.hidden == ['head'] and data.strip():
                self.hidden.pop()
            if self.hidden:
                if self.hidden[-1] == 'style' and 'template' not in self.hidden[:-1]:
                    self.stylesheet_parts.append(data)
                return
            if self._visually_hidden():
                self.hidden_characters += sum(not char.isspace() for char in _strip_invisible_format_controls(data))
                if data.strip():
                    self.excluded_hidden_text = True
            else:
                self.parts.append(data)

    collector = _collect_html(TextCollector, text, parse_warnings)
    if collector.excluded_hidden_text and parse_warnings is not None:
        parse_warnings.append(_HIDDEN_HTML_TEXT_WARNING)
    if parse_warnings is not None and _stylesheet_may_hide_text(''.join(collector.stylesheet_parts)):
        parse_warnings.append(_STYLESHEET_VISIBILITY_WARNING)
    if collector.uncertain_inline_style and parse_warnings is not None:
        parse_warnings.append(_INLINE_CSS_VISIBILITY_WARNING)
    if collector.conditional_image_alt and parse_warnings is not None:
        parse_warnings.append(_IMAGE_ALT_FALLBACK_WARNING)
    visible = re.sub(r'\s+', ' ', ''.join(collector.parts)).strip()
    if structure_stats is not None:
        structure_stats.update(hidden_characters=collector.hidden_characters,
                               visible_characters=sum(not char.isspace() for char in _strip_invisible_format_controls(visible)),
                               linked_visible_images=collector.linked_visible_images)
    return visible


_INLINE_IMAGE_WARNING = 'Embedded image content was not inspected; analysis is incomplete.'
_REMOTE_IMAGE_WARNING = 'Remote image content was not inspected; analysis is incomplete.'
_UNRESOLVED_IMAGE_WARNING = 'Unresolved image references were not inspected; analysis is incomplete.'
_HAN_TEXT_WARNING = ('Substantial Han-script text detected; language-specific phishing checks '
                     'are limited and this content may not be fully evaluated.')
_REMOTE_IMAGE_MIN_VISIBLE_CHARS = 80


def _unescape_css(value: str) -> str:
    value = re.sub(r'\\(?:\r\n|[\n\r\f])', '', value)
    def replacement(match):
        if match.group(1):
            codepoint = int(match.group(1), 16)
            return chr(codepoint) if 0 < codepoint <= 0x10ffff else '\ufffd'
        return match.group(2)

    return re.sub(r'\\(?:([0-9a-fA-F]{1,6})(?:[ \t\n\r\f])?|([^\n\r\f]))',
                  replacement, value)


def _mask_inline_data_payloads(text: str) -> str:
    """Keep image data bytes out of URL scans without hiding real destinations."""
    def mask_css_url(match):
        normalized = _unescape_css(match.group(0))
        if re.search(r'url\(\s*[\'\"]?\s*data:image/', normalized, re.IGNORECASE):
            return 'url(data:image/opaque)'
        return match.group(0)

    css_url = r"""url\(\s*(?:"(?:\\.|[^"<>])*"|'(?:\\.|[^'<>])*'|(?:\\.|[^)'"<>])*)\s*\)"""
    text = re.sub(css_url, mask_css_url, text, flags=re.IGNORECASE)
    return re.sub(r'data:image/[^\s\'"<>)]*', 'data:image/opaque', text, flags=re.IGNORECASE)


def _image_reference_counts(text: str, parse_warnings=None) -> tuple[int, int, int]:
    """Count embedded, remote, and unresolved image references without inspecting pixels."""
    data_image = re.compile(r'^\s*data:image/[a-z0-9.+-]+', re.IGNORECASE)
    data_css = re.compile(r'url\(\s*[\'\"]?\s*data:image/[a-z0-9.+-]+', re.IGNORECASE)
    remote_image = re.compile(r'^\s*(?:https?:)?//', re.IGNORECASE)
    remote_css = re.compile(r'url\(\s*[\'\"]?\s*(?:https?:)?//', re.IGNORECASE)
    css_url = re.compile(r'url\(\s*[\'\"]?([^\'\")\s]+)', re.IGNORECASE)

    def srcset_urls(value):
        """Read URL tokens without treating a data URI's comma as a separator."""
        position = 0
        while position < len(value):
            while position < len(value) and value[position] in ' \t\n\r\f,':
                position += 1
            start = position
            while position < len(value) and not value[position].isspace():
                position += 1
            token = value[start:position]
            if token.rstrip(','):
                yield token.rstrip(',')
            if not token.endswith(','):
                depth = 0
                while position < len(value):
                    character = value[position]
                    position += 1
                    if character == '(':
                        depth += 1
                    elif character == ')':
                        depth = max(0, depth - 1)
                    elif character == ',' and depth == 0:
                        break

    class ImageCollector(_AnalysisHTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.data_count = 0
            self.remote_count = 0
            self.unresolved_count = 0
            self.in_style = False
            self.in_script = False
            self.remote_base = None

        def is_remote(self, value):
            if remote_image.match(value):
                return True
            if not self.remote_base or data_image.match(value) or value.lstrip().startswith('#'):
                return False
            try:
                return bool(remote_image.match(urljoin(self.remote_base, value)))
            except ValueError:
                return False

        def add_reference(self, value):
            if data_image.match(value):
                self.data_count = min(20, self.data_count + 1)
            elif self.is_remote(value):
                self.remote_count = min(20, self.remote_count + 1)
            elif value.strip() and not value.lstrip().lower().startswith(('data:', '#')):
                self.unresolved_count = min(20, self.unresolved_count + 1)

        def add_css(self, value):
            without_comments = re.sub(r'/\*.*?\*/', '', value, flags=re.DOTALL)
            normalized = _unescape_css(without_comments)
            self.data_count = min(20, self.data_count + len(data_css.findall(normalized)))
            self.remote_count = min(20, self.remote_count + len(remote_css.findall(normalized)))
            for match in css_url.finditer(normalized):
                value = match.group(1)
                if not (data_image.match(value) or remote_image.match(value)):
                    self.add_reference(value)

        def handle_starttag(self, tag, attrs):
            attrs = list(_first_html_attributes(attrs).items())
            if tag == 'script':
                self.in_script = True
                return
            if self.in_script:
                return
            if tag == 'style':
                self.in_style = True
            if tag == 'base':
                href = dict(attrs).get('href') or ''
                if remote_image.match(href):
                    self.remote_base = href
            for name, value in attrs:
                if not value:
                    continue
                if tag in {'img', 'source', 'v:imagedata', 'v:fill', 'image'}:
                    if name == 'src':
                        if tag != 'source' or data_image.match(value):
                            self.add_reference(value)
                    elif tag == 'image' and name in {'href', 'xlink:href'}:
                        self.add_reference(value)
                    elif name == 'srcset':
                        for url in srcset_urls(value):
                            self.add_reference(url)
                if name == 'background' and tag in {'body', 'table', 'td', 'th'}:
                    self.add_reference(value)
                if name == 'style':
                    self.add_css(value)

        def handle_endtag(self, tag):
            if tag == 'style':
                self.in_style = False
            elif tag == 'script':
                self.in_script = False

        def collect_data(self, data):
            if self.in_style and not self.in_script:
                self.add_css(data)

    collector = _collect_html(ImageCollector, text, parse_warnings)
    return collector.data_count, collector.remote_count, collector.unresolved_count


def _has_password_form(text: str, parse_warnings=None) -> bool:
    class FormCollector(_AnalysisHTMLParser):
        def __init__(self):
            super().__init__()
            self.depth = 0
            self.form_ids = set()
            self.password_forms = []

        def handle_starttag(self, tag, attrs):
            attrs = list(_first_html_attributes(attrs).items())
            attributes = dict(attrs)
            if tag == 'form':
                self.depth += 1
                if attributes.get('id'):
                    self.form_ids.add(attributes['id'])
            if tag == 'input' and (attributes.get('type') or '').lower() == 'password' and 'disabled' not in attributes:
                self.password_forms.append((self.depth > 0, attributes.get('form')))

        def handle_endtag(self, tag):
            if tag == 'form':
                self.depth = max(0, self.depth - 1)

    collector = _collect_html(FormCollector, text, parse_warnings)
    return any(in_form if form_id is None else form_id in collector.form_ids
               for in_form, form_id in collector.password_forms)


def _has_pressured_credential_request(text: str) -> bool:
    """Narrow conjunction, not a blanket penalty for password-reset notices."""
    pattern = r'\b(?:enter|provide|send|share|submit)\s+(?:(?:your|the)\s+)?(?:password|passcode|one-time password|otp code|credit card number)\b'
    for match in re.finditer(pattern, text, re.IGNORECASE):
        prefix = re.split(r'[.!?;]', text[max(0, match.start() - 100):match.start()])[-1]
        if re.search(r"\b(?:never(?:\s+ask(?:\s+you)?\s+to)?|do not|don't|must not|should not|will not|won't|not to)(?:\s+(?:ever|directly))?\s*$", prefix, re.IGNORECASE):
            continue
        context = text[max(0, match.start() - 240):match.end() + 240].lower()
        if all(any(_keyword_matches(context, keyword) for keyword in CONTENT_RULES[key]['keywords'])
               for key in ('urgency', 'threats')):
            return True
    return False


def analyze_email_content(subject: str, body: str, *, content_parts: list[dict] | None = None,
                          _model_view: dict | None = None) -> dict:
    """Rule-based heuristic phishing analysis of email subject + body text."""
    analysis_warnings = []

    hidden_image_padding = []

    def visible_html(part):
        part_warnings = []
        stats = {}
        visible = _visible_content_text(part, part_warnings, structure_stats=stats)
        # Require a large explicitly concealed block and an actionable image in
        # this same HTML document. Short preheaders and text-rich mail do not qualify.
        hidden_image_padding.append(
            stats['hidden_characters'] >= 500
            and stats['visible_characters'] < _REMOTE_IMAGE_MIN_VISIBLE_CHARS
            and stats['hidden_characters'] >= 10 * max(stats['visible_characters'], 1)
            and stats['linked_visible_images'] > 0
            and not any(warning in part_warnings for warning in (
                _STYLESHEET_VISIBILITY_WARNING, _INLINE_CSS_VISIBILITY_WARNING,
                _MSO_CONDITIONAL_WARNING))
            and not any('malformed' in warning.lower() or 'recovery' in warning.lower()
                        for warning in part_warnings))
        analysis_warnings.extend(part_warnings)
        stylesheet_uncertain = any(warning in part_warnings for warning in (
            _STYLESHEET_VISIBILITY_WARNING, _INLINE_CSS_VISIBILITY_WARNING,
        ))
        return (visible, stylesheet_uncertain,
                stylesheet_uncertain or any(warning in part_warnings for warning in (
                    _IMAGE_ALT_FALLBACK_WARNING, _MSO_CONDITIONAL_WARNING,
                )))

    if content_parts is None:
        raw_parts = [subject, body]
        html_parts = [False, True]
        parsed_parts = [(subject, False, False), visible_html(body)]
        visible_parts = [visible for visible, _css_uncertain, _model_uncertain in parsed_parts]
        stylesheet_uncertain_parts = [uncertain for _visible, uncertain, _model in parsed_parts]
    else:
        # Each MIME part is its own document. Plain text must not be interpreted
        # as markup, nor may an unclosed tag in one part hide another part.
        raw_parts = [subject] + [part['content'] for part in content_parts]
        html_parts = [False] + [part['content_type'] == 'text/html' for part in content_parts]
        parsed_parts = [visible_html(part['content']) if part['content_type'] == 'text/html'
                        else (part['content'], False, False) for part in content_parts]
        visible_parts = [subject] + [visible for visible, _css_uncertain, _model_uncertain
                                     in parsed_parts]
        stylesheet_uncertain_parts = [False] + [uncertain for _visible, uncertain, _model
                                                  in parsed_parts]
        model_uncertain_parts = [False] + [uncertain for _visible, _css, uncertain
                                           in parsed_parts]
    raw_parts = [_strip_invisible_format_controls(part) for part in raw_parts]
    if _model_view is not None:
        # The model and rule checks consume the same MIME-aware visible text.
        model_parts = [re.sub(r'\s+', ' ', _strip_invisible_format_controls(part)).strip()
                       for part in visible_parts]
        _model_view['subject'] = model_parts[0]
        _model_view['body'] = '\n'.join(model_parts[1:]).strip()
        if content_parts is not None:
            _model_view['mime_views'] = [(_model_view['body'], any(model_uncertain_parts[1:]))]
            choices = {}
            for part in content_parts:
                for path in part.get('alternative_paths', [()]):
                    for group, branch in path:
                        choices.setdefault(group, set()).add(branch)
            if choices:
                groups = sorted(choices)
                views = {}
                defaults = tuple(min(choices[group]) for group in groups)
                combinations = 1
                for group in groups:
                    combinations *= len(choices[group])
                    if combinations > _MAX_MIME_MODEL_VIEWS:
                        _model_view['mime_alternatives_truncated'] = True
                        break
                # Cover a leaf from each branch before spending the remaining
                # budget on Cartesian combinations. Nested decoys must not
                # starve a later, shallower phishing alternative.
                paths = {tuple(path) for part in content_parts
                         for path in part.get('alternative_paths', [()])}
                assignments = [defaults]
                for path in sorted(paths, key=lambda item: (len(item), item)):
                    selected = dict(zip(groups, defaults))
                    selected.update(path)
                    branches = tuple(selected[group] for group in groups)
                    if branches not in assignments:
                        assignments.append(branches)
                    if len(assignments) == _MAX_MIME_MODEL_VIEWS:
                        break
                if len(assignments) < _MAX_MIME_MODEL_VIEWS:
                    for branches in product(*(sorted(choices[group]) for group in groups)):
                        if branches not in assignments:
                            assignments.append(branches)
                        if len(assignments) == _MAX_MIME_MODEL_VIEWS:
                            break
                for branches in assignments:
                    selected = dict(zip(groups, branches))
                    included = [
                        any(all(selected[group] == branch for group, branch in path)
                            for path in part.get('alternative_paths', [()]))
                        for part in content_parts
                    ]
                    body_view = '\n'.join(text for text, use in zip(model_parts[1:], included)
                                          if use).strip()
                    uncertain = any(use and part_uncertain for use, part_uncertain
                                    in zip(included, model_uncertain_parts[1:]))
                    # Identical visible text is safe to score if any MIME path
                    # reaches it without uncertain rendering.
                    views[body_view] = views.get(body_view, True) and uncertain
                _model_view['mime_views'] = list(views.items())
    html_image_parts = [(part, visible) for part, visible, is_html
                        in zip(raw_parts[1:], visible_parts[1:], html_parts[1:]) if is_html]
    image_counts = [_image_reference_counts(part, analysis_warnings)
                    for part, _visible in html_image_parts]
    image_count = min(20, sum(counts[0] for counts in image_counts))
    remote_image_count = min(20, sum(counts[1] for counts in image_counts))
    unresolved_image_count = min(20, sum(counts[2] for counts in image_counts))
    if _model_view is not None:
        _model_view['remote_image_dominant'] = any(
            counts[1] > 0 and sum(not char.isspace() for char in _strip_invisible_format_controls(visible))
            < _REMOTE_IMAGE_MIN_VISIBLE_CHARS
            for counts, (_part, visible) in zip(image_counts, html_image_parts)
        )
    if image_count:
        analysis_warnings.append(_INLINE_IMAGE_WARNING)
    if remote_image_count:
        analysis_warnings.append(_REMOTE_IMAGE_WARNING)
    if unresolved_image_count:
        analysis_warnings.append(_UNRESOLVED_IMAGE_WARNING)
    url_parts = [_mask_inline_data_payloads(part) if is_html else part
                 for part, is_html in zip(raw_parts, html_parts)]
    raw_text = '\n'.join(url_parts)
    links = []
    for part, visible, is_html, stylesheet_uncertain in zip(
        url_parts, visible_parts, html_parts, stylesheet_uncertain_parts,
    ):
        part_links = _extract_links(
            part, parse_html=is_html, parse_warnings=analysis_warnings,
            visible_text=('' if stylesheet_uncertain else _strip_invisible_format_controls(visible))
            if is_html else None,
        )
        # Explicit destinations remain actionable. Without a CSS renderer,
        # neither naked HTML URLs nor displayed anchor labels are reliable.
        links.extend((('', destination) for _label, destination in part_links)
                     if is_html and stylesheet_uncertain else part_links)
    # CSS may hide arbitrary body text. Do not derive high phishing scores from
    # prose that might be hidden; independent destination/form checks still run.
    scored_parts = [visible if not uncertain else '' for visible, uncertain
                    in zip(visible_parts, stylesheet_uncertain_parts)]
    full_orig = re.sub(r'\s+', ' ', '\n'.join(scored_parts)).strip()
    analysis_text = _strip_invisible_format_controls(full_orig)
    full_lower = analysis_text.lower()
    if _has_substantial_han_text(analysis_text):
        analysis_warnings.append(_HAN_TEXT_WARNING)

    category_results = []
    total_score = 0
    risk_floor = "safe"

    for cat_key, cat_info in CONTENT_RULES.items():
        matched = [
            kw for kw in cat_info["keywords"]
            if _keyword_matches(full_lower, kw)
        ]
        if matched:
            capped = min(len(matched), 5)
            total_score += capped
            category_results.append({
                "key":         cat_key,
                "label":       cat_info["label"],
                "level":       cat_info["level"],
                "icon":        cat_info["icon"],
                "description": cat_info["description"],
                "matched":     matched[:6],
                "count":       len(matched),
                "score":       capped,
            })

    extra_indicators = []

    if any(hidden_image_padding):
        total_score += 4
        risk_floor = 'medium'
        extra_indicators.append({
            'level': 'medium',
            'msg': 'Large hidden text block accompanies an image-dominant linked message; '
                   'the visible message differs substantially from its hidden text. Review the image and destination manually.',
        })

    if any(_has_password_form(part, analysis_warnings) for part, is_html in zip(raw_parts, html_parts) if is_html):
        total_score += 4
        risk_floor = 'medium'
        extra_indicators.append({
            'level': 'medium',
            'msg': 'Embedded HTML form contains a password field; inspect the submission destination before entering credentials.',
        })

    if _has_pressured_credential_request(analysis_text):
        total_score += 4
        risk_floor = 'high'
        extra_indicators.append({
            'level': 'high',
            'msg': 'Direct credential request combined with urgency and threats; verify through an independent channel.',
        })

    # ── Structural & heuristic checks ────────────────────────────────────────

    # 2. URL shorteners
    if _has_shortener_url(raw_text, links=links):
        total_score += 2
        extra_indicators.append({
            "level": "high",
            "msg": "Contains shortened URLs (bit.ly, tinyurl, etc.) — hides the true destination domain",
        })

    # 3. Inspect every actual link target, even when its visible text is a
    # generic button such as "Review document".
    link_score, link_findings, link_floor = _analyze_link_destinations(
        raw_text, links=links, parse_warnings=analysis_warnings)
    total_score += link_score
    extra_indicators.extend(link_findings)
    floor_rank = {'safe': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    risk_floor = max((risk_floor, link_floor), key=floor_rank.get)

    # 4. Excessive exclamation marks
    excl = full_orig.count("!")
    if excl >= 3:
        total_score += 1
        extra_indicators.append({
            "level": "medium",
            "msg": f"Excessive exclamation marks ({excl}) — emotional manipulation tactic common in scam emails",
        })

    # 5. Excessive capitalization
    caps_ratio = _excessive_caps_ratio(full_orig)
    if caps_ratio > 0.40 and len(full_orig) > 60:
        total_score += 1
        extra_indicators.append({
            "level": "medium",
            "msg": f"Excessive capitalization ({caps_ratio:.0%} uppercase) — used to simulate alarm and urgency",
        })

    # 6. Excessive question marks in subject
    subj_q = scored_parts[0].count("?")
    if subj_q >= 2:
        total_score += 1
        extra_indicators.append({
            "level": "medium",
            "msg": f"Multiple question marks in subject line ({subj_q}) — manipulative rhetorical device",
        })

    # 7. High URL count
    url_count = _count_urls(links)
    if url_count > 6:
        total_score += 1
        extra_indicators.append({
            "level": "medium",
            "msg": f"Unusually high number of URLs ({url_count}) — suggests bulk phishing template",
        })

    # 8. Generic/impersonal salutation
    if _has_generic_salutation(full_orig):
        total_score += 2
        extra_indicators.append({
            "level": "medium",
            "msg": "Generic impersonal greeting (Dear Customer/User/Valued Member) — legitimate services address you by name",
        })

    # 9. Implausibly large currency amounts
    large_amounts = _large_currency_amounts(full_orig)
    if large_amounts:
        total_score += 2
        extra_indicators.append({
            "level": "high",
            "msg": f"Implausibly large monetary amounts mentioned: {', '.join(large_amounts)} — hallmark of advance-fee and lottery scams",
        })

    # 10. Excessive generic CTAs
    cta_count = _count_generic_cta(full_orig)
    if cta_count >= 2:
        total_score += 1
        extra_indicators.append({
            "level": "medium",
            "msg": f"Generic call-to-action phrases used {cta_count}× ('click here', 'click now') — legitimate emails use descriptive link text",
        })

    # 11. Regional/formal English variants are context only. Language variety
    # is neither malicious nor a reliable signal against modern LLM phishing.
    non_native = _detect_non_native_phrases(full_orig)
    if non_native:
        extra_indicators.append({
            "level": "info",
            "msg": f"Regional or formal English phrasing observed: \"{non_native[0]}\"{'...' if len(non_native)>1 else ''}; not included in the risk score.",
        })

    # 12. Character obfuscation / leetspeak
    obfuscated = _detect_obfuscation(full_orig)
    if obfuscated:
        total_score += 3
        extra_indicators.append({
            "level": "high",
            "msg": f"Character substitution / homoglyph obfuscation detected for: {', '.join(set(obfuscated))} — e.g. P@yP@l, Amaz0n — used to evade spam filters",
        })

    # Cosmetic legitimacy signals are context only. Attackers can copy these
    # strings, so they must never lower the risk score by themselves.
    safety_found = [
        desc for (kw, desc) in CONTENT_SAFETY_SIGNALS if kw.lower() in full_lower
    ]

    if total_score > 15:
        risk_level, risk_label = "critical", "Critical Risk — Very Likely Phishing"
    elif risk_floor == "high":
        risk_level, risk_label = "high", "High Risk — Likely Phishing"
    elif risk_floor == "medium" and total_score <= 8:
        risk_level, risk_label = "medium", "Medium Risk — Suspicious Content"
    elif total_score == 0:
        risk_level, risk_label = "safe",     "No Phishing Indicators Found"
    elif total_score <= 3:
        risk_level, risk_label = "low",      "Low Risk — Minor Concerns"
    elif total_score <= 8:
        risk_level, risk_label = "medium",   "Medium Risk — Suspicious Content"
    else:
        risk_level, risk_label = "high",     "High Risk — Likely Phishing"

    extra_indicators.extend({'level': 'info', 'msg': warning} for warning in analysis_warnings)
    return {
        "analysis_warnings": analysis_warnings,
        "inline_image_coverage": {
            "count": image_count,
            "inspection_status": "metadata_only" if image_count else "not_applicable",
        },
        "remote_image_coverage": {
            "count": remote_image_count,
            "inspection_status": "metadata_only" if remote_image_count else "not_applicable",
        },
        "unresolved_image_coverage": {
            "count": unresolved_image_count,
            "inspection_status": "metadata_only" if unresolved_image_count else "not_applicable",
        },
        "risk_level":        risk_level,
        "risk_label":        risk_label,
        "total_score":       total_score,
        "category_results":  category_results,
        "extra_indicators":  extra_indicators,
        "safety_signals":    safety_found,
        "url_count":         url_count,
        "has_ip_url":        _has_ip_url(raw_text, links=links),
        "has_shortener":     _has_shortener_url(raw_text, links=links),
        "risk_floor":        risk_floor,
    }


class ContentRequest(BaseModel):
    subject: str = Field(default="", max_length=500)
    body: str = Field(default="", max_length=50_000)
    raw_email: str = Field(default="", max_length=60_000)


def fuse_content_risk(
    *,
    ml_phishing_probability: float | None,
    ml_decision_threshold: float,
    heuristic_score: int,
    minimum_level: str = "safe",
) -> dict:
    """Conservatively fuse independent evidence without averaging it away."""
    heuristic_risk = min(1.0, max(0.0, heuristic_score / 16.0))
    ml_risk = 0.0 if ml_phishing_probability is None else min(
        1.0, max(0.0, ml_phishing_probability)
    )
    floor_scores = {
        "safe": 0.0,
        "low": 0.10,
        "medium": 0.30,
        "high": 0.55,
        "critical": 0.80,
    }
    floor_score = max(floor_scores.get(minimum_level, 0.0), 0.10 if heuristic_score > 0 else 0.0)
    combined = max(heuristic_risk, ml_risk, floor_score)
    model_signal = ml_phishing_probability is not None and ml_risk >= ml_decision_threshold
    # A high model score alone is not enough to justify a Critical label.
    independent_support = heuristic_score >= 9 or minimum_level in {"high", "critical"}
    model_only = model_signal and heuristic_score == 0 and minimum_level == "safe"
    model_led = model_signal and not independent_support and not model_only

    if minimum_level == "critical" or heuristic_risk >= 0.80 or (ml_risk >= 0.80 and independent_support):
        level, label = "critical", "Critical Risk — Very Likely Phishing"
    elif minimum_level == "high" or heuristic_risk >= 0.55 or model_signal:
        level = "high"
        label = ("High Risk — Model Signal Needs Review" if model_only or model_led
                 else "High Risk — Likely Phishing")
    elif combined >= 0.30:
        level, label = "medium", "Medium Risk — Suspicious Content"
    elif combined >= 0.10:
        level, label = "low", "Low Risk — Minor Concerns"
    else:
        level, label = "safe", "No Phishing Indicators Found"
    return {
        "combined_phishing_score": round(combined * 100, 1),
        "risk_level": level,
        "risk_label": label,
        "fusion_method": "conservative-evidence-max",
        "fusion_basis": ("model_only" if model_only else "model_led" if model_led else
                         "corroborated" if model_signal and independent_support else "other"),
    }


@app.post("/api/analyze-content")
async def analyze_content_endpoint(request: ContentRequest):
    return await _analyze_content(request)


@app.post("/api/analyze-eml")
async def analyze_eml_endpoint(request: Request):
    if request.headers.get('content-type', '').split(';', 1)[0].lower() not in {'message/rfc822', 'application/octet-stream'}:
        raise HTTPException(status_code=415, detail='Upload the original .eml bytes as message/rfc822')
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > 60_000:
            raise HTTPException(status_code=413, detail='Email file exceeds the 60,000-byte limit')
        raw.extend(chunk)
    if not raw.strip():
        raise HTTPException(status_code=400, detail='Email file is empty')
    structure = analyze_raw_email(bytes(raw), trusted_authserv_ids=SETTINGS.trusted_authserv_ids)
    return await _analyze_content(ContentRequest(), structure)


async def _analyze_content(
    request: ContentRequest,
    structure: dict | None = None,
    *,
    observe_sender_history: bool = True,
    plain_text: bool = False,
    allow_empty: bool = False,
):
    subject = request.subject.strip()
    body    = request.body.strip()
    if structure is not None or request.raw_email.strip():
        if structure is None:
            structure = analyze_raw_email(
                request.raw_email,
                trusted_authserv_ids=SETTINGS.trusted_authserv_ids,
            )
        # Raw-message mode is authoritative, including empty fields. Stale
        # manual input must not replace evidence from the uploaded message.
        subject = structure["subject"]
        body = structure["body"]
    has_structure = structure and (
        structure["attachments"] or structure["from"] or structure["reply_to"]
        or structure["return_path"] or structure["auth_results"]
        or structure["untrusted_authentication_claims"]
        or structure["parse_warnings"]
    )
    if not subject and not body and not has_structure and not allow_empty:
        raise HTTPException(status_code=400, detail="Subject, body, or message structure is required")

    # 1. Rule-based heuristic scan (explainable categories + extra indicators)
    model_view = {}
    result = analyze_email_content(subject, body, content_parts=(structure['content_parts'] if structure else
                                       [{'content_type': 'text/plain', 'content': body}] if plain_text else None),
                                   _model_view=model_view)
    if model_view.get('mime_alternatives_truncated'):
        result['analysis_warnings'].append(_MIME_ALTERNATIVE_LIMIT_WARNING)
    remote_image_dominant = model_view['remote_image_dominant']
    result["input_mode"] = "raw-email" if structure else "subject-body"
    result["structure_score"] = structure["structure_score"] if structure else 0
    if structure:
        result["extra_indicators"].extend(structure["indicators"])
        result["total_score"] += structure["structure_score"]
        result["message_structure"] = {
            key: structure[key]
            for key in (
                "from", "reply_to", "return_path", "auth_results",
                "authentication_trusted", "authentication_results_trusted",
                "untrusted_authentication_claims", "attachments", "risk_floor", "parse_warnings", "header_candidates",
            )
        }
        floor_rank = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        if floor_rank[structure["risk_floor"]] > floor_rank[result["risk_floor"]]:
            result["risk_floor"] = structure["risk_floor"]

        sender_addresses_by_identity = {}
        for header in structure['header_candidates']['From']:
            for address in _raw_sender_addresses(header):
                canonical = canonicalize_sender_address(address)
                sender_addresses_by_identity.setdefault(canonical, address)
        sender_addresses = list(sender_addresses_by_identity.values())
        if sender_addresses:
            # Select locally before touching the external history store. An
            # attacker can inject many ambiguous From values into one message;
            # only the sender that actually drives the result gets one bounded
            # observation request.
            selected_sender = max(
                (_analyze_sender_address(address) for address in sender_addresses),
                key=lambda analysis: analysis["risk_score"],
            )
            sender_analysis = (
                await _analyze_and_observe_sender(selected_sender["email"])
                if observe_sender_history
                else selected_sender
            )
            result["sender_analysis"] = sender_analysis
            sender_verdict = sender_analysis["verdict"]
            sender_contribution = {
                "critical": 6,
                "high": 5,
                "medium": 3,
            }.get(sender_verdict, 1 if sender_analysis["risk_score"] else 0)
            result["total_score"] += sender_contribution
            result["sender_score"] = sender_contribution
            result["extra_indicators"].extend(
                {
                    "level": indicator["level"],
                    "msg": f"Sender: {indicator['msg']}",
                }
                for indicator in sender_analysis["risk_indicators"]
            )
            sender_floor = (
                "high" if sender_verdict in {"critical", "high"}
                else "medium" if sender_verdict == "medium"
                else "safe"
            )
            if floor_rank[sender_floor] > floor_rank[result["risk_floor"]]:
                result["risk_floor"] = sender_floor

        if result["total_score"] > 15:
            result["risk_level"], result["risk_label"] = "critical", "Critical Risk — Very Likely Phishing"
        elif result["risk_floor"] == "high":
            result["risk_level"], result["risk_label"] = "high", "High Risk — Likely Phishing"
        elif result["risk_floor"] == "medium":
            result["risk_level"], result["risk_label"] = "medium", "Medium Risk — Suspicious Content"
        elif result["total_score"] > 8:
            result["risk_level"], result["risk_label"] = "high", "High Risk — Likely Phishing"
        elif result["total_score"] > 3:
            result["risk_level"], result["risk_label"] = "medium", "Medium Risk — Suspicious Content"

    if structure:
        nested_summaries = []
        floor_rank = {'safe': 0, 'unknown': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        for nested in structure['nested_messages']:
            nested_result = json.loads((await _analyze_content(
                ContentRequest(), nested, observe_sender_history=False,
            )).body)
            result['analysis_warnings'].extend('Attached message: ' + warning
                                                for warning in nested_result['analysis_warnings']
                                                if warning not in {_INLINE_IMAGE_WARNING, _REMOTE_IMAGE_WARNING,
                                                                   _UNRESOLVED_IMAGE_WARNING})
            coverage = result['inline_image_coverage']
            coverage['count'] = min(20, coverage['count'] + nested_result['inline_image_coverage']['count'])
            if coverage['count']:
                coverage['inspection_status'] = 'metadata_only'
            remote_coverage = result['remote_image_coverage']
            remote_coverage['count'] = min(20, remote_coverage['count']
                                          + nested_result['remote_image_coverage']['count'])
            if remote_coverage['count']:
                remote_coverage['inspection_status'] = 'metadata_only'
            unresolved_coverage = result['unresolved_image_coverage']
            unresolved_coverage['count'] = min(20, unresolved_coverage['count']
                                               + nested_result['unresolved_image_coverage']['count'])
            if unresolved_coverage['count']:
                unresolved_coverage['inspection_status'] = 'metadata_only'
            if (nested_result['remote_image_coverage']['count']
                    and nested_result['risk_level'] == 'unknown'):
                remote_image_dominant = True
            result['total_score'] = max(result['total_score'], nested_result['total_score'])
            nested_floor = 'safe' if nested_result['risk_level'] == 'unknown' else nested_result['risk_level']
            result['risk_floor'] = max((result['risk_floor'], nested_floor), key=floor_rank.get)
            result['extra_indicators'].extend(
                {'level': item['level'], 'msg': 'Attached message: ' + item['msg']}
                for item in nested_result['extra_indicators']
                if item['msg'] not in {_INLINE_IMAGE_WARNING, _REMOTE_IMAGE_WARNING,
                                      _UNRESOLVED_IMAGE_WARNING})
            # Categories are not parent-body matches; expose their provenance.
            result['extra_indicators'].extend(
                {'level': cat['level'], 'msg': 'Attached message: ' + cat['label'] + ' — ' + ', '.join(cat['matched'])}
                for cat in nested_result['category_results'])
            nested_summaries.append({
                'from': nested['from'], 'subject': nested['subject'],
                'risk_level': nested_result['risk_level'],
                'analysis_complete': nested_result['analysis_complete'],
                'authentication_results_trusted': nested['authentication_results_trusted'],
                'nested_messages': nested_result['message_structure']['nested_messages'],
            })
        result['message_structure']['nested_messages'] = nested_summaries

    if result['inline_image_coverage']['count'] and _INLINE_IMAGE_WARNING not in result['analysis_warnings']:
        result['analysis_warnings'].append(_INLINE_IMAGE_WARNING)
        result['extra_indicators'].append({'level': 'info', 'msg': _INLINE_IMAGE_WARNING})
    if result['remote_image_coverage']['count'] and _REMOTE_IMAGE_WARNING not in result['analysis_warnings']:
        result['analysis_warnings'].append(_REMOTE_IMAGE_WARNING)
        result['extra_indicators'].append({'level': 'info', 'msg': _REMOTE_IMAGE_WARNING})
    if (result['unresolved_image_coverage']['count']
            and _UNRESOLVED_IMAGE_WARNING not in result['analysis_warnings']):
        result['analysis_warnings'].append(_UNRESOLVED_IMAGE_WARNING)
        result['extra_indicators'].append({'level': 'info', 'msg': _UNRESOLVED_IMAGE_WARNING})

    # 2. Optional ML text classifier (TF-IDF + selected linear model)
    rendering_uncertain = any(warning in result['analysis_warnings'] for warning in (
        _STYLESHEET_VISIBILITY_WARNING, _INLINE_CSS_VISIBILITY_WARNING,
        _IMAGE_ALT_FALLBACK_WARNING, _MSO_CONDITIONAL_WARNING,
    ))
    if _content_pipeline is not None:
        views = model_view.get('mime_views', [(model_view['body'], rendering_uncertain)])
        bodies = [body for body, uncertain in views if not uncertain]
        if not bodies:
            ml = {
                'ml_status': 'unverified_rendering',
                '_phishing_probability': None,
                'ml_phishing_probability': None,
                'ml_legitimate_probability': None,
                'ml_label': None,
                'ml_prediction': None,
                'ml_decision_threshold': round(
                    float(_content_pipeline.get('decision_threshold', 0.5)) * 100, 1
                ),
                'ml_top_contributors': [],
            }
        else:
            predictions = [predict_content(_content_pipeline, model_view['subject'], body,
                                           canonical_text=True) for body in bodies]
            scored = [prediction for prediction in predictions
                      if prediction['_phishing_probability'] is not None]
            ml = (max(scored, key=lambda prediction: prediction['_phishing_probability'])
                  if scored else predictions[0])
            if len(views) > 1 and (len(bodies) != len(views)
                                   or len(scored) != len(predictions)):
                result['analysis_warnings'].append(_MIME_ALTERNATIVE_MODEL_WARNING)
        result.update({key: value for key, value in ml.items() if key != '_phishing_probability'})
        result["ml_metrics"] = _content_pipeline["metrics"]

        ml_probability = ml['_phishing_probability']
        if ml.get("ml_status") == "insufficient_context":
            result["analysis_warnings"].append(
                "The message contains too little text for reliable model scoring; "
                "ML classification was not applied."
            )
        elif ml.get("ml_status") == "insufficient_feature_coverage":
            result["analysis_warnings"].append(
                "Text model feature coverage is insufficient; ML classification "
                "was not applied."
            )

        result.update(fuse_content_risk(
            ml_phishing_probability=ml_probability,
            ml_decision_threshold=float(_content_pipeline.get("decision_threshold", 0.5)),
            heuristic_score=result["total_score"],
            minimum_level=result["risk_floor"],
        ))
    else:
        result.update(fuse_content_risk(
            ml_phishing_probability=None,
            ml_decision_threshold=0.5,
            heuristic_score=result["total_score"],
            minimum_level=result["risk_floor"],
        ))

    if structure and any(item['inspection_status'] == 'metadata_only'
                         for item in structure['attachments']):
        warning = ('Attachment content was not inspected; only filenames and MIME types '
                   'were checked. Analysis is incomplete.')
        result['analysis_warnings'].append(warning)
        result['extra_indicators'].append({'level': 'info', 'msg': warning})

    result['analysis_warnings'] = list(dict.fromkeys(result['analysis_warnings']
        + (structure['parse_warnings'] if structure else [])))
    result['analysis_complete'] = not bool(result['analysis_warnings'])
    # Weak routing/text evidence cannot establish low risk when the main visible
    # content is an uninspected image. Keep independently supported alerts.
    if not result['analysis_complete'] and (result['risk_level'] == 'safe'
                                            or (rendering_uncertain or remote_image_dominant)
                                            and result['risk_level'] == 'low'):
        if result['analysis_warnings'] == [_REMOTE_IMAGE_WARNING] and not remote_image_dominant:
            result['risk_label'] = 'No Indicators in Inspected Text — Remote Image Unchecked'
        else:
            result['risk_level'] = 'unknown'
            result['risk_label'] = 'Analysis Incomplete — Risk Undetermined'
            result['combined_phishing_score'] = None
    return JSONResponse(result)


@app.post('/api/analyze-visual')
async def analyze_visual_endpoint(payload: VisualRequest):
    return await _analyze_visual(payload)


# Do not echo private image text/base64 (or non-JSON NaN values) in validation errors.
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler


@app.exception_handler(RequestValidationError)
async def safe_visual_validation(request, exc):
    if request.url.path in VISUAL_PATHS:
        return JSONResponse(status_code=422, content={'detail': 'Invalid image evidence or email input. Check file size and recognition limits.'})
    return await request_validation_exception_handler(request, exc)


async def _analyze_visual(payload, structure=None, *, observe_sender_history=True):
    raw = payload.eml_bytes()
    if structure is None and raw is not None:
        structure = bound_message_text(analyze_raw_email(raw, trusted_authserv_ids=SETTINGS.trusted_authserv_ids))
    if not (raw or payload.subject.strip() or payload.body.strip() or payload.observations or payload.warnings):
        raise HTTPException(400, 'Image evidence or an email is required')
    base = json.loads((await _analyze_content(
        ContentRequest(subject=payload.subject, body=payload.body), structure,
        observe_sender_history=observe_sender_history, allow_empty=True,
    )).body)
    findings = []
    for item in payload.observations:
        # Treat extracted strings as text, never as an HTML document or a URL to fetch.
        text = '\n'.join([item.ocr_text, *dict.fromkeys(item.qr_payloads)])
        finding = json.loads((await _analyze_content(
            ContentRequest(body=text), observe_sender_history=False,
            plain_text=True, allow_empty=True,
        )).body)
        findings.append(finding)
    base['input_mode'] = 'raw-email' if raw else 'image-evidence'
    return JSONResponse(merge_visual_findings(base, payload.observations, findings, payload.warnings))


# ── Email Authenticity Verification ──────────────────────────────────────────

from concurrent.futures import TimeoutError as FutureTimeout, wait as futures_wait
from verification_runtime import BoundedExecutor

VERIFICATION_TIMEOUT = 12.0
try:
    VERIFICATION_WORKERS = int(os.getenv("VERIFICATION_WORKERS", "10"))
except ValueError as exc:
    raise ValueError("VERIFICATION_WORKERS must be an integer") from exc
if not 1 <= VERIFICATION_WORKERS <= 32:
    raise ValueError("VERIFICATION_WORKERS must be between 1 and 32")
_verification_pool = BoundedExecutor(workers=VERIFICATION_WORKERS)


class VerifyRequest(BaseModel):
    email: str = Field(..., min_length=1, max_length=254)


# ── Helper: SMTP mailbox probe ────────────────────────────────────────────────
def _resolve_public_smtp_addresses(
    mx_host: str,
    *,
    resolver=None,
    timeout: float = 5,
) -> list[str]:
    """Resolve a mail host once and retain only globally routable targets."""
    addresses: list[str] = []
    if resolver is None:
        import dns.resolver
        import dns.exception
        answers = []
        deadline = time.monotonic() + timeout
        for kind in ('A', 'AAAA'):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                records = dns.resolver.resolve(mx_host, kind, lifetime=remaining)
                answers.extend((None, None, None, None, (str(r), 25)) for r in records)
            except dns.exception.DNSException:
                continue
    else:
        try:
            answers = resolver(mx_host, 25, type=socket.SOCK_STREAM)
        except (OSError, socket.gaierror):
            return addresses

    for _family, _socktype, _proto, _canonname, sockaddr in answers:
        address = str(sockaddr[0]).split("%", 1)[0]
        try:
            is_global = ipaddress.ip_address(address).is_global
        except ValueError:
            continue
        if is_global and address not in addresses:
            addresses.append(address)
    return addresses


def _smtp_probe(
    email: str,
    mx_host: str,
    smtp_address: str | None = None,
    timeout: int = 8,
) -> dict:
    result = {"connectable": False, "result": "unverifiable", "message": "", "status": "error"}
    deadline = time.monotonic() + timeout
    if smtp_address is None:
        public_addresses = _resolve_public_smtp_addresses(mx_host, timeout=min(5, timeout))
        smtp_address = public_addresses[0] if public_addresses else None
    try:
        is_public_target = bool(
            smtp_address and ipaddress.ip_address(smtp_address).is_global
        )
    except ValueError:
        is_public_target = False
    if not is_public_target:
        result['status'] = 'unavailable'
        result["message"] = f"SMTP target for {mx_host} is non-public or could not be validated."
        return result

    smtp = None
    def remaining():
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise socket.timeout()
        return seconds
    try:
        smtp = smtplib.SMTP(timeout=remaining())
        smtp.connect(smtp_address, 25)
        result["connectable"] = True
        smtp.sock.settimeout(remaining())
        smtp.helo("verify.phishguard.local")
        smtp.sock.settimeout(remaining())
        smtp.mail("")
        smtp.sock.settimeout(remaining())
        code, msg_bytes = smtp.rcpt(email)
        result['status'] = 'ok'
        msg_str = msg_bytes.decode(errors="replace") if isinstance(msg_bytes, bytes) else str(msg_bytes)
        enhanced_match = re.match(r'^\s*([245]\.\d{1,3}\.\d{1,3})(?:\s|$)', msg_str)
        enhanced = enhanced_match.group(1) if enhanced_match else None
        try:
            smtp.sock.settimeout(remaining())
            smtp.quit()
        except Exception:
            pass
        if code == 250:
            result["result"] = "exists"
            result["message"] = f"Mail server accepted the address (SMTP {code})"
        elif 500 <= code < 600 and enhanced == '5.1.1':
            result["result"] = "does_not_exist"
            result["message"] = f"Mail server reports no such mailbox (SMTP {code}): {msg_str[:120]}"
        elif 500 <= code < 600 and enhanced and enhanced.startswith('5.7.'):
            result['result'] = 'policy_rejected'
            result['message'] = f'Policy rejection does not establish mailbox existence (SMTP {code}): {msg_str[:120]}'
        elif 500 <= code < 600 and enhanced == '5.2.2':
            result['result'] = 'mailbox_full'
            result['message'] = f'Mailbox full; not evidence of a nonexistent address (SMTP {code}): {msg_str[:120]}'
        elif code in (421, 450, 451, 452):
            result["result"] = "temporarily_unavailable"
            result["message"] = f"Server returned a temporary error (SMTP {code}) — try again later"
        else:
            result["result"] = "unknown"
            result["message"] = f"Mailbox existence is inconclusive (SMTP {code}): {msg_str[:120]}"
    except smtplib.SMTPConnectError as e:
        result["message"] = f"Cannot connect to {mx_host}:25 — {e}"
    except smtplib.SMTPServerDisconnected as e:
        result["message"] = f"Server disconnected unexpectedly — {e}"
    except socket.timeout:
        result['status'] = 'timeout'
        result["message"] = f"Connection to {mx_host} timed out after {timeout}s"
    except OSError as e:
        result["message"] = f"Network error: {e}"
    except Exception as e:
        result["message"] = str(e)[:150]
    finally:
        if smtp is not None:
            try:
                smtp.close()
            except Exception:
                pass
    return result


# ── Helper: SPF record check ──────────────────────────────────────────────────
def _check_spf(domain: str) -> dict:
    """Look up SPF TXT record and parse the enforcement policy."""
    import dns.resolver, dns.exception
    result = {"found": False, "record": None, "policy": None, "message": "", "status": "not_found"}
    try:
        records = [b''.join(r.strings).decode('ascii', errors='replace')
                   for r in dns.resolver.resolve(domain, 'TXT', lifetime=5)]
        records = [txt for txt in records if re.match(r'^v=spf1(?:\s|$)', txt, re.IGNORECASE)]
        if len(records) > 1:
            raise ValueError('Multiple SPF records; policy is inconclusive')
        for txt in records:
            terms = txt.split()
            if terms and terms[0].lower() == 'v=spf1':
                # Validate local term shapes before summarizing the first all.
                # This does not expand macros or evaluate include/redirect.
                mechanism = (r'[+?~-]?(?:all|(?:include|exists):\S+|'
                             r'(?:a|mx)(?::\S+|/[0-9]+(?://[0-9]+)?|//[0-9]+)?|'
                             r'ptr(?::\S+)?|ip[46]:\S+)')
                modifier = r'[a-z][a-z0-9._-]*=\S+'
                if any(not re.fullmatch(mechanism + '|' + modifier, term, re.IGNORECASE)
                       for term in terms[1:]):
                    raise ValueError('Malformed or unsupported SPF mechanism')
                result['status'] = 'ok'
                result["found"]  = True
                result["record"] = txt[:250]
                all_term = next((term.lower() for term in terms[1:]
                                 if re.fullmatch(r'[+?~-]?all', term, re.IGNORECASE)), None)
                if all_term == '-all':
                    result["policy"]  = "strict"
                    result["message"] = "Strict policy (-all): unauthorized senders are rejected."
                elif all_term == '~all':
                    result["policy"]  = "softfail"
                    result["message"] = "Soft-fail policy (~all): unauthorized senders are flagged but not blocked."
                elif all_term == '?all':
                    result["policy"]  = "neutral"
                    result["message"] = "Neutral policy (?all): no enforcement — spoofing possible."
                elif all_term in {'+all', 'all'}:
                    result["policy"]  = "open"
                    result["message"] = "Open policy (+all): ANY server may send — high spoofing risk!"
                else:
                    result["policy"]  = "unknown"
                    result["message"] = "SPF record found but enforcement policy is unclear."
                break
        if not result["found"]:
            result["message"] = "No SPF record — this domain is vulnerable to email spoofing."
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result["message"] = "No TXT records found for domain."
    except dns.exception.DNSException as e:
        result['status'] = 'timeout' if isinstance(e, dns.exception.Timeout) else 'error'
        result["message"] = f"DNS error: {e}"
    except Exception as e:
        result['status'] = 'error'
        result["message"] = f"SPF check error: {str(e)[:100]}"
    return result


# ── Helper: DMARC policy check ────────────────────────────────────────────────
def _check_dmarc(domain: str) -> dict:
    """Look up DMARC TXT record at _dmarc.<domain> and parse the p= policy."""
    import dns.resolver, dns.exception
    result = {"found": False, "record": None, "policy": None, "pct": None, "message": "", "status": "not_found"}
    try:
        dmarc_domain = f"_dmarc.{domain}"
        records = [b''.join(r.strings).decode('ascii', errors='replace')
                   for r in dns.resolver.resolve(dmarc_domain, 'TXT', lifetime=5)]
        records = [txt for txt in records if re.match(r'^v\s*=\s*DMARC1\s*(?:;|$)', txt)]
        if len(records) > 1:
            raise ValueError('Multiple DMARC records; policy is inconclusive')
        for txt in records:
            result['found'] = True
            result['record'] = txt[:250]
            tags = {}
            for field in txt.rstrip().rstrip(';').split(';'):
                match = re.fullmatch(r'\s*([a-zA-Z][a-zA-Z0-9_]*)\s*=\s*(.*?)\s*', field)
                if not match or match.group(1) in tags:
                    raise ValueError('Malformed or duplicate DMARC tag')
                tags[match.group(1)] = match.group(2)
            p = tags.get('p')
            if p not in {'reject', 'quarantine', 'none'}:
                raise ValueError('Missing or invalid DMARC p= policy')
            pct_text = tags.get('pct', '100')
            if not re.fullmatch(r'[0-9]{1,3}', pct_text) or int(pct_text) > 100:
                raise ValueError('DMARC pct must be between 0 and 100')
            pct = int(pct_text)
            result.update(status='ok', policy=p, pct=pct)
            pct_str = f" (requested for {pct}% of messages)" if pct < 100 else ""
            messages = {
                'reject': f'p=reject{pct_str}: domain requests rejection of DMARC-failing messages.',
                'quarantine': f'p=quarantine{pct_str}: domain requests quarantine of DMARC-failing messages.',
                'none': 'p=none: monitoring only — no enforcement requested.',
            }
            result['message'] = messages[p]
        if not result["found"]:
            result["message"] = f"No DMARC record at _dmarc.{domain} — no anti-spoofing policy set."
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result["message"] = f"No DMARC record at _dmarc.{domain}."
    except dns.exception.DNSException as e:
        result['status'] = 'timeout' if isinstance(e, dns.exception.Timeout) else 'error'
        result["message"] = f"DNS error: {e}"
    except Exception as e:
        result['status'] = 'error'
        result["message"] = f"DMARC check error: {str(e)[:100]}"
    return result


# ── Helper: Domain age via WHOIS ──────────────────────────────────────────────
def _check_domain_age(domain: str) -> dict:
    """Retrieve domain creation date via WHOIS and assess age."""
    result = {"found": False, "creation_date": None, "age_days": None,
              "registrar": None, "message": "", "status": "not_found"}
    try:
        import whois
        from datetime import datetime, timezone
        w = whois.whois(domain, timeout=5)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            now = datetime.now(timezone.utc)
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age = (now - creation).days
            result["found"]         = True
            result['status'] = 'ok'
            result["creation_date"] = creation.strftime("%Y-%m-%d")
            result["age_days"]      = age
            result["registrar"]     = (w.registrar or "")[:80] if w.registrar else None
            if age < 30:
                result["message"] = (
                    f"Domain is only {age} days old — newly registered domains "
                    f"are a major phishing red flag."
                )
            elif age < 180:
                result["message"] = (
                    f"Domain is {age} days old (~{age//30} months) — "
                    f"relatively new, proceed with caution."
                )
            elif age < 365:
                result["message"] = f"Domain is {age} days old (< 1 year) — moderately established."
            else:
                years = age // 365
                result["message"] = (
                    f"Domain registered {creation.strftime('%Y-%m-%d')} "
                    f"({years} year{'s' if years != 1 else ''} old) — well-established."
                )
        else:
            result["message"] = "WHOIS returned no creation date for this domain."
    except Exception as e:
        result['status'] = 'timeout' if isinstance(e, TimeoutError) else 'error'
        result["message"] = f"WHOIS lookup failed or data unavailable: {str(e)[:100]}"
    return result


# ── Helper: MX PTR (reverse DNS) check ───────────────────────────────────────
def _check_mx_ptr(mx_host: str) -> dict:
    """Check if the primary MX server has a valid PTR (reverse DNS) record."""
    import dns.resolver, dns.reversename, dns.exception
    result = {"found": False, "ptr": None, "ip": None, "message": "", "status": "not_found"}
    try:
        a_records = dns.resolver.resolve(mx_host, "A", lifetime=5)
        ip = str(a_records[0])
        result["ip"] = ip
        rev = dns.reversename.from_address(ip)
        ptr_records = dns.resolver.resolve(rev, "PTR", lifetime=5)
        ptr = str(ptr_records[0]).rstrip(".")
        result["found"] = True
        result["ptr"]   = ptr
        result['status'] = 'ok'
        result["message"] = f"MX server {ip} → PTR: {ptr}"
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result["message"] = (
            f"No PTR record for MX server{(' ' + result['ip']) if result['ip'] else ''} "
            f"— legitimate mail servers almost always have reverse DNS configured."
        )
    except dns.exception.DNSException as e:
        result['status'] = 'timeout' if isinstance(e, dns.exception.Timeout) else 'error'
        result["message"] = f"PTR lookup error: {e}"
    except Exception as e:
        result['status'] = 'error'
        result["message"] = f"PTR check error: {str(e)[:100]}"
    return result


def _lookup_mail_domain(domain: str, deadline: float) -> dict:
    """Perform bounded DNS discovery; a timeout is not a nonexistent mailbox."""
    import dns.resolver
    import dns.exception
    result = {'mx_found': False, 'mx_records': [], 'overall': 'unverifiable',
              'smtp_message': 'DNS lookup timed out or was unavailable.'}
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return result
        answers = dns.resolver.resolve(domain, 'MX', lifetime=min(6, remaining))
        records = sorted((r.preference, str(r.exchange).rstrip('.')) for r in answers)
        if any(not host for _, host in records):
            if records == [(0, '')]:
                return {**result, 'null_mx': True, 'overall': 'no_mail_service',
                        'smtp_message': 'Domain publishes Null MX: it does not accept email. This is not evidence of phishing.'}
            return {**result, 'smtp_message': 'Invalid mixed or nonzero-preference Null MX records; mail service is inconclusive.'}
        if records:
            return {'mx_found': True, 'mx_records': records}
    except dns.resolver.NXDOMAIN:
        return {**result, 'overall': 'likely_invalid', 'smtp_message': 'Domain does not exist in DNS.'}
    except dns.resolver.NoAnswer:
        pass
    except dns.exception.DNSException:
        return result
    address_lookup_failed = False
    for kind in ('A', 'AAAA'):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return result
        try:
            addresses = dns.resolver.resolve(domain, kind, lifetime=min(4, remaining))
            if addresses:
                return {'mx_found': True, 'mx_records': [[0, domain]],
                        'note': f'No MX record found; domain has an {kind} record — using domain directly.'}
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except dns.exception.DNSException:
            address_lookup_failed = True
    if address_lookup_failed:
        return result
    return {**result, 'overall': 'likely_invalid', 'smtp_message': 'Domain has no MX, A, or AAAA records.'}


def _summarize_verification(out: dict, *, smtp_enabled: bool) -> None:
    """Add explicit domain/mailbox summaries without overstating evidence."""
    domain_complete = False
    if not out["format_valid"]:
        domain_status = "invalid_format"
    elif out["null_mx"]:
        domain_status = "no_mail_service"
    elif out["mx_found"]:
        domain_checks = (out["spf"], out["dmarc"], out["domain_age"], out["mx_ptr"])
        domain_complete = all(
            info is not None and info.get("status") in {"ok", "not_found"}
            for info in domain_checks
        )
        domain_status = "valid" if domain_complete else "partial"
    elif out["overall"] == "likely_invalid":
        domain_status = "invalid"
    else:
        domain_status = "unavailable"

    if not smtp_enabled:
        mailbox_status = "unavailable"
        mailbox_reason = (
            "SMTP mailbox probing is unavailable on this deployment; "
            "domain evidence does not prove that the mailbox exists."
        )
    elif out["smtp_result"] == "exists":
        mailbox_status = "accepted"
        mailbox_reason = out["smtp_message"]
    elif out["smtp_result"] == "does_not_exist":
        mailbox_status = "rejected"
        mailbox_reason = out["smtp_message"]
    else:
        mailbox_status = "inconclusive"
        mailbox_reason = out["smtp_message"]

    out["domain_verification"] = {
        "status": domain_status,
        "complete": domain_complete,
        "mx_found": out["mx_found"],
    }
    out["mailbox_verification"] = {
        "status": mailbox_status,
        "reason": mailbox_reason,
    }
    out["verification_complete"] = (
        domain_complete and mailbox_status in {"accepted", "rejected"}
    )


@app.post("/api/verify-email")
def verify_email_endpoint(req: VerifyRequest):
    """
    Six-stage email authenticity check (stages 3-6 run in parallel):
      1. RFC 5321 format validation
      2. DNS MX (+ A/AAAA fallback) record lookup
      3. Optional SMTP RCPT TO probe  ┐
      4. SPF record & policy          ├─ parallel
      5. DMARC record & policy        │
      6. MX PTR / reverse-DNS         │
      7. Domain age (WHOIS)           ┘
    """
    if not SETTINGS.domain_verification_enabled:
        raise HTTPException(
            status_code=404,
            detail=(
                "Domain verification is disabled in this deployment. "
                "Enable Lite mode or run full SMTP checks locally."
            ),
        )

    import dns.resolver
    import dns.exception

    email = req.email.strip()
    out = {
        "email": email,
        "format_valid": False,
        "mx_found": False,
        "mx_records": [],
        "null_mx": False,
        "smtp_connectable": False,
        "smtp_result": None,
        "smtp_message": None,
        "smtp_status": "skipped",
        "spf":  None,
        "dmarc": None,
        "domain_age": None,
        "mx_ptr": None,
        "note": None,
        "overall": None,
        "verification_complete": False,
    }

    def respond():
        _summarize_verification(
            out,
            smtp_enabled=SETTINGS.smtp_verification_enabled,
        )
        return JSONResponse(out)

    # ── Stage 1: Format ───────────────────────────────────────────────────────
    normalized_email = _normalize_sender_address(email)
    if not normalized_email:
        out["overall"]       = "invalid_format"
        out["smtp_message"]  = "Enter a single supported email address with an unquoted ASCII local part and a valid domain."
        return respond()
    out["format_valid"] = True
    # Retain the submitted address for display, but use the same canonical
    # IDNA domain/address as sender analysis for DNS, WHOIS and SMTP checks.
    email = normalized_email
    domain = email.split("@")[1].lower()

    # One deadline covers DNS discovery and every subsequent check.
    deadline = time.monotonic() + VERIFICATION_TIMEOUT
    discovery = _verification_pool.submit(_lookup_mail_domain, domain, deadline)
    if discovery is None:
        raise HTTPException(status_code=503, detail='Verification capacity is busy; retry later.', headers={'Retry-After': '12'})
    try:
        out.update(discovery.result(timeout=max(0, deadline - time.monotonic())))
    except FutureTimeout:
        discovery.cancel()
        out['overall'] = 'unverifiable'
        out['smtp_message'] = 'DNS lookup timed out or was unavailable.'
        return respond()
    except Exception:
        out['overall'] = 'unverifiable'
        out['smtp_message'] = 'DNS lookup was unavailable.'
        return respond()
    if not out['mx_found']:
        return respond()
    mx_host = out['mx_records'][0][1]
    if time.monotonic() >= deadline:
        out['overall'] = 'unverifiable'
        out['smtp_message'] = 'Verification deadline reached after DNS lookup.'
        return respond()

    # No per-request context manager: its shutdown would wait past the deadline.
    f_smtp = (
        _verification_pool.submit(_smtp_probe, email, mx_host)
        if SETTINGS.smtp_verification_enabled else None
    )
    f_spf = _verification_pool.submit(_check_spf, domain)
    f_dmarc = _verification_pool.submit(_check_dmarc, domain)
    f_age = _verification_pool.submit(_check_domain_age, domain)
    f_ptr = _verification_pool.submit(_check_mx_ptr, mx_host)
    futures = [f for f in (f_smtp, f_spf, f_dmarc, f_age, f_ptr) if f is not None]
    done, pending = futures_wait(futures, timeout=max(0, deadline - time.monotonic()))
    for future in pending:
        future.cancel()

    def safe_result(future, fallback):
        if future is None:
            return {**fallback, 'status': 'busy', 'message': 'Verification capacity is busy; this check was not run.'}
        if future not in done:
            return {**fallback, 'status': 'timeout'}
        try:
            return future.result(timeout=0)
        except Exception:
            return {**fallback, 'status': 'error', 'message': 'Verification check failed; result unavailable.'}

    if SETTINGS.smtp_verification_enabled:
        probe = safe_result(f_smtp, {"connectable": False, "result": "unverifiable",
                                     "message": "SMTP probe timed out."})
    else:
        probe = {
            "connectable": False,
            "result": "unavailable",
            "message": "SMTP mailbox probing is unavailable on this deployment.",
            "status": "skipped",
        }
    spf_info     = safe_result(f_spf,   {"found": False, "policy": None,
                                          "message": "SPF check timed out."})
    dmarc_info   = safe_result(f_dmarc, {"found": False, "policy": None,
                                          "message": "DMARC check timed out."})
    age_info     = safe_result(f_age,   {"found": False, "age_days": None,
                                          "message": "WHOIS lookup timed out."})
    ptr_info     = safe_result(f_ptr,   {"found": False, "ptr": None,
                                          "message": "PTR check timed out."})

    out["smtp_connectable"] = probe["connectable"]
    out['smtp_status'] = probe['status']
    out["smtp_result"]      = probe["result"]
    out["smtp_message"]     = probe["message"]
    out["spf"]              = spf_info
    out["dmarc"]            = dmarc_info
    out["domain_age"]       = age_info
    out["mx_ptr"]           = ptr_info

    # ── Overall verdict ───────────────────────────────────────────────────────
    if not SETTINGS.smtp_verification_enabled:
        out["overall"] = "domain_valid"
    elif probe["result"] == "exists":
        out["overall"] = "verified"
    elif probe["result"] == "does_not_exist":
        out["overall"] = "likely_invalid"
    elif not probe["connectable"]:
        out["overall"] = "unverifiable"
        if not out["smtp_message"]:
            out["smtp_message"] = (
                "Port 25 appears blocked by your network. "
                "MX records exist, so the domain is real, but mailbox existence cannot be confirmed."
            )
    else:
        out["overall"] = "unverifiable"

    # Escalate: very new domain is a serious additional red flag
    age_days = age_info.get("age_days")
    if age_days is not None and age_days < 30 and out["overall"] != "likely_invalid":
        out["overall"] = "suspicious"

    return respond()



async def _analyze_case(payload, raw):
    """Capture server evidence once; clients cannot submit or edit detection results."""
    structure = None
    visual = isinstance(payload, VisualRequest)
    raw_input = payload.eml_bytes() if visual else raw if raw is not None else payload.raw_email
    if raw_input:
        structure = analyze_raw_email(raw_input, trusted_authserv_ids=SETTINGS.trusted_authserv_ids)
    if visual:
        if structure:
            bound_message_text(structure)
        response = await _analyze_visual(payload, structure, observe_sender_history=False)
    else:
        response = await _analyze_content(ContentRequest(**payload.model_dump()), structure,
                                         observe_sender_history=False)
    analysis = json.loads(response.body)
    analysis.pop('ml_metrics', None)  # Dataset-wide metrics are not per-message evidence.
    source = {'subject': structure['subject'] if structure else payload.subject.strip(),
              'body': structure['body'] if structure else payload.body.strip(),
              'input_mode': analysis['input_mode']}
    if visual:
        # Analyze the original message above, but retain text rather than embedded
        # image bytes. Plain MIME parts remain literal text, including angle brackets.
        parts = structure['content_parts'] if structure else [
            {'content_type': 'text/html', 'content': source['body']}]
        source['body'] = '\n'.join(_mask_inline_data_payloads(
            _visible_content_text(part['content']) if part['content_type'] == 'text/html'
            else part['content']) for part in parts)
    if visual and not structure and not source['subject'] and payload.observations:
        source['subject'] = 'Image: ' + payload.observations[0].name
    source['text_truncated'] = bool(len(source['body']) > 60000 or
                                    (visual and structure and structure.get('text_truncated')))
    source['body'] = source['body'][:60000]
    # Preserve MIME text/plain literally for later optional semantic analysis.
    # Saved legacy raw-email bodies mix HTML/plain and cannot be re-parsed safely.
    semantic_parts = structure['content_parts'] if structure else [
        {'content_type': 'text/html', 'content': payload.body}]
    source['auxiliary_text'] = '\n'.join(
        _mask_inline_data_payloads(_visible_content_text(part['content'])
                                  if part['content_type'] == 'text/html' else part['content'])
        for part in semantic_parts)[:12001]  # Over-limit sentinel length makes Jev skip, not silently truncate.
    source['auxiliary_omitted_nested_messages'] = bool(structure and structure.get('nested_messages'))
    digest = hashlib.sha256()
    for path in sorted([*BASE_DIR.glob('*.py'), *(BASE_DIR / 'data').glob('*.json')]):
        digest.update(str(path.relative_to(BASE_DIR)).encode() + b'\0' + path.read_bytes())
    provenance = {'code_sha256': digest.hexdigest(), 'model_sha256': _content_model_artifact_sha256,
                  'commit': os.getenv('VERCEL_GIT_COMMIT_SHA') or None,
                  'trusted_authserv_ids': sorted(SETTINGS.trusted_authserv_ids)}
    return source, analysis, provenance


app.include_router(make_case_router(_analyze_case, visible_text=_visible_content_text,
                                   mask_inline_data=_mask_inline_data_payloads))
app.include_router(make_feedback_router())


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
