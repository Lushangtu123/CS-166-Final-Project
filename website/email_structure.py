"""Parse RFC 5322 messages and expose phishing-relevant structural signals."""

from __future__ import annotations

from email import policy
from email.parser import Parser
from email.utils import parseaddr
from pathlib import PurePath
import re
import unicodedata


_AUTH_FAILURES = {"fail", "softfail", "permerror", "temperror"}
_DANGEROUS_EXTENSIONS = {
    ".bat", ".chm", ".cmd", ".com", ".dll", ".docm", ".exe", ".hta",
    ".html", ".htm", ".img", ".iso", ".jar", ".js", ".lnk", ".msi",
    ".one", ".ps1", ".scr", ".vbs", ".vhd", ".vhdx", ".wsf", ".xlam",
    ".xlsm", ".xll",
}
_ARCHIVE_EXTENSIONS = {".7z", ".gz", ".rar", ".tar", ".tgz", ".zip"}
_PROTECTED_BRAND_DOMAINS = {
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com"},
    "google": {"google.com"},
    "microsoft": {"microsoft.com"},
    "paypal": {"paypal.com"},
}
_CONFUSABLE_TRANSLATION = str.maketrans({
    # Cyrillic characters commonly used in Latin-brand lookalikes.
    "а": "a", "е": "e", "і": "i", "ј": "j", "о": "o",
    "р": "p", "с": "c", "х": "x", "у": "y", "ӏ": "l",
    # Greek characters with a close Latin appearance.
    "α": "a", "ε": "e", "ι": "i", "κ": "k", "ο": "o",
    "ρ": "p", "τ": "t", "υ": "y", "χ": "x",
})


def _domain(address: str) -> str:
    parsed = parseaddr(address or "")[1].lower()
    return parsed.rsplit("@", 1)[-1] if "@" in parsed else ""


def _domains_align(left: str, right: str) -> bool:
    """Accept exact domains and ordinary parent/subdomain relationships."""
    return bool(left and right) and (
        left == right or left.endswith("." + right) or right.endswith("." + left)
    )


def _decode_idna_domain(domain: str) -> str:
    labels = []
    for label in domain.lower().strip(".").split("."):
        try:
            labels.append(label.encode("ascii").decode("idna"))
        except (UnicodeError, UnicodeEncodeError):
            labels.append(label)
    return ".".join(labels)


def _confusable_skeleton(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value.casefold())
    without_marks = "".join(ch for ch in normalized if not unicodedata.combining(ch))
    return without_marks.translate(_CONFUSABLE_TRANSLATION)


def _canonical_brand_domain(domain: str, canonical_domains: set[str]) -> bool:
    return any(_domains_align(domain, canonical) for canonical in canonical_domains)


def _brand_identity_signals(from_header: str, from_domain: str) -> tuple[int, list[dict]]:
    display_name = parseaddr(from_header or "")[0]
    decoded_domain = _decode_idna_domain(from_domain)
    display_skeleton = re.sub(r"[^a-z0-9]", "", _confusable_skeleton(display_name))
    domain_skeleton = _confusable_skeleton(decoded_domain)
    domain_label_skeleton = domain_skeleton.split(".", 1)[0]
    indicators: list[dict] = []
    score = 0

    for brand, canonical_domains in _PROTECTED_BRAND_DOMAINS.items():
        canonical = _canonical_brand_domain(from_domain, canonical_domains)
        if brand in display_skeleton and not canonical:
            score += 4
            indicators.append({
                "level": "high",
                "msg": (
                    f"Protected brand identity '{brand}' is displayed from "
                    f"an unrelated domain ({from_domain})."
                ),
            })
        if (
            brand in domain_label_skeleton
            and domain_skeleton != decoded_domain.casefold()
            and not canonical
        ):
            score += 4
            indicators.append({
                "level": "high",
                "msg": f"Sender domain ({from_domain}) is a Unicode/IDN confusable for {brand}.",
            })

    return score, indicators


def _message_text(message) -> tuple[str, str, list[dict]]:
    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[dict] = []

    for part in message.walk():
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if filename or disposition == "attachment":
            attachments.append({
                "filename": filename or "unnamed",
                "content_type": content_type,
            })
            continue
        if content_type not in {"text/plain", "text/html"}:
            continue
        try:
            content = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            content = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        if content_type == "text/html":
            html_parts.append(str(content))
        else:
            plain_parts.append(str(content))

    return "\n".join(plain_parts), "\n".join(html_parts), attachments


def analyze_raw_email(
    raw_email: str,
    *,
    trusted_authserv_ids: set[str] | frozenset[str] | None = None,
) -> dict:
    """Return normalized content plus authentication, identity, and attachment signals."""
    message = Parser(policy=policy.default).parsestr(raw_email)
    plain, html, attachments = _message_text(message)
    # Analyze both alternatives. Phishers commonly put harmless text in the
    # plain part and the credential link only in the HTML part.
    body = "\n".join(part for part in (plain, html) if part)
    indicators: list[dict] = []
    score = 0
    risk_floor = "safe"

    from_domain = _domain(message.get("From", ""))
    reply_domain = _domain(message.get("Reply-To", ""))
    return_domain = _domain(message.get("Return-Path", ""))

    brand_score, brand_indicators = _brand_identity_signals(
        str(message.get("From", "") or ""),
        from_domain,
    )
    score += brand_score
    indicators.extend(brand_indicators)
    if brand_score:
        risk_floor = "high"

    if from_domain and reply_domain and not _domains_align(reply_domain, from_domain):
        score += 4
        indicators.append({
            "level": "high",
            "msg": f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain}).",
        })
    if from_domain and return_domain and not _domains_align(return_domain, from_domain):
        score += 2
        indicators.append({
            "level": "medium",
            "msg": f"Return-Path domain ({return_domain}) differs from From domain ({from_domain}).",
        })

    trusted_ids = {
        value.strip().lower()
        for value in (trusted_authserv_ids or set())
        if value.strip()
    }
    auth_results: dict[str, str] = {}
    untrusted_authentication_claims = []
    for auth_header in message.get_all("Authentication-Results", []):
        authserv_id = auth_header.partition(";")[0].strip().lower()
        claimed_results = {
            mechanism: result
            for mechanism, result in re.findall(
                r"\b(spf|dkim|dmarc)=([a-z]+)", auth_header.lower()
            )
        }
        if claimed_results and authserv_id in trusted_ids and not auth_results:
            auth_results = claimed_results
        elif claimed_results:
            untrusted_authentication_claims.append({
                "authserv_id": authserv_id,
                "results": claimed_results,
            })
    failures = {
        mechanism for mechanism, result in auth_results.items()
        if result in _AUTH_FAILURES
    }
    dmarc_passes = auth_results.get("dmarc") == "pass"
    decisive_failure = (
        auth_results.get("dmarc") in _AUTH_FAILURES
        or {"spf", "dkim"}.issubset(failures)
    )
    if decisive_failure and not dmarc_passes:
        score += 6
        risk_floor = "high"
        indicators.append({
            "level": "high",
            "msg": "Message authentication failed: " + ", ".join(sorted(failures)).upper() + ".",
        })
    elif failures and not dmarc_passes:
        score += 2
        indicators.append({
            "level": "medium",
            "msg": "One authentication mechanism failed: "
                   + ", ".join(sorted(failures)).upper() + ".",
        })

    for attachment in attachments:
        suffix = PurePath(attachment["filename"]).suffix.lower()
        if suffix in _DANGEROUS_EXTENSIONS:
            score += 4
            risk_floor = "high"
            indicators.append({
                "level": "high",
                "msg": f"Potentially dangerous attachment: {attachment['filename']}.",
            })
        elif suffix in _ARCHIVE_EXTENSIONS:
            score += 2
            if risk_floor == "safe":
                risk_floor = "medium"
            indicators.append({
                "level": "medium",
                "msg": (
                    f"Archive attachment requires inspection before opening: "
                    f"{attachment['filename']}."
                ),
            })

    return {
        "input_mode": "raw-email",
        "subject": str(message.get("Subject", "") or ""),
        "body": body,
        "html_body": html,
        "from": str(message.get("From", "") or ""),
        "reply_to": str(message.get("Reply-To", "") or ""),
        "return_path": str(message.get("Return-Path", "") or ""),
        "auth_results": auth_results,
        "authentication_trusted": dmarc_passes,
        "authentication_results_trusted": bool(auth_results),
        "untrusted_authentication_claims": untrusted_authentication_claims,
        "attachments": attachments,
        "structure_score": score,
        "risk_floor": risk_floor,
        "indicators": indicators,
    }
