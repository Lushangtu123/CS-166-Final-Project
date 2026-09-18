"""Parse RFC 5322 messages and expose phishing-relevant structural signals."""

from __future__ import annotations

from email import policy
from email.parser import BytesParser, Parser
from email.utils import parseaddr
from pathlib import PurePath
import re
import unicodedata
import codecs


_AUTH_FAILURES = {"fail", "softfail", "permerror", "temperror"}
_DANGEROUS_EXTENSIONS = {
    ".bat", ".chm", ".cmd", ".com", ".dll", ".docm", ".exe", ".hta",
    ".html", ".htm", ".img", ".iso", ".jar", ".js", ".lnk", ".msi",
    ".one", ".ps1", ".scr", ".vbs", ".vhd", ".vhdx", ".wsf", ".xlam",
    ".xlsm", ".xll",
}
_ARCHIVE_EXTENSIONS = {".7z", ".gz", ".rar", ".tar", ".tgz", ".zip"}
_DANGEROUS_MIME_TYPES = {
    "application/java-archive",
    "application/javascript",
    "application/vnd.microsoft.portable-executable",
    "application/vnd.ms-excel.addin.macroenabled.12",
    "application/vnd.ms-excel.sheet.binary.macroenabled.12",
    "application/vnd.ms-excel.sheet.macroenabled.12",
    "application/vnd.ms-excel.template.macroenabled.12",
    "application/vnd.ms-powerpoint.addin.macroenabled.12",
    "application/vnd.ms-powerpoint.presentation.macroenabled.12",
    "application/vnd.ms-powerpoint.slideshow.macroenabled.12",
    "application/vnd.ms-powerpoint.template.macroenabled.12",
    "application/vnd.ms-word.document.macroenabled.12",
    "application/vnd.ms-word.template.macroenabled.12",
    "application/x-apple-diskimage",
    "application/x-bat",
    "application/x-dosexec",
    "application/x-executable",
    "application/x-iso9660-image",
    "application/x-java-archive",
    "application/x-msdos-program",
    "application/x-msdownload",
    "application/x-sh",
    "text/javascript",
}
_ARCHIVE_MIME_TYPES = {
    "application/gzip",
    "application/vnd.rar",
    "application/x-7z-compressed",
    "application/x-gzip",
    "application/x-rar-compressed",
    "application/x-tar",
    "application/x-zip-compressed",
    "application/zip",
}
_PROTECTED_BRAND_DOMAINS = {
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de"},
    "google": {"google.com", "google.co.uk", "googleusercontent.com"},
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


def normalize_domain(domain: str) -> str:
    try:
        return domain.encode('idna').decode('ascii').lower().rstrip('.')
    except UnicodeError:
        return ''


def _domain(address: str) -> str:
    parsed = parseaddr(address or "")[1].lower()
    return normalize_domain(parsed.rsplit("@", 1)[-1]) if "@" in parsed else ""


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


def _walk_message_parts(message):
    """Walk one message, leaving encapsulated messages to bounded analysis."""
    pending = [message]
    while pending:
        part = pending.pop()
        yield part
        if part.is_multipart() and part.get_content_type() not in {'message/rfc822', 'message/global'}:
            pending.extend(reversed(part.get_payload()))


def _message_text(message, *, unicode_source: bool = False) -> tuple[str, str, list[dict], list[str], list[dict]]:
    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[dict] = []
    parse_warnings: list[str] = []
    content_parts: list[dict] = []

    for part in _walk_message_parts(message):
        content_type = part.get_content_type()
        if content_type in {'message/rfc822', 'message/global'}:
            attachments.append({'filename': part.get_filename() or 'attached.eml', 'content_type': content_type})
            continue
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if (
            filename
            or disposition == "attachment"
            or content_type in _DANGEROUS_MIME_TYPES
            or content_type in _ARCHIVE_MIME_TYPES
        ):
            attachments.append({
                "filename": filename or "unnamed",
                "content_type": content_type,
            })
            if PurePath(filename or '').suffix.lower() == '.eml':
                warning = 'Opaque .eml attachment was not parsed as an encapsulated message; analysis is incomplete.'
                if warning not in parse_warnings:
                    parse_warnings.append(warning)
            continue
        if content_type not in {"text/plain", "text/html"}:
            continue
        try:
            if unicode_source and str(part.get('Content-Transfer-Encoding', '')).lower() not in {'base64', 'quoted-printable'}:
                # Legacy JSON already contains Unicode text, not original MIME
                # bytes. Do not round-trip it through raw-unicode-escape.
                codecs.lookup(part.get_content_charset() or 'utf-8')
                content = part.get_payload()
            else:
                content = part.get_content(errors='strict')
        except Exception:
            payload = part.get_payload(decode=True) or b""
            try:
                content = payload.decode(part.get_content_charset() or 'utf-8', errors='replace')
            except (LookupError, UnicodeError):
                content = payload.decode('utf-8', errors='replace')
            warning = "MIME text decoding required a fallback or replacement; analysis may be incomplete."
            if warning not in parse_warnings:
                parse_warnings.append(warning)
        content_parts.append({'content_type': content_type, 'content': str(content)})
        if content_type == "text/html":
            html_parts.append(str(content))
        else:
            plain_parts.append(str(content))

    return "\n".join(plain_parts), "\n".join(html_parts), attachments, parse_warnings, content_parts


def analyze_raw_email(
    raw_email: str | bytes,
    *,
    trusted_authserv_ids: set[str] | frozenset[str] | None = None,
) -> dict:
    """Return normalized content plus authentication, identity, and attachment signals."""
    if isinstance(raw_email, bytes):
        message = BytesParser(policy=policy.default).parsebytes(raw_email)
    else:
        message = Parser(policy=policy.default).parsestr(raw_email)
    return _analyze_message(message, unicode_source=isinstance(raw_email, str),
                            trusted_authserv_ids=trusted_authserv_ids, depth=0, budget=[20])


def _analyze_message(message, *, unicode_source, trusted_authserv_ids, depth, budget):
    plain, html, attachments, parse_warnings, content_parts = _message_text(message, unicode_source=unicode_source)
    if depth and not (plain.strip() or html.strip() or attachments or any(
            message.get(name) for name in ('Subject', 'From', 'Reply-To', 'Return-Path', 'Authentication-Results'))):
        parse_warnings.append('Attached message has no analyzable content; analysis is incomplete.')
    # The parser recovers without raising; decoding may append more defects.
    defect_names = sorted({type(defect).__name__ for part in _walk_message_parts(message)
                           for defect in part.defects})
    if defect_names:
        parse_warnings.append('MIME structure is incomplete or malformed ('
                              + ', '.join(defect_names) + '); analysis may be incomplete.')
    nested_messages = []
    for part in _walk_message_parts(message):
        if part.get_content_type() not in {'message/rfc822', 'message/global'}:
            continue
        encoding = str(part.get('Content-Transfer-Encoding', '')).strip().lower()
        if encoding not in {'', '7bit', '8bit', 'binary'}:
            warning = 'Transfer-encoded attached message was not inspected; analysis is incomplete.'
            if warning not in parse_warnings:
                parse_warnings.append(warning)
            continue
        children = part.get_payload()
        if not isinstance(children, list) or not children:
            parse_warnings.append('Attached message could not be parsed; analysis is incomplete.')
            continue
        for child in children:
            if depth >= 3 or budget[0] <= 0:
                warning = 'Attached-message depth/count limit reached; analysis is incomplete.'
                if warning not in parse_warnings:
                    parse_warnings.append(warning)
                break
            budget[0] -= 1
            nested = _analyze_message(child, unicode_source=unicode_source,
                                      trusted_authserv_ids=set(), depth=depth + 1, budget=budget)
            nested_messages.append(nested)
            for warning in nested['parse_warnings']:
                prefixed = 'Attached message: ' + warning
                if prefixed not in parse_warnings:
                    parse_warnings.append(prefixed)
    # Analyze both alternatives. Phishers commonly put harmless text in the
    # plain part and the credential link only in the HTML part.
    body = "\n".join(part for part in (plain, html) if part)
    indicators: list[dict] = [
        {"level": "info", "msg": warning} for warning in parse_warnings
    ]
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
        content_type = attachment["content_type"].lower().split(";", 1)[0].strip()
        if suffix in _DANGEROUS_EXTENSIONS or content_type in _DANGEROUS_MIME_TYPES:
            score += 4
            risk_floor = "high"
            indicators.append({
                "level": "high",
                "msg": f"Potentially dangerous attachment: {attachment['filename']}.",
            })
        elif suffix in _ARCHIVE_EXTENSIONS or content_type in _ARCHIVE_MIME_TYPES:
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
        "content_parts": content_parts,
        "nested_messages": nested_messages,
        "from": str(message.get("From", "") or ""),
        "reply_to": str(message.get("Reply-To", "") or ""),
        "return_path": str(message.get("Return-Path", "") or ""),
        "auth_results": auth_results,
        "authentication_trusted": dmarc_passes,
        "authentication_results_trusted": bool(auth_results),
        "untrusted_authentication_claims": untrusted_authentication_claims,
        "attachments": attachments,
        "parse_warnings": parse_warnings,
        "structure_score": score,
        "risk_floor": risk_floor,
        "indicators": indicators,
    }
