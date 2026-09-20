"""Parse RFC 5322 messages and expose phishing-relevant structural signals."""

from __future__ import annotations

from email import policy
from email.parser import BytesParser, Parser
from email.message import EmailMessage
from email.utils import parseaddr, getaddresses
from pathlib import PurePath
import re
import unicodedata
import codecs
from itertools import product


_AUTH_FAILURES = {"fail", "softfail", "permerror", "temperror"}
MAX_MIME_PARTS = 200


class _MimeResourceLimit(Exception):
    """Abort tree construction before excessive parts or nesting consume resources."""


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


def _brand_identity_signals(display_name: str, from_domain: str) -> tuple[int, list[dict]]:
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


def _mime_candidates(message, warnings):
    """Recover bounded alternate leaf interpretations; never reparse MIME trees."""
    remaining = 32
    names = ('Content-Type', 'Content-Transfer-Encoding', 'Content-Disposition')
    for part in _walk_message_parts(message):
        choices = [[value for key, value in part.raw_items() if key.lower() == name.lower()]
                   for name in names]
        duplicate_names = [name for name, values in zip(names, choices) if len(values) > 1]
        if duplicate_names:
            warnings.append('Duplicate MIME headers (' + ', '.join(duplicate_names)
                            + ') are ambiguous; bounded alternate inspection, analysis is incomplete.')
        yield part
        if not duplicate_names:
            continue
        choices = [list(dict.fromkeys(values)) or [None] for values in choices]
        for index, candidate in enumerate(product(*choices)):
            if index == 0:
                continue  # Original interpretation was already inspected.
            if index > 8 or remaining <= 0:
                warnings.append('MIME candidate limit reached; additional interpretations were not inspected.')
                break
            remaining -= 1
            alternate = EmailMessage(policy=part.policy)
            alternate.set_default_type(part.get_default_type())
            for key, value in part.raw_items():
                if key.lower() not in {name.lower() for name in names}:
                    alternate.set_raw(key, value)
            for name, value in zip(names, candidate):
                if value is not None:
                    alternate.set_raw(name, value)
            alternate.set_payload(part.get_payload())
            yield alternate


def _message_text(message, *, unicode_source: bool = False) -> tuple[str, str, list[dict], list[str], list[dict]]:
    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[dict] = []
    parse_warnings: list[str] = []
    content_parts: list[dict] = []

    for part in _mime_candidates(message, parse_warnings):
        content_type = part.get_content_type()
        if content_type in {'message/rfc822', 'message/global'}:
            attachments.append({'filename': part.get_filename() or 'attached.eml', 'content_type': content_type})
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
        if part.is_multipart():
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
        record = {'content_type': content_type, 'content': str(content)}
        if record in content_parts:
            continue
        content_parts.append(record)
        if content_type == "text/html":
            html_parts.append(str(content))
        else:
            plain_parts.append(str(content))

    attachments = [dict(filename=name, content_type=kind) for name, kind in dict.fromkeys(
        (item['filename'], item['content_type']) for item in attachments)]
    return "\n".join(plain_parts), "\n".join(html_parts), attachments, parse_warnings, content_parts


def analyze_raw_email(
    raw_email: str | bytes,
    *,
    trusted_authserv_ids: set[str] | frozenset[str] | None = None,
) -> dict:
    """Return normalized content plus authentication, identity, and attachment signals."""
    count = 0
    def bounded_factory(*, policy):
        nonlocal count
        count += 1
        if count > MAX_MIME_PARTS:
            raise _MimeResourceLimit()
        return EmailMessage(policy=policy)

    def parse(parser_policy, *, headersonly=False):
        if isinstance(raw_email, bytes):
            return BytesParser(policy=parser_policy).parsebytes(raw_email, headersonly=headersonly)
        return Parser(policy=parser_policy).parsestr(raw_email, headersonly=headersonly)

    limited = False
    try:
        message = parse(policy.default.clone(message_factory=bounded_factory))
    except (_MimeResourceLimit, RecursionError):
        # Headers-only mode never descends into the body. Do not reinterpret
        # unparsed MIME payload as ordinary text or claim it was inspected.
        message = parse(policy.default, headersonly=True)
        message.set_payload('')
        limited = True
    result = _analyze_message(message, unicode_source=isinstance(raw_email, str),
                              trusted_authserv_ids=trusted_authserv_ids, depth=0, budget=[20])
    if limited:
        warning = ('MIME parser resource limit reached; only outer headers were inspected, '
                   'body and attachments were not analyzed. Analysis is incomplete.')
        result['parse_warnings'].append(warning)
        result['indicators'].append({'level': 'info', 'msg': warning})
    return result


def _authentication_results(value: str) -> tuple[str, dict[str, str], bool]:
    """Read result clauses, never method-like text inside comments or strings."""
    segments, current = [], []
    comment_depth = 0
    quoted = escaped = False
    for char in value:
        if escaped:
            if not comment_depth:
                current.append(char)
            escaped = False
        elif char == '\\' and (comment_depth or quoted):
            escaped = True
            if quoted:
                current.append(char)
        elif comment_depth:
            if char == '(':
                comment_depth += 1
            elif char == ')':
                comment_depth -= 1
        elif char == '"':
            quoted = not quoted
            current.append(char)
        elif not quoted and char == '(':
            comment_depth = 1
            current.append(' ')
        elif not quoted and char == ';':
            segments.append(''.join(current).strip())
            current = []
        else:
            current.append(char)
    segments.append(''.join(current).strip())
    complete = not (comment_depth or quoted or escaped)
    identity = re.fullmatch(r'(?:"([^"\\]+)"|([^\s";]+))(?:\s+\d+)?', segments[0])
    authserv_id = (identity.group(1) or identity.group(2)).lower() if identity else ''
    results = {}
    for segment in segments[1:]:
        match = re.match(r'^(spf|dkim|dmarc)(?:\s*/\s*\d+)?\s*=\s*([a-z]+)(?=\s|$)',
                         segment, re.IGNORECASE)
        if match:
            mechanism, result = (part.lower() for part in match.groups())
            results[mechanism] = result
    return authserv_id, results, bool(identity) and complete


def _analyze_message(message, *, unicode_source, trusted_authserv_ids, depth, budget):
    plain, html, attachments, parse_warnings, content_parts = _message_text(message, unicode_source=unicode_source)
    header_candidates = {
        name: []
        for name in ('From', 'To', 'Cc', 'Subject', 'Reply-To', 'Return-Path')
    }
    canonical_names = {name.lower(): name for name in header_candidates}
    # headerregistry can itself raise for malformed address headers. Parse one
    # field at a time, preserving raw candidates and other evidence on failure.
    defect_names = set()
    for part in _walk_message_parts(message):
        defect_names.update(type(defect).__name__ for defect in part.defects)
        for name, raw_value in part.raw_items():
            try:
                header = part.policy.header_fetch_parse(name, raw_value)
                value = str(header)
                defect_names.update(type(defect).__name__ for defect in getattr(header, 'defects', ()))
            except Exception:
                value = raw_value
                warning = f'{name} header could not be parsed; raw value preserved, analysis is incomplete.'
                if warning not in parse_warnings:
                    parse_warnings.append(warning)
            candidate_name = canonical_names.get(name.lower())
            if part is message and candidate_name:
                header_candidates[candidate_name].append(value)
    for name, values in header_candidates.items():
        if len(values) > 1:
            parse_warnings.append(f'Duplicate {name} headers are ambiguous; all candidates inspected, analysis is incomplete.')
    if depth and not (plain.strip() or html.strip() or attachments or any(header_candidates.values())
                      or message.get('Authentication-Results')):
        parse_warnings.append('Attached message has no analyzable content; analysis is incomplete.')
    if defect_names:
        parse_warnings.append('MIME structure is incomplete or malformed ('
                              + ', '.join(sorted(defect_names)) + '); analysis may be incomplete.')
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

    from_mailboxes = [mailbox for value in header_candidates['From']
                      for mailbox in getaddresses([value])]
    from_domains = {_domain(address) for _, address in from_mailboxes} - {''}
    from_addresses = {
        address.strip().lower() for _, address in from_mailboxes if address.strip()
    }
    recipient_addresses = {
        address.strip().lower()
        for name in ('To', 'Cc')
        for value in header_candidates[name]
        for _, address in getaddresses([value])
        if address.strip()
    }
    if not recipient_addresses:
        indicators.append({
            'level': 'info',
            'msg': 'No visible To or Cc recipient is present; the message may have used Bcc.',
        })
    elif from_addresses & recipient_addresses:
        score += 1
        indicators.append({
            'level': 'low',
            'msg': 'Self-addressed message: a From mailbox also appears in To or Cc.',
        })
    brand_score, brand_indicators = max(
        (_brand_identity_signals(name, _domain(address)) for name, address in from_mailboxes),
        key=lambda pair: pair[0], default=(0, []),
    )
    score += brand_score
    indicators.extend(brand_indicators)
    if brand_score:
        risk_floor = "high"

    for name, points, level in (('Reply-To', 4, 'high'), ('Return-Path', 2, 'medium')):
        domains = {_domain(address) for value in header_candidates[name]
                   for _, address in getaddresses([value])} - {''}
        mismatch = next((other for other in sorted(domains) if from_domains
                         and not any(_domains_align(other, sender) for sender in from_domains)), None)
        if mismatch:
            score += points
            indicators.append({'level': level, 'msg':
                f'{name} domain ({mismatch}) differs from From domain candidates ({", ".join(sorted(from_domains))}).'})

    trusted_ids = {
        value.strip().lower()
        for value in (trusted_authserv_ids or set())
        if value.strip()
    }
    auth_results: dict[str, str] = {}
    untrusted_authentication_claims = []
    for auth_header in message.get_all("Authentication-Results", []):
        authserv_id, claimed_results, auth_complete = _authentication_results(str(auth_header))
        if not auth_complete:
            warning = 'Authentication-Results syntax is incomplete; authentication claims require review.'
            if warning not in parse_warnings:
                parse_warnings.append(warning)
                indicators.append({'level': 'info', 'msg': warning})
            # Incomplete claims cannot confer a trusted pass.
            claimed_results = {key: value for key, value in claimed_results.items() if value != 'pass'}
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
        "subject": '\n'.join(header_candidates['Subject']),
        "header_candidates": header_candidates,
        "body": body,
        "html_body": html,
        "content_parts": content_parts,
        "nested_messages": nested_messages,
        "from": next(iter(header_candidates['From']), ''),
        "reply_to": next(iter(header_candidates['Reply-To']), ''),
        "return_path": next(iter(header_candidates['Return-Path']), ''),
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
