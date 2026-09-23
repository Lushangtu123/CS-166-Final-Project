"""Derive a bounded, read-only text preview from retained original feedback mail."""
import base64
import binascii

from email_structure import analyze_raw_email


def eml_preview(source, *, visible_text, mask_inline_data):
    unavailable = {'status': 'unavailable', 'subject': '', 'body': '', 'truncated': False,
                   'warnings': ['The retained email could not be decoded for preview. Original evidence is unchanged.']}
    encoded = source.get('eml_base64')
    if not isinstance(encoded, str) or not 0 < len(encoded) <= 80000:
        return unavailable
    try:
        raw = base64.b64decode(encoded, validate=True)
        if not raw.strip() or len(raw) > 60000:
            return unavailable
        # No detector, model, trust configuration, or external resource is used.
        structure = analyze_raw_email(raw)
        warnings, pieces = [], []
        remaining = 60000
        truncated = len(structure['subject']) > 500
        pending = [(structure, False)]
        while pending:
            message, nested = pending.pop()
            warnings.extend(message['parse_warnings'])
            texts = ['Attached message: ' + message['subject']] if nested else []
            for part in message['content_parts']:
                content = part['content']
                if part['content_type'] == 'text/html':
                    content = visible_text(content, parse_warnings=warnings)
                texts.append(mask_inline_data(content))
            for content in texts:
                text = ('\n\n' if pieces else '') + content
                pieces.append(text[:remaining])
                truncated |= len(text) > remaining
                remaining -= min(len(text), remaining)
            pending.extend((child, True) for child in reversed(message['nested_messages']))
        if truncated:
            warnings.append('Decoded preview exceeded the display limit and was truncated.')
        warnings = list(dict.fromkeys(str(warning)[:300] for warning in warnings))
        if len(warnings) > 12:
            warnings = warnings[:11] + ['Additional parsing warnings were omitted.']
        return {'status': 'available', 'subject': structure['subject'][:500],
                'body': ''.join(pieces), 'warnings': warnings, 'truncated': truncated}
    except (ValueError, TypeError, LookupError, RecursionError, binascii.Error):
        return unavailable
