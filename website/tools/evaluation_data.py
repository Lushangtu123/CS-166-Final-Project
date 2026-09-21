"""Bounded, local-only public evaluation inputs and conservative overlap fingerprints.

Manifests are provenance declarations, not proof of license suitability, label quality
or training independence. No referenced web address is requested by this module.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from email import policy
from email.parser import BytesParser
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from .evaluate_serving_pipeline import _json_bytes, MAX_EML_BYTES

MAX_MANIFEST_BYTES = 512_000
MAX_JSONL_BYTES = 64_000_000
MAX_RECORD_BYTES = 256_000
MAX_RECORDS = 10_000
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,99}')


@dataclass
class Corpus:
    records: list[dict]
    sources: list[dict]
    dataset_sha256: str
    manifest_sha256: str
    records_sha256: str
    exploratory_only: bool


def _read(path: Path, limit: int) -> bytes:
    try:
        if not path.is_file() or path.stat().st_size > limit:
            raise ValueError()
        with path.open('rb') as stream:
            value = stream.read(limit + 1)
        if not value.strip() or len(value) > limit:
            raise ValueError()
        return value
    except (OSError, ValueError):
        raise ValueError('Local input is missing, empty, nonregular or exceeds its size limit') from None


def _local_path(base: Path, value) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise ValueError('Input paths must be relative to the manifest directory')
    target = (base / value).resolve()
    if not target.is_relative_to(base.resolve()):
        raise ValueError('Input path escapes the manifest directory')
    return target


class _VisibleHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden = 0
        self.parts = []
    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self.hidden += 1
    def handle_endtag(self, tag):
        if tag in ('script', 'style') and self.hidden:
            self.hidden -= 1
    def handle_data(self, value):
        if not self.hidden:
            self.parts.append(value)


def _visible(text: str) -> str:
    parser = _VisibleHTML()
    parser.feed(text)
    return ' '.join(parser.parts)


def _eml_text(raw: bytes) -> str:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    parts = [str(message.get('subject', ''))]
    count = 0
    for part in message.walk():
        count += 1
        if count > 100:
            raise ValueError('Email has too many MIME parts for evaluation')
        if part.get_content_disposition() == 'attachment' or part.get_content_type() not in ('text/plain', 'text/html'):
            continue
        payload = part.get_payload(decode=True) or b''
        try:
            text = payload.decode(part.get_content_charset() or 'utf-8', errors='replace')
        except LookupError:
            text = payload.decode('utf-8', errors='replace')
        parts.append(_visible(text) if part.get_content_type() == 'text/html' else text)
    return '\n'.join(parts)


def template_fingerprint(text: str) -> str | None:
    """Heuristic overlap signal; exact text/URLs are still used for real analysis.

Require at least 80 characters and 12 words to avoid collapsing short subjects.
This catches only simple template variants, not every paraphrase or MIME variant.
"""
    value = text.casefold()
    value = re.sub(r'https?://[^\s<>]+', '<url>', value)
    value = re.sub(r'\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b', '<email>', value)
    value = re.sub(r'\d+', '<number>', value)
    value = re.sub(r'\s+', ' ', value).strip()
    if len(value) < 80 or len(value.split()) < 12:
        return None
    return hashlib.sha256(value.encode()).hexdigest()


def _source(value) -> dict:
    fields = ('id', 'url', 'revision', 'license', 'label_basis')
    if not isinstance(value, dict) or any(not isinstance(value.get(key), str) or not value[key].strip() for key in fields):
        raise ValueError('Each source requires id, url, revision, license and label_basis')
    if not ID.fullmatch(value['id']) or any(len(value[key]) > 2000 for key in fields):
        raise ValueError('Source metadata exceeds permitted bounds')
    url = urlsplit(value['url'])
    if url.scheme not in ('https', 'http') or not url.hostname or url.username or url.password:
        raise ValueError('Source URL must be a public HTTP(S) provenance URL without credentials')
    if value['revision'].strip().lower() in {'main', 'master', 'head', 'latest', 'unknown'}:
        raise ValueError('Source revision must identify a fixed version')
    return {key: value[key] for key in fields}


def load_corpus(manifest_path: Path) -> Corpus:
    """Validate and snapshot the complete corpus before any inference is attempted."""
    manifest_path = Path(manifest_path)
    raw_manifest = _read(manifest_path, MAX_MANIFEST_BYTES)
    try:
        manifest = json.loads(raw_manifest)
    except (ValueError, UnicodeError):
        raise ValueError('Manifest contains invalid JSON') from None
    if not isinstance(manifest, dict) or type(manifest.get('schema_version')) is not int or manifest['schema_version'] != 1:
        raise ValueError('Manifest schema_version must be 1')
    if not isinstance(manifest.get('sources'), list) or not 1 <= len(manifest['sources']) <= 100:
        raise ValueError('Manifest requires 1 to 100 sources')
    sources = [_source(source) for source in manifest['sources']]
    source_ids = {source['id'] for source in sources}
    if len(source_ids) != len(sources):
        raise ValueError('Duplicate source IDs')
    exploratory = manifest.get('exploratory_only', True)
    if not isinstance(exploratory, bool):
        raise ValueError('exploratory_only must be boolean')
    raw_records = _read(_local_path(manifest_path.parent, manifest.get('records')), MAX_JSONL_BYTES)
    records, ids, fingerprints = [], set(), []
    total_message_bytes = 0
    for line_number, line in enumerate(raw_records.splitlines(), 1):
        if not line.strip():
            continue
        if len(line) > MAX_RECORD_BYTES or len(records) >= MAX_RECORDS:
            raise ValueError('Corpus exceeds the record count or line size limit')
        try:
            row = json.loads(line)
        except (ValueError, UnicodeError):
            raise ValueError(f'Line {line_number}: invalid JSON') from None
        if not isinstance(row, dict) or not isinstance(row.get('id'), str) or not ID.fullmatch(row['id']):
            raise ValueError(f'Line {line_number}: invalid record ID')
        if row['id'] in ids:
            raise ValueError(f'Line {line_number}: duplicate record ID')
        ids.add(row['id'])
        if (not isinstance(row.get('source_id'), str) or row['source_id'] not in source_ids
                or not isinstance(row.get('label'), str) or row['label'] not in {'phishing', 'legitimate'}):
            raise ValueError(f'Line {line_number}: invalid source or label')
        item = {key: row[key] for key in ('id', 'source_id', 'label')}
        for field in ('provider', 'language'):
            value = row.get(field)
            if value is not None and (not isinstance(value, str) or not re.fullmatch(r'[a-z][a-z0-9_-]{1,39}', value)):
                raise ValueError(f'Line {line_number}: invalid {field}')
            item[field] = value or 'unknown'
        received = row.get('received_at')
        if received is not None:
            try:
                if not isinstance(received, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', received):
                    raise ValueError()
                date.fromisoformat(received)
            except ValueError:
                raise ValueError(f'Line {line_number}: invalid received_at') from None
        item['received_at'] = received
        if 'eml_path' in row:
            if any(row.get(key) for key in ('subject', 'body', 'raw_email')):
                raise ValueError(f'Line {line_number}: ambiguous message input')
            raw = _read(_local_path(manifest_path.parent, row['eml_path']), MAX_EML_BYTES)
            item.update(eml_path='snapshot.eml', _eml_bytes=raw)
            try:
                text = _eml_text(raw)
            except Exception:
                raise ValueError(f'Line {line_number}: malformed MIME input') from None
            payload = b'eml\0' + raw
        else:
            if 'raw_email' in row or any(not isinstance(row.get(key, ''), str) for key in ('subject', 'body')):
                raise ValueError(f'Line {line_number}: subject and body must be text')
            item.update(subject=row.get('subject', ''), body=row.get('body', ''))
            if not (item['subject'] + item['body']).strip():
                raise ValueError(f'Line {line_number}: message content is required')
            raw = _json_bytes([item['subject'], item['body']])
            if len(raw) > MAX_EML_BYTES:
                raise ValueError(f'Line {line_number}: message exceeds size limit')
            text = item['subject'] + '\n' + _visible(item['body'])
            payload = b'text\0' + raw
        total_message_bytes += len(raw)
        if total_message_bytes > MAX_JSONL_BYTES:
            raise ValueError('Combined message content exceeds corpus size limit')
        content_hash = hashlib.sha256(raw).hexdigest()
        if 'content_sha256' in row and row['content_sha256'] != content_hash:
            raise ValueError(f'Line {line_number}: content hash mismatch')
        item['_exact_sha256'] = hashlib.sha256(payload).hexdigest()
        item['_template_sha256'] = template_fingerprint(text)
        item['_content_sha256'] = content_hash
        fingerprints.append(hashlib.sha256(_json_bytes({key: item[key] for key in (
            'id', 'source_id', 'label', 'provider', 'language', 'received_at', '_content_sha256')})).digest())
        records.append(item)
    if not records:
        raise ValueError('No evaluation records supplied')
    dataset_hash = hashlib.sha256(b'public-corpus-v1\0' + _json_bytes(sorted(sources, key=lambda item: item['id'])) +
                                  b''.join(sorted(fingerprints))).hexdigest()
    return Corpus(records, sources, dataset_hash, hashlib.sha256(raw_manifest).hexdigest(),
                  hashlib.sha256(raw_records).hexdigest(), exploratory)
