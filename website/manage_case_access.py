"""Run interactively to generate or preserve analyst credentials.

The token is displayed once for the administrator to save in a password manager.
The tool accepts the current CASE_ANALYST_TOKEN_HASHES value and emits a complete
merged replacement. It refuses to overwrite an existing analyst unless the
administrator explicitly confirms a rotation.
"""
from getpass import getpass
import hashlib
import json
import re
import secrets
import sys


ACTOR_PATTERN = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}')
DIGEST_PATTERN = re.compile(r'[0-9a-f]{64}')


class RotationRequired(ValueError):
    """An existing analyst's credential would be replaced."""


def parse_existing_mapping(raw):
    try:
        mapping = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        raise ValueError('Existing value must be a JSON object.') from None
    if not isinstance(mapping, dict):
        raise ValueError('Existing value must be a JSON object.')
    if len(mapping) > 50:
        raise ValueError('At most 50 analyst credentials are supported.')
    if any(not isinstance(actor, str) or not ACTOR_PATTERN.fullmatch(actor)
           or not isinstance(digest, str) or not DIGEST_PATTERN.fullmatch(digest)
           for actor, digest in mapping.items()):
        raise ValueError('Existing JSON contains an invalid analyst ID or SHA-256 hash.')
    if len(set(mapping.values())) != len(mapping):
        raise ValueError('Each analyst must have a distinct credential hash.')
    return mapping


def merge_credential(existing, actor, digest, *, allow_rotation=False):
    if not ACTOR_PATTERN.fullmatch(actor) or not DIGEST_PATTERN.fullmatch(digest):
        raise ValueError('Invalid analyst ID or SHA-256 hash.')
    duplicate = next((name for name, value in existing.items()
                      if name != actor and value == digest), None)
    if duplicate:
        raise ValueError(f'This credential already belongs to analyst {duplicate}.')
    if actor in existing:
        if existing[actor] == digest:
            return dict(existing), False
        if not allow_rotation:
            raise RotationRequired(
                f'Analyst {actor} already exists. Type ROTATE only if the old token should be revoked.')
    if actor not in existing and len(existing) >= 50:
        raise ValueError('At most 50 analyst credentials are supported.')
    merged = dict(existing)
    merged[actor] = digest
    return merged, True


def main():
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise SystemExit('Run this command in your own interactive terminal; do not redirect credential output.')
    actor = input('Analyst ID (letters, digits, _, ., -): ').strip()
    if not ACTOR_PATTERN.fullmatch(actor):
        raise SystemExit('Invalid analyst ID')
    raw = getpass(
        'Paste the current CASE_ANALYST_TOKEN_HASHES JSON (hidden; use {} only for first setup): ').strip()
    try:
        existing = parse_existing_mapping(raw)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    reuse = input('Use a token you already saved? [y/N]: ').strip().lower()
    rotation_confirmed = False
    if reuse == 'y':
        token = getpass('Paste your existing token (hidden): ').strip()
        if not 32 <= len(token) <= 256 or not token.isascii() or any(c.isspace() for c in token):
            raise SystemExit('Invalid token: paste the token only, without quotes or spaces.')
    else:
        if actor in existing:
            print('\nWARNING: generating a replacement token will revoke the old one on new deployments.')
            if input('Type ROTATE to continue, or press Enter to stop: ').strip() != 'ROTATE':
                raise SystemExit('Credential was not changed.')
            rotation_confirmed = True
        token = secrets.token_urlsafe(32)
        print('\nSave this access token privately in your password manager:\n' + token)
    try:
        digest = hashlib.sha256(token.encode()).hexdigest()
        try:
            merged, changed = merge_credential(
                existing, actor, digest, allow_rotation=rotation_confirmed)
        except RotationRequired:
            print('\nWARNING: replacing this analyst hash revokes the old token on new deployments.')
            if input('Type ROTATE to continue, or press Enter to stop: ').strip() != 'ROTATE':
                raise SystemExit('Credential was not changed.')
            merged, changed = merge_credential(existing, actor, digest, allow_rotation=True)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    if not changed:
        print('\nThe existing mapping already contains this analyst and token; no rotation is needed.')
    print('\nCopy the ENTIRE merged JSON line below into the intended Vercel environment.')
    print('Do not paste the token itself into Vercel. Production and Preview use separate values.')
    print(json.dumps(merged, sort_keys=True, separators=(',', ':')))
    print('\nDo not share the token in chat, Git, logs or screenshots.')


if __name__ == '__main__':
    main()
