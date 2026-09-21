"""Run interactively to generate one analyst credential; never commit the output.

The token is displayed once for the administrator to save in a password manager.
Merge the emitted actor/hash into CASE_ANALYST_TOKEN_HASHES in the deployment
settings. Removing an actor or replacing its hash revokes the old credential on
new deployments. Existing deployments must also be protected or removed.
"""
import hashlib
import json
import re
import secrets
import sys


def main():
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise SystemExit('Run this command in your own interactive terminal; do not redirect credential output.')
    actor = input('Analyst ID (letters, digits, _, ., -): ').strip()
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}', actor):
        raise SystemExit('Invalid analyst ID')
    token = secrets.token_urlsafe(32)
    print('\nSave this access token privately in your password manager:\n' + token)
    print('\nAdd this analyst/hash to CASE_ANALYST_TOKEN_HASHES (preserve existing analysts):')
    print(json.dumps({actor: hashlib.sha256(token.encode()).hexdigest()}))
    print('\nDo not share the token in chat, Git, logs or screenshots.')


if __name__ == '__main__':
    main()
