"""Run interactively to generate one analyst credential; never commit the output.

The token is displayed once for the administrator to save in a password manager.
Merge the emitted actor/hash into CASE_ANALYST_TOKEN_HASHES in the deployment
settings. Removing an actor or replacing its hash revokes the old credential on
new deployments. Existing deployments must also be protected or removed.
"""
from getpass import getpass
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
    reuse = input('Use a token you already saved? [y/N]: ').strip().lower()
    if reuse == 'y':
        token = getpass('Paste your existing token (hidden): ').strip()
        if not 32 <= len(token) <= 256 or not token.isascii() or any(c.isspace() for c in token):
            raise SystemExit('Invalid token: paste the token only, without quotes or spaces.')
    else:
        token = secrets.token_urlsafe(32)
        print('\nSave this access token privately in your password manager:\n' + token)
    print('\nCopy the ENTIRE JSON line below, including braces and double quotes. Do not paste the token into Vercel.')
    print('\nAdd this analyst/hash to CASE_ANALYST_TOKEN_HASHES (preserve existing analysts):')
    print(json.dumps({actor: hashlib.sha256(token.encode()).hexdigest()}))
    print('\nDo not share the token in chat, Git, logs or screenshots.')


if __name__ == '__main__':
    main()
