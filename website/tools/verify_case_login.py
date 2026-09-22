"""Check a saved analyst token against the stable Production site without printing it."""

from getpass import getpass
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener


PRODUCTION_ME = 'https://phishguard-email-analyzer.vercel.app/api/cases/me'


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def verify_token(token, *, opener=None):
    if not isinstance(token, str) or not 32 <= len(token) <= 256 or not token.isascii() or any(c.isspace() for c in token):
        raise ValueError('Paste the token only, without quotes or spaces.')
    request = Request(PRODUCTION_ME, headers={'Authorization': 'Bearer ' + token,
                                              'Accept': 'application/json'})
    try:
        with (opener or build_opener(_NoRedirect()).open)(request, timeout=10) as response:
            if response.geturl() != PRODUCTION_ME:
                raise ValueError('The site redirected away from the Production login endpoint.')
            if not response.headers.get('Content-Type', '').lower().startswith('application/json'):
                raise ValueError('The site returned a non-JSON response.')
            raw = response.read(4097)
    except HTTPError as exc:
        if exc.code == 401:
            raise ValueError('Production rejected this token (HTTP 401).') from None
        if exc.code == 404:
            raise ValueError('Case management is disabled on Production (HTTP 404).') from None
        if exc.code == 503:
            raise ValueError('Production case configuration or storage is unavailable (HTTP 503).') from None
        raise ValueError(f'Production login check failed (HTTP {exc.code}).') from None
    except (OSError, URLError):
        raise ValueError('Could not reach the Production login endpoint.') from None
    if len(raw) > 4096:
        raise ValueError('Production returned an oversized login response.')
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError('Production returned invalid login JSON.') from None
    actor = payload.get('actor') if isinstance(payload, dict) else None
    if not isinstance(actor, str) or not actor:
        raise ValueError('Production did not confirm an analyst identity.')
    return actor


def main():
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise SystemExit('Run in your own interactive terminal; do not redirect token input.')
    print('Production token check. Input is hidden; pasted characters will not appear.')
    token = getpass('Paste your saved analyst token: ').strip()
    try:
        actor = verify_token(token)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    print(f'Production login succeeded for analyst {actor}.')


if __name__ == '__main__':
    main()
