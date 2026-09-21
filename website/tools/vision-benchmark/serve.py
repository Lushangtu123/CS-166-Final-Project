"""Local-only benchmark host. No production mount, dependencies, or case API."""
import argparse
import hashlib
import json
import mimetypes
from pathlib import Path
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler

HERE = Path(__file__).resolve().parent
WEBSITE = HERE.parent.parent


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def identity(risk_enabled):
    files = ['vision.js', 'vision-worker.mjs', 'vision-core.mjs', 'vision-email.mjs', 'vendor/vision/manifest.json']
    try:
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=WEBSITE, text=True).strip()
        dirty = bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=WEBSITE, text=True).strip())
    except (OSError, subprocess.CalledProcessError):
        commit = None
        dirty = None
    assets = WEBSITE / 'static/vendor/vision'
    expected = json.loads((assets / 'manifest.json').read_text())['files']
    mismatches = [name for name, details in expected.items()
                  if not (assets / name).is_file() or hashlib.sha256((assets / name).read_bytes()).hexdigest() != details['sha256']]
    return {'code_commit': commit, 'working_tree_dirty': dirty, 'risk_enabled': risk_enabled,
            'evaluation_sha256': {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in ['metrics.mjs', 'harness.mjs', 'serve.py']},
            'asset_count': len(expected), 'asset_manifest_verified': not mismatches, 'asset_mismatches': mismatches,
            'extraction_sha256': {name: hashlib.sha256((WEBSITE / 'static' / name).read_bytes()).hexdigest() for name in files}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8930)
    parser.add_argument('--api-port', type=int, help='Optional local backend port; only POST /api/analyze-visual is forwarded.')
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or args.api_port is not None and not 1 <= args.api_port <= 65535:
        parser.error('Ports must be 1–65535.')
    if args.port == args.api_port:
        parser.error('Backend and harness ports must differ.')
    metadata = identity(args.api_port is not None)
    opener = build_opener(ProxyHandler({}), NoRedirect())

    class Handler(BaseHTTPRequestHandler):
        def allowed(self):
            return self.headers.get('Host') in {f'127.0.0.1:{args.port}', f'localhost:{args.port}'}

        def respond(self, data, content_type, status=200):
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self'; img-src 'self' blob:; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if not self.allowed():
                return self.respond(b'Local host required.', 'text/plain', 403)
            path = unquote(urlsplit(self.path).path)
            if path == '/identity.json':
                return self.respond(json.dumps(metadata).encode(), 'application/json')
            root = WEBSITE / 'static' if path.startswith('/static/') else HERE
            relative = path[len('/static/'):] if path.startswith('/static/') else path.lstrip('/') or 'index.html'
            target = (root / relative).resolve()
            allowed_harness = {'index.html', 'harness.css', 'harness.mjs', 'metrics.mjs'}
            if not target.is_relative_to(root) or not target.is_file() or (root == HERE and relative not in allowed_harness):
                return self.respond(b'Not found.', 'text/plain', 404)
            content_type = 'text/javascript' if target.suffix in {'.js', '.mjs'} else mimetypes.guess_type(target)[0] or 'application/octet-stream'
            self.respond(target.read_bytes(), content_type)

        def do_POST(self):
            if not self.allowed() or self.headers.get('Origin') not in {f'http://127.0.0.1:{args.port}', f'http://localhost:{args.port}'}:
                return self.respond(b'Local origin required.', 'text/plain', 403)
            if self.path != '/api/analyze-visual' or not args.api_port:
                return self.respond(b'Local risk API disabled.', 'text/plain', 404)
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 < size <= 3 * 1024 * 1024:
                    raise ValueError('Size limit')
                data = self.rfile.read(size)
                parsed = json.loads(data)
                # The image benchmark does not forward original images or email bytes.
                if not isinstance(parsed, dict) or set(parsed) - {'observations', 'warnings'}:
                    raise ValueError('Unexpected evidence fields')
                request = Request(f'http://127.0.0.1:{args.api_port}/api/analyze-visual', data=data, headers={'Content-Type': 'application/json'})
                with opener.open(request, timeout=25) as response:
                    body = response.read(3 * 1024 * 1024 + 1)
                    if len(body) > 3 * 1024 * 1024:
                        raise ValueError('Response size limit')
                    self.respond(body, 'application/json')
            except Exception:
                self.respond(b'{"error":"Local risk request failed"}', 'application/json', 502)

    print(f'Local benchmark: http://127.0.0.1:{args.port}/', flush=True)
    ThreadingHTTPServer(('127.0.0.1', args.port), Handler).serve_forever()


if __name__ == '__main__':
    main()
