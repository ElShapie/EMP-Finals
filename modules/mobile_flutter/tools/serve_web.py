import os
import urllib.error
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

WEB_ROOT = Path(__file__).resolve().parents[1] / "build" / "web"
FRIGATE = os.environ.get("FRIGATE_URL", "http://127.0.0.1:5000").rstrip("/")
PORT = int(os.environ.get("PORT", "9000"))


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_ROOT), **kwargs)

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        if self.path.startswith("/api/"):
            return self.proxy()
        return super().do_GET()

    def do_HEAD(self):
        if self.path.startswith("/api/"):
            return self.proxy(head=True)
        return super().do_HEAD()

    def proxy(self, head=False):
        req = urllib.request.Request(FRIGATE + self.path, headers={"Accept": "*/*"})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                body = b"" if head else resp.read()
                length = int(resp.headers.get("Content-Length", len(body))) if head else len(body)
                self.send_response(resp.status)
                self.send_header("Content-Type", resp.headers.get("Content-Type", "application/octet-stream"))
                self.send_header("Content-Length", str(length))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                if not head:
                    self.wfile.write(body)
        except urllib.error.HTTPError as exc:
            body = exc.read()
            self.send_response(exc.code)
            self.send_header("Content-Type", exc.headers.get("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if not head:
                self.wfile.write(body)
        except Exception as exc:
            body = str(exc).encode()
            self.send_response(502)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if not head:
                self.wfile.write(body)


if __name__ == "__main__":
    if not (WEB_ROOT / "index.html").exists():
        raise SystemExit(f"No existe {WEB_ROOT}. Ejecuta primero: flutter build web --release")
    print(f"Serving {WEB_ROOT} on http://0.0.0.0:{PORT} (proxy /api -> {FRIGATE})", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
