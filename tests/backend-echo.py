"""backend-echo.py — backend kiểm thử toàn diện cho guard-go/frp loopback.
Routes (port 18081):
  /               -> 200 hello-backend
  /echo-query     -> 200 raw query string (giữ nguyên, để test multi-value)
  /echo-headers   -> 200 JSON headers backend nhận (test strip/forward)
  /echo-method    -> 200 METHOD path
  /redirect-internal -> 302 Location http://127.0.0.1:18081/secret (test sanitize)
  /redirect-public   -> 302 Location https://example.com/out (giữ nguyên)
  /post-echo      -> 200 số byte body nhận (test body forward + cap)
Stdlib only.
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class H(BaseHTTPRequestHandler):
    server_version = "EchoBackend/9.9"
    sys_version = ""

    def log_message(self, *a):
        pass

    def _send(self, code, body: bytes, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except Exception:
                pass

    def _handle(self):
        from urllib.parse import urlparse
        u = urlparse(self.path)
        if u.path == "/echo-query":
            return self._send(200, u.query.encode() or b"(empty)")
        if u.path == "/echo-headers":
            data = {k: v for k, v in self.headers.items()}
            return self._send(200, json.dumps(data, sort_keys=True).encode())
        if u.path == "/echo-method":
            return self._send(200, f"{self.command} {u.path}".encode())
        if u.path == "/redirect-internal":
            return self._send(302, b"redir", {"Location": "http://127.0.0.1:18081/secret?x=1"})
        if u.path == "/redirect-public":
            return self._send(302, b"redir", {"Location": "https://example.com/out"})
        if u.path == "/post-echo":
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                n = 0
            body = self.rfile.read(n) if n else b""
            return self._send(200, f"got:{len(body)}".encode())
        return self._send(200, b"hello-backend")

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_PATCH = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle

if __name__ == "__main__":
    print("echo-backend :18081 ready", flush=True)
    ThreadingHTTPServer(("127.0.0.1", 18081), H).serve_forever()
