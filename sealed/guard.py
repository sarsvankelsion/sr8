"""Sealed Link Guard — lớp đột phá phía trước frps vhost.
Kiến trúc: visitor -> guard(:19090) -> frps vhost(:18080) -> backend.
Guard verify HMAC(secret, "name:exp") + expiry + single-use trước khi forward.
Không sửa frp, không cần password prompt như PortBuddy -pc.
Stdlib only, chạy 1 file trên mọi máy.
"""
import hashlib
import hmac
import json
import os
import tempfile
import time
import urllib.parse
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

GUARD_PORT = int(os.environ.get("GUARD_PORT", "19090"))
FRPS_VHOST = os.environ.get("FRPS_VHOST", "127.0.0.1:18080")
# Hỗ trợ dynamic host: " {name}.tunnel.example.com" -> thay {name} bằng tên link.
# Loopback test để "loopback.test". Production để "{name}.tunnel.example.com".
VHOST_HOST = os.environ.get("VHOST_HOST", "loopback.test")
SEAL_SECRET = os.environ.get("SEAL_SECRET", "CHANGE-ME-SEAL-SECRET-32-CHARS")
USED_DB = os.environ.get("SEAL_USED_DB", os.path.join(tempfile.gettempdir(), "sealed-used.json"))
SINGLE_USE = os.environ.get("SEAL_SINGLE_USE", "1") == "1"


def load_used():
    try:
        with open(USED_DB, "r", encoding="utf-8") as f:
            return set(json.load(f))
    except Exception:
        return set()


def save_used(s):
    try:
        with open(USED_DB, "w", encoding="utf-8") as f:
            json.dump(sorted(s), f)
    except Exception:
        pass


def expected_seal(name, exp):
    msg = f"{name}:{exp}".encode()
    return hmac.new(SEAL_SECRET.encode(), msg, hashlib.sha256).hexdigest()


FORWARD_VISITOR_IP = os.environ.get("SEAL_FORWARD_IP", "0") == "1"
# Header nào của visitor KHÔNG bao giờ forward về backend (chống lộ IP + chống replay seal qua Referer).
STRIP_REQ = {
    "host", "content-length", "connection", "referer", "referrer",
    "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-real-ip",
    "forwarded", "cf-connecting-ip", "true-client-ip", "fastly-client-ip",
}
# Header nào của backend KHÔNG trả về visitor (chống lộ fingerprint nội bộ).
STRIP_RESP = {"transfer-encoding", "connection", "server"}


class Handler(BaseHTTPRequestHandler):
    # Giả fingerprint generic, không lộ "SealedGuard/Python".
    server_version = "nginx"
    sys_version = ""

    def log_message(self, *a):
        pass

    def _deny(self, code, msg):
        body = msg.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _handle(self):
        u = urllib.parse.urlparse(self.path)
        parts = u.path.strip("/").split("/")
        # GET /healthz -> ok không cần seal (cho monitor nội bộ)
        if u.path == "/healthz":
            return self._deny(200, "guard ok")
        if len(parts) < 2 or parts[0] != "t":
            return self._deny(404, "use /t/<name>/?exp=..&seal=..")
        name = parts[1]
        qs = urllib.parse.parse_qs(u.query)
        exp = (qs.get("exp") or [None])[0]
        seal = (qs.get("seal") or [None])[0]
        if not exp or not seal:
            return self._deny(403, "missing exp/seal")
        try:
            if int(exp) < int(time.time()):
                return self._deny(403, "link expired")
        except ValueError:
            return self._deny(403, "bad exp")
        if not hmac.compare_digest(expected_seal(name, exp), seal):
            return self._deny(403, "bad seal")
        used = load_used()
        key = f"{name}:{exp}:{seal[:16]}"
        if SINGLE_USE and key in used:
            return self._deny(403, "link already used")
        # Forward sang frps vhost, giữ Host để frp routing đúng proxy
        fwd_path = "/" + "/".join(parts[2:])
        if u.query:
            # strip seal/exp khỏi backend? giữ nguyên cũng vô hại, strip cho sạch
            q = {k: v for k, v in qs.items() if k not in ("seal", "exp")}
            flat = "&".join(f"{k}={v[0]}" for k, v in q.items())
            if flat:
                fwd_path += "?" + flat
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        host, _, port = FRPS_VHOST.partition(":")
        conn = http.client.HTTPConnection(host, int(port or 80), timeout=15)
        vhost = VHOST_HOST.replace("{name}", name)
        fwd_headers = {"Host": vhost, "X-Sealed-Name": name}
        if FORWARD_VISITOR_IP:
            fwd_headers["X-Sealed-Visitor"] = self.client_address[0]
        for k, v in self.headers.items():
            if k.lower() in STRIP_REQ:
                continue
            fwd_headers[k] = v
        try:
            conn.request(self.command, fwd_path or "/", body=body, headers=fwd_headers)
            resp = conn.getresponse()
            data = resp.read()
        except Exception:
            return self._deny(502, "upstream fail")
        finally:
            conn.close()
        if SINGLE_USE:
            used.add(key)
            save_used(used)
        self.send_response(resp.status)
        for k, v in resp.getheaders():
            if k.lower() in STRIP_RESP:
                continue
            # Chặn backend redirect lộ host/port nội bộ (vd Location: http://127.0.0.1:18081/...)
            if k.lower() == "location" and ("127.0.0.1" in v or "localhost" in v or ":1808" in v):
                v = "/"
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_PATCH = _handle


if __name__ == "__main__":
    print(f"guard :{GUARD_PORT} -> {FRPS_VHOST} (Host={VHOST_HOST}) single_use={SINGLE_USE}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", GUARD_PORT), Handler).serve_forever()
