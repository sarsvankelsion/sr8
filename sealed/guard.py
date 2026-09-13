"""Sealed Link Guard — lớp đột phá phía trước frps vhost.
Kiến trúc: visitor -> guard(:19090) -> frps vhost(:18080) -> backend.
2 chế độ:
  /t/<name>/?exp=..&seal=..   link 1-1: HMAC(secret,"name:exp") + expiry + single-use.
  /r/<room>/?ticket=..        phòng chung xoay vòng: ticket = HMAC(secret,"room:<round>"),
                              round = floor(now / ROTATE_SECS). Ticket leak tự chết sau ~2 vòng.
Không sửa frp. Stdlib only, chạy 1 file trên mọi máy.
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
# Hỗ trợ dynamic host: "{name}.tunnel.example.com" -> thay {name} bằng tên link/room.
# Loopback test để "loopback.test". Production để "{name}.tunnel.example.com".
VHOST_HOST = os.environ.get("VHOST_HOST", "loopback.test")
SEAL_SECRET = os.environ.get("SEAL_SECRET", "CHANGE-ME-SEAL-SECRET-32-CHARS")
USED_DB = os.environ.get("SEAL_USED_DB", os.path.join(tempfile.gettempdir(), "sealed-used.json"))
SINGLE_USE = os.environ.get("SEAL_SINGLE_USE", "1") == "1"
# Phòng chung xoay vòng: ticket đổi mỗi ROTATE_SECS giây, chấp nhận vòng hiện tại + 1 vòng trước.
ROTATE_SECS = int(os.environ.get("SEAL_ROTATE_SECS", "60"))
# Giới hạn lượt request thành công mỗi vòng/room (0 = không giới hạn). Chống spam F5 / share tràn lan.
ROOM_MAX_USES = int(os.environ.get("SEAL_ROOM_MAX_USES", "0"))
ROOM_DB = os.environ.get("SEAL_ROOM_DB", os.path.join(tempfile.gettempdir(), "sealed-room.json"))
# Chống brute-force seal: giới hạn request/phút/IP (bộ nhớ process).
RATE_PER_MIN = int(os.environ.get("SEAL_RATE_PER_MIN", "120"))

FORWARD_VISITOR_IP = os.environ.get("SEAL_FORWARD_IP", "0") == "1"
# Header nào của visitor KHÔNG bao giờ forward về backend (chống lộ IP + chống replay seal qua Referer).
STRIP_REQ = {
    "host", "content-length", "connection", "referer", "referrer",
    "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-real-ip",
    "forwarded", "cf-connecting-ip", "true-client-ip", "fastly-client-ip",
}
# Header nào của backend KHÔNG trả về visitor (chống lộ fingerprint nội bộ).
STRIP_RESP = {"transfer-encoding", "connection", "server"}

_rate = {}


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


def load_room():
    try:
        with open(ROOM_DB, "r", encoding="utf-8") as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def save_room(d):
    try:
        with open(ROOM_DB, "w", encoding="utf-8") as f:
            json.dump(d, f)
    except Exception:
        pass


def expected_seal(name, exp):
    msg = f"{name}:{exp}".encode()
    return hmac.new(SEAL_SECRET.encode(), msg, hashlib.sha256).hexdigest()


def room_round(now=None):
    return int((now if now is not None else time.time()) // ROTATE_SECS)


def expected_room_ticket(room, rnd):
    msg = f"room:{room}:{rnd}".encode()
    return hmac.new(SEAL_SECRET.encode(), msg, hashlib.sha256).hexdigest()


def rate_ok(ip):
    now = time.time()
    bucket = _rate.get(ip)
    if not bucket or now - bucket[0] > 60:
        _rate[ip] = (now, 1)
        return True
    start, cnt = bucket
    if cnt >= RATE_PER_MIN:
        return False
    _rate[ip] = (start, cnt + 1)
    return True


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
        client_ip = self.client_address[0]
        if not rate_ok(client_ip):
            return self._deny(429, "too many requests")
        u = urllib.parse.urlparse(self.path)
        parts = u.path.strip("/").split("/")
        # GET /healthz -> ok không cần seal (cho monitor nội bộ)
        if u.path == "/healthz":
            return self._deny(200, "guard ok")
        if len(parts) >= 2 and parts[0] == "r":
            return self._handle_room(parts[1], u)
        if len(parts) >= 2 and parts[0] == "t":
            return self._handle_sealed(parts[1], u)
        return self._deny(404, "use /t/<name>/?exp=..&seal=.. or /r/<room>/?ticket=..")

    def _handle_sealed(self, name, u):
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
        parts = u.path.strip("/").split("/")
        code = self._proxy(name, parts[2:], u, qs, strip_keys=("seal", "exp"))
        if code == 200 and SINGLE_USE:
            used.add(key)
            save_used(used)
        return code

    def _handle_room(self, room, u):
        """Phòng chung xoay vòng: 1 URL chung, ticket đổi mỗi ROTATE_SECS.
        Link leak/forward ra ngoài tự chết sau tối đa ~2 vòng. Giới hạn lượt/vòng
        bằng ROOM_MAX_USES để chống phá (spam F5, share tràn lan)."""
        qs = urllib.parse.parse_qs(u.query)
        ticket = (qs.get("ticket") or [None])[0]
        if not ticket:
            return self._deny(403, "missing ticket")
        rnd = room_round()
        ok = any(
            hmac.compare_digest(expected_room_ticket(room, c), ticket)
            for c in (rnd, rnd - 1)
        )
        if not ok:
            return self._deny(403, "bad or rotated ticket")
        if ROOM_MAX_USES > 0:
            counts = load_room()
            k = f"{room}:{rnd}"
            if int(counts.get(k, 0)) >= ROOM_MAX_USES:
                return self._deny(429, "room round full")
            counts[k] = int(counts.get(k, 0)) + 1
            # Giữ DB gọn: chỉ giữ vòng hiện tại + vòng trước
            counts = {kk: vv for kk, vv in counts.items() if kk >= f"{room}:{rnd - 1}"}
            save_room(counts)
        parts = u.path.strip("/").split("/")
        return self._proxy(room, parts[2:], u, qs, strip_keys=("ticket",))

    def _proxy(self, name, rest, u, qs, strip_keys=("seal", "exp")):
        # Forward sang frps vhost, giữ Host để frp routing đúng proxy
        fwd_path = "/" + "/".join(rest)
        q = {k: v for k, v in qs.items() if k not in strip_keys}
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
        return resp.status

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_PATCH = _handle


if __name__ == "__main__":
    print(
        f"guard :{GUARD_PORT} -> {FRPS_VHOST} (Host={VHOST_HOST}) "
        f"single_use={SINGLE_USE} rotate={ROTATE_SECS}s room_max={ROOM_MAX_USES}",
        flush=True,
    )
    ThreadingHTTPServer(("127.0.0.1", GUARD_PORT), Handler).serve_forever()
