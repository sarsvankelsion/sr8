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
import ipaddress
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
SEAL_MODE = os.environ.get("SEAL_MODE", "sealed").lower().strip()  # "sealed" | "open"

# Store persistent: ưu tiên volume /var/lib/sr8 (docker), fallback ./data (chạy tay), cuối cùng tempdir.
def _default_store(name):
    for base in ("/var/lib/sr8", os.path.join(os.getcwd(), "data")):
        try:
            os.makedirs(base, exist_ok=True)
            return os.path.join(base, name)
        except Exception:
            continue
    return os.path.join(tempfile.gettempdir(), name)

USED_DB = os.environ.get("SEAL_USED_DB", _default_store("sealed-used.json"))
ROOM_DB = os.environ.get("SEAL_ROOM_DB", _default_store("sealed-room.json"))
SINGLE_USE = os.environ.get("SEAL_SINGLE_USE", "1") == "1"
# Phòng chung xoay vòng: ticket đổi mỗi ROTATE_SECS giây, chấp nhận vòng hiện tại + 1 vòng trước.
ROTATE_SECS = int(os.environ.get("SEAL_ROTATE_SECS", "60"))
# Giới hạn lượt request thành công mỗi vòng/room (0 = không giới hạn). Chống spam F5 / share tràn lan.
ROOM_MAX_USES = int(os.environ.get("SEAL_ROOM_MAX_USES", "0"))
# Chống brute-force seal: giới hạn request/phút/IP (bộ nhớ process).
RATE_PER_MIN = int(os.environ.get("SEAL_RATE_PER_MIN", "120"))
# Giới hạn body upload và response streaming để chống OOM. SSE/WebSocket đi qua dạng stream.
MAX_BODY = int(os.environ.get("SEAL_MAX_BODY_BYTES", str(10 * 1024 * 1024)))
MAX_RESP = int(os.environ.get("SEAL_MAX_RESP_BYTES", str(50 * 1024 * 1024)))
UPSTREAM_TIMEOUT = int(os.environ.get("SEAL_UPSTREAM_TIMEOUT", "15"))
CHUNK = 64 * 1024

FORWARD_VISITOR_IP = os.environ.get("SEAL_FORWARD_IP", "0") == "1"
# Proxy ngược tin cậy (Caddy/CF) được phép gửi X-Forwarded-For. Format: "10.0.0.0/8, 127.0.0.1".
# Để trống = kết nối trực tiếp, real-IP = socket peer (đúng cho loopback + VPS không proxy).
TRUSTED_PROXIES = os.environ.get("SEAL_TRUSTED_PROXIES", "")
# Header nào của visitor KHÔNG bao giờ forward về backend (chống lộ IP + chống replay seal qua Referer).
STRIP_REQ = {
    "host", "content-length", "connection", "referer", "referrer",
    "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-real-ip",
    "forwarded", "cf-connecting-ip", "true-client-ip", "fastly-client-ip",
}
# Header nào của backend KHÔNG trả về visitor (chống lộ fingerprint nội bộ).
STRIP_RESP = {"transfer-encoding", "connection", "server"}

_rate = {}


def _ensure_dir(path):
    try:
        d = os.path.dirname(os.path.abspath(path))
        if d:
            os.makedirs(d, exist_ok=True)
    except Exception:
        pass


def _acquire_lock(path, timeout=5.0):
    lock = path + ".lock"
    start = time.time()
    while True:
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            return lock
        except FileExistsError:
            if time.time() - start > timeout:
                return None
            time.sleep(0.05)


def _release_lock(lock):
    try:
        if lock:
            os.remove(lock)
    except Exception:
        pass


def load_used():
    lock = _acquire_lock(USED_DB)
    try:
        with open(USED_DB, "r", encoding="utf-8") as f:
            v = json.load(f)
            return set(v) if isinstance(v, list) else set()
    except Exception:
        return set()
    finally:
        _release_lock(lock)


def try_burn_sealed(key):
    """Check-then-burn nguyên tử. True = lần đầu (được đi tiếp), False = đã dùng."""
    _ensure_dir(USED_DB)
    lock = _acquire_lock(USED_DB)
    try:
        try:
            with open(USED_DB, "r", encoding="utf-8") as f:
                v = json.load(f)
                used = set(v) if isinstance(v, list) else set()
        except Exception:
            used = set()
        if key in used:
            return False
        used.add(key)
        tmp = USED_DB + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(sorted(used), f)
        os.replace(tmp, USED_DB)
        return True
    except Exception:
        return True
    finally:
        _release_lock(lock)


def load_room():
    lock = _acquire_lock(ROOM_DB)
    try:
        with open(ROOM_DB, "r", encoding="utf-8") as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except Exception:
        return {}
    finally:
        _release_lock(lock)


def try_inc_room(room, rnd):
    """Tăng quota vòng hiện tại một cách nguyên tử. True = còn quota."""
    if ROOM_MAX_USES <= 0:
        return True
    _ensure_dir(ROOM_DB)
    lock = _acquire_lock(ROOM_DB)
    try:
        try:
            with open(ROOM_DB, "r", encoding="utf-8") as f:
                d = json.load(f)
                counts = d if isinstance(d, dict) else {}
        except Exception:
            counts = {}
        k = f"{room}:{rnd}"
        if int(counts.get(k, 0)) >= ROOM_MAX_USES:
            return False
        counts[k] = int(counts.get(k, 0)) + 1
        # Prune theo số học: giữ mọi room khác, room hiện tại chỉ giữ vòng rnd và rnd-1.
        pruned = {}
        for kk, vv in counts.items():
            try:
                rname, rs = kk.rsplit(":", 1)
                if rname != room or int(rs) >= rnd - 1:
                    pruned[kk] = vv
            except Exception:
                continue
        tmp = ROOM_DB + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(pruned, f)
        os.replace(tmp, ROOM_DB)
        return True
    except Exception:
        return True
    finally:
        _release_lock(lock)


def expected_seal(name, exp):
    msg = f"{name}:{exp}".encode()
    return hmac.new(SEAL_SECRET.encode(), msg, hashlib.sha256).hexdigest()


def room_round(now=None):
    return int((now if now is not None else time.time()) // ROTATE_SECS)


def expected_room_ticket(room, rnd):
    msg = f"room:{room}:{rnd}".encode()
    return hmac.new(SEAL_SECRET.encode(), msg, hashlib.sha256).hexdigest()


def _trusted_nets():
    nets = []
    for part in TRUSTED_PROXIES.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "/" in part:
                nets.append(ipaddress.ip_network(part, strict=False))
            else:
                nets.append(ipaddress.ip_network(part + "/32" if "." in part else part + "/128"))
        except Exception:
            continue
    return nets


_TRUSTED = None


def _is_trusted(ip):
    global _TRUSTED
    if _TRUSTED is None:
        _TRUSTED = _trusted_nets()
    if not _TRUSTED:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in n for n in _TRUSTED)
    except Exception:
        return False


def real_ip(handler):
    peer = handler.client_address[0]
    if not _is_trusted(peer):
        return peer
    for h in ("X-Forwarded-For", "CF-Connecting-IP", "True-Client-IP", "X-Real-IP"):
        v = handler.headers.get(h)
        if v:
            first = v.split(",")[0].strip().strip("[]")
            if first:
                return first
    return peer


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


def sanitize_location(v):
    """Rewrite Location trỏ vào mạng nội bộ về path tương đối. Giữ nguyên URL public."""
    try:
        p = urllib.parse.urlparse(v)
        if not p.netloc:
            return v
        host = (p.hostname or "").strip("[]")
        if not host:
            return v
        low = host.lower()
        if low in ("localhost",) or low.endswith((".localhost", ".local", ".internal")) or ("." not in low and ":" not in low):
            return p.path or "/" + (("?" + p.query) if p.query else "") + (("#" + p.fragment) if p.fragment else "")
        try:
            addr = ipaddress.ip_address(host)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast or addr.is_unspecified:
                rel = p.path or "/"
                if p.query:
                    rel += "?" + p.query
                if p.fragment:
                    rel += "#" + p.fragment
                return rel
            return v
        except ValueError:
            return v
    except Exception:
        return "/"


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
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass
        self.close_connection = True

    def _handle(self):
        ip = real_ip(self)
        if not rate_ok(ip):
            return self._deny(429, "too many requests")
        u = urllib.parse.urlparse(self.path)
        parts = u.path.strip("/").split("/")
        # GET /healthz -> ok không cần seal (cho monitor nội bộ)
        if u.path == "/healthz":
            return self._deny(200, f"guard ok mode={SEAL_MODE}")
        if SEAL_MODE == "open":
            name = "open"
            if len(parts) >= 2 and parts[0] in ("r", "t"):
                name = parts[1]
            rest = parts[2:] if (len(parts) >= 2 and parts[0] in ("r", "t")) else parts
            qs = urllib.parse.parse_qs(u.query, keep_blank_values=True)
            return self._proxy(name, rest, u, qs, strip_keys=("seal", "exp", "ticket"))
        if len(parts) >= 2 and parts[0] == "r":
            return self._handle_room(parts[1], u)
        if len(parts) >= 2 and parts[0] == "t":
            return self._handle_sealed(parts[1], u)
        return self._deny(404, "use /t/<name>/?exp=..&seal=.. or /r/<room>/?ticket=..")

    def _handle_sealed(self, name, u):
        qs = urllib.parse.parse_qs(u.query, keep_blank_values=True)
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
        # Burn ngay khi seal hợp lệ (kể cả backend trả non-200) để chống dò backend bằng 1 seal.
        key = f"{name}:{exp}:{seal[:16]}"
        if SINGLE_USE and not try_burn_sealed(key):
            return self._deny(403, "link already used")
        parts = u.path.strip("/").split("/")
        return self._proxy(name, parts[2:], u, qs, strip_keys=("seal", "exp"))

    def _handle_room(self, room, u):
        """Phòng chung xoay vòng: 1 URL chung, ticket đổi mỗi ROTATE_SECS.
        Link leak/forward ra ngoài tự chết sau tối đa ~2 vòng. Giới hạn lượt/vòng
        bằng ROOM_MAX_USES để chống phá (spam F5, share tràn lan)."""
        qs = urllib.parse.parse_qs(u.query, keep_blank_values=True)
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
        if not try_inc_room(room, rnd):
            return self._deny(429, "room round full")
        parts = u.path.strip("/").split("/")
        return self._proxy(room, parts[2:], u, qs, strip_keys=("ticket",))

    def _proxy(self, name, rest, u, qs, strip_keys=("seal", "exp")):
        # Giữ multi-value query (?a=1&a=2), chỉ strip key xác thực.
        pairs = [(k, vv) for k, vals in qs.items() if k not in strip_keys for vv in vals]
        fwd_path = "/" + "/".join(rest)
        if pairs:
            fwd_path += "?" + urllib.parse.urlencode(pairs, doseq=True)
        # Body upload có cap 10MB để chống OOM.
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY:
            return self._deny(413, "body too large")
        try:
            if length:
                body = self.rfile.read(length)
            elif self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                body = self.rfile.read(MAX_BODY + 1)
                if len(body) > MAX_BODY:
                    return self._deny(413, "body too large")
            else:
                body = None
        except Exception:
            return self._deny(400, "bad body")
        host, _, port = FRPS_VHOST.partition(":")
        conn = http.client.HTTPConnection(host, int(port or 80), timeout=UPSTREAM_TIMEOUT)
        vhost = VHOST_HOST.replace("{name}", name)
        fwd_headers = {"Host": vhost, "X-Sealed-Name": name}
        if FORWARD_VISITOR_IP:
            fwd_headers["X-Sealed-Visitor"] = real_ip(self)
        for k, v in self.headers.items():
            if k.lower() in STRIP_REQ:
                continue
            fwd_headers[k] = v
        try:
            conn.request(self.command, fwd_path or "/", body=body, headers=fwd_headers)
            resp = conn.getresponse()
        except Exception:
            try:
                conn.close()
            except Exception:
                pass
            return self._deny(502, "upstream fail")
        try:
            self.send_response(resp.status)
            sent_len = False
            for k, v in resp.getheaders():
                if k.lower() in STRIP_RESP:
                    continue
                if k.lower() == "location":
                    v = sanitize_location(v)
                if k.lower() == "content-length":
                    try:
                        if int(v) > MAX_RESP:
                            continue
                    except ValueError:
                        continue
                    sent_len = True
                self.send_header(k, v)
            # HEAD: chỉ header, không body.
            is_head = self.command == "HEAD"
            backend_len = resp.getheader("Content-Length")
            if not sent_len and not is_head:
                # Không biết length -> stream close-delimited (HTTP/1.0), có cap chống OOM.
                pass
            elif is_head:
                pass
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            if is_head:
                resp.read()
                return resp.status
            # Stream từng chunk 64KB, tổng không quá MAX_RESP (SSE/live cũng đi qua).
            total = 0
            while True:
                data = resp.read(CHUNK)
                if not data:
                    break
                total += len(data)
                if total > MAX_RESP:
                    break
                try:
                    self.wfile.write(data)
                except Exception:
                    break
            return resp.status
        finally:
            try:
                conn.close()
            except Exception:
                pass
            self.close_connection = True

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_PATCH = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle


if __name__ == "__main__":
    print(
        f"guard :{GUARD_PORT} -> {FRPS_VHOST} (Host={VHOST_HOST}) "
        f"single_use={SINGLE_USE} rotate={ROTATE_SECS}s room_max={ROOM_MAX_USES}",
        flush=True,
    )
    ThreadingHTTPServer(("127.0.0.1", GUARD_PORT), Handler).serve_forever()
