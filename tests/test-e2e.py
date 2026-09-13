"""test-e2e.py — full E2E loopback single-machine cho sr8 + guard-go.
Yêu cầu trước: frps (s.toml) + frpc (c.toml) + guard-go chạy đúng env loopback.
  guard-go env: SEAL_SECRET=loopback-test-seal-1234567890, SEAL_ROTATE_SECS=60,
    SEAL_USED_DB/ROOM_DB trỏ file temp riêng, TCP_SEAL_PORT=19091, TCP_BACKEND=127.0.0.1:18082.
Chạy: python tests/test-e2e.py
Kết quả: PASS/FAIL từng case, exit 0 khi tất cả pass.
Stdlib only (urllib + socket).
"""
import hashlib
import hmac
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRET = os.environ.get("SEAL_SECRET", "loopback-test-seal-1234567890")
GUARD = os.environ.get("GUARD_BASE", "http://127.0.0.1:19090")
ROTATE = int(os.environ.get("SEAL_ROTATE_SECS", "60"))
TCP_PORT = int(os.environ.get("TCP_SEAL_PORT", "19091"))
TOTAL = [0, 0]

def check(name, cond, detail=""):
    TOTAL[0] += 1
    if cond:
        TOTAL[1] += 1
        print(f"PASS {name} {detail}")
    else:
        print(f"FAIL {name} {detail}")

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def http_no_redirect(url, headers=None, timeout=10):
    opener = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except Exception as e:
        return -1, {}, str(e).encode()

def http_get(url, headers=None, timeout=10):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except Exception as e:
        return -1, {}, str(e).encode()

def http_post(url, data, headers=None, timeout=10):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except Exception as e:
        return -1, {}, str(e).encode()

def mint_sealed(name, ttl=300):
    exp = int(time.time()) + ttl
    seal = hmac.new(SECRET.encode(), f"{name}:{exp}".encode(), hashlib.sha256).hexdigest()
    return f"{GUARD}/t/{name}/?exp={exp}&seal={seal}", exp, seal

def mint_room(room, at=None):
    rnd = int((at if at is not None else time.time()) // ROTATE)
    ticket = hmac.new(SECRET.encode(), f"room:{room}:{rnd}".encode(), hashlib.sha256).hexdigest()
    return f"{GUARD}/r/{room}/?ticket={ticket}", rnd, ticket

# 1. healthz
s, _, _ = http_get(GUARD + "/healthz")
check("healthz", s == 200, f"got={s}")

# 2. sealed lần 1 200, lần 2 403
u, _, _ = mint_sealed("full1", 300)
s, h, b = http_get(u)
check("sealed-1st-200", s == 200, f"got={s}")
s2, _, _ = http_get(u)
check("sealed-2nd-403", s2 == 403, f"got={s2}")

# 3. sai/thiếu/hết hạn seal
bad = f"{GUARD}/t/full1/?exp=9999999999&seal=bad000"
s, _, _ = http_get(bad)
check("sealed-bad-403", s == 403, f"got={s}")
s, _, _ = http_get(f"{GUARD}/t/full1/")
check("sealed-missing-403", s == 403, f"got={s}")
old_exp = int(time.time()) - 10
old_seal = hmac.new(SECRET.encode(), f"full1:{old_exp}".encode(), hashlib.sha256).hexdigest()
s, _, _ = http_get(f"{GUARD}/t/full1/?exp={old_exp}&seal={old_seal}")
check("sealed-expired-403", s == 403, f"got={s}")

# 4. multi-value query giữ nguyên
u, _, _ = mint_sealed("full1", 300)
s, _, b = http_get(u.replace("/t/full1/", "/t/full1/echo-query", 1) if False else u)
# seal gắn với name=full1 nên path con phải giữ /t/full1/... mới đúng route; test multi-value qua room:
ru, _, _ = mint_room("fullq")
s, _, b = http_get(ru.replace("/r/fullq/", "/r/fullq/echo-query", 1) + "&x=1&x=2")
check("room-multivalue", s == 200 and b == b"x=1&x=2", f"got={s} body={b!r}")

# 5. method/body forward + cap: POST 5 byte -> got:5
ru, _, _ = mint_room("fullpost")
s, _, b = http_post(ru.replace("/r/fullpost/", "/r/fullpost/post-echo", 1), b"hello")
check("room-post-body", s == 200 and b == b"got:5", f"got={s} body={b!r}")

# 6. strip header: backend không thấy IP visitor chèn vào (1.2.3.4/evil),
# thấy X-Sealed-Name + Host đúng. LƯU Ý: frps/frpc (frp core) luôn append thêm
# X-Forwarded-For hop hạ tầng của chính tunnel (documented frp behavior:
# "You can get user's real IP from X-Forwarded-For") — guard không thể và
# không cần chặn cái này; guard đảm bảo không giá trị nào do visitor chèn
# còn sống sót tới backend.
ru, _, _ = mint_room("fullhdr")
s, _, b = http_get(ru.replace("/r/fullhdr/", "/r/fullhdr/echo-headers", 1),
                   headers={"X-Forwarded-For": "1.2.3.4", "Referer": "http://evil/"})
try:
    import json as _j
    d = _j.loads(b.decode())
    low = {k.lower(): v for k, v in d.items()}
    ok = ("1.2.3.4" not in b.decode() and "evil" not in b.decode()
          and low.get("x-sealed-name") == "fullhdr" and low.get("host") == "loopback.test")
except Exception:
    ok = False
check("strip-headers", s == 200 and ok, f"got={s}")

# 7. sanitize Location nội bộ -> /, public giữ nguyên (không follow redirect)
ru, _, _ = mint_room("fullred")
s, h, _ = http_no_redirect(ru.replace("/r/fullred/", "/r/fullred/redirect-internal", 1))
loc = ""
for k, v in h.items():
    if k.lower() == "location":
        loc = v
check("sanitize-internal", s == 302 and loc == "/", f"got={s} loc={loc!r}")
ru, _, _ = mint_room("fullred2")
s, h, _ = http_no_redirect(ru.replace("/r/fullred2/", "/r/fullred2/redirect-public", 1))
loc = ""
for k, v in h.items():
    if k.lower() == "location":
        loc = v
check("keep-public-location", s == 302 and loc == "https://example.com/out", f"got={s} loc={loc!r}")

# 8. fingerprint Server: nginx
u, _, _ = mint_sealed("fullfp", 300)
s, h, _ = http_get(u)
srv = ""
for k, v in h.items():
    if k.lower() == "server":
        srv = v
check("server-nginx", s == 200 and srv == "nginx", f"got={s} server={srv!r}")

# 9. room hiện tại 200, cũ 3 vòng 403
ru, _, _ = mint_room("fullroom")
s, _, _ = http_get(ru)
check("room-now-200", s == 200, f"got={s}")
old, _, _ = mint_room("fullroom", at=time.time() - 3 * ROTATE)
s, _, _ = http_get(old)
check("room-old-403", s == 403, f"got={s}")

# 10. TCP sealed: handshake sealed ok, room ok, sai đóng 403
def tcp_handshake(line, payload=b"ping"):
    s = socket.create_connection(("127.0.0.1", TCP_PORT), timeout=10)
    try:
        s.sendall(line.encode() + b"\n")
        s.sendall(payload)
        return s.recv(4096)
    finally:
        s.close()

u, exp, seal = mint_sealed("fulltcp", 300)
got = tcp_handshake(f"fulltcp:{exp}:{seal}", b"hello-go")
check("tcp-sealed-ok", got == b"GO-TCP-OK:hello-go", f"got={got!r}")
ru, _, _ = mint_room("fulltcproom")
m = re.search(r"ticket=([0-9a-f]+)", ru)
got = tcp_handshake(f"fulltcproom:{m.group(1)}", b"hi-room")
check("tcp-room-ok", b"GO-TCP-OK:hi-room" in got, f"got={got!r}")
got = tcp_handshake("bad:1:bad", b"x")
check("tcp-bad-403", got == b"403 bad seal\n", f"got={got!r}")

# 11. mkroom sinh config frpc verify được (cần frpc.exe ở C:\Temp\frp\frpc.exe trên Win)
frpc = r"C:\Temp\frp\frpc.exe"
room_toml = os.path.join(ROOT, "tests", "room-autotest.toml")
r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "mkroom.py"),
                    "--server", "127.0.0.1", "--token", "loopback-test-token-12345678",
                    "--local-port", "18081", "--count", "2", "--out", room_toml],
                   capture_output=True, text=True, timeout=30)
ok_mk = r.returncode == 0 and os.path.exists(room_toml)
ok_verify = False
if ok_mk and os.path.exists(frpc):
    p = subprocess.run([frpc, "verify", "-c", room_toml], capture_output=True, text=True, timeout=30)
    ok_verify = p.returncode == 0
check("mkroom-verify", ok_mk and (ok_verify or not os.path.exists(frpc)),
      f"mk={ok_mk} verify={ok_verify}")

print(f"\nTOTAL {TOTAL[1]}/{TOTAL[0]} passed")
sys.exit(0 if TOTAL[0] == TOTAL[1] else 1)
