"""seal.py — provisioner tạo Sealed Link dùng một lần + Room ticket xoay vòng.
Usage:
  set SEAL_SECRET=loopback-test-seal-1234567890
  python seal.py demo 300            -> link 1-1 /t/demo/?exp=..&seal=..
  python seal.py --room team 60      -> link phòng chung /r/team/?ticket=.. (ticket đổi mỗi 60s)
  python seal.py --room team 60 --at <unix>  -> ticket cho 1 vòng cụ thể (để test xoay vòng)
Stdlib only.
"""
import hashlib
import hmac
import os
import sys
import time

SECRET = os.environ.get("SEAL_SECRET", "CHANGE-ME-SEAL-SECRET-32-CHARS")
GUARD_BASE = os.environ.get("GUARD_BASE", "http://127.0.0.1:19090")
ROTATE_SECS = int(os.environ.get("SEAL_ROTATE_SECS", "60"))


def make(name, ttl):
    exp = int(time.time()) + int(ttl)
    seal = hmac.new(SECRET.encode(), f"{name}:{exp}".encode(), hashlib.sha256).hexdigest()
    return exp, seal


def make_room(room, rotate_secs=ROTATE_SECS, at=None):
    rnd = int((at if at is not None else time.time()) // rotate_secs)
    ticket = hmac.new(SECRET.encode(), f"room:{room}:{rnd}".encode(), hashlib.sha256).hexdigest()
    return rnd, ticket


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--room":
        if len(sys.argv) < 4:
            print("Usage: python seal.py --room <room> <rotate_secs> [--at <unix>]")
            sys.exit(2)
        room = sys.argv[2]
        rotate_secs = int(sys.argv[3])
        at = None
        if "--at" in sys.argv:
            at = int(sys.argv[sys.argv.index("--at") + 1])
        rnd, ticket = make_room(room, rotate_secs, at)
        print(f"{GUARD_BASE}/r/{room}/?ticket={ticket}")
        print(f"# room={room} round={rnd} rotate={rotate_secs}s")
    else:
        if len(sys.argv) < 3:
            print("Usage: python seal.py <name> <ttl_seconds> | python seal.py --room <room> <rotate_secs>")
            sys.exit(2)
        name, ttl = sys.argv[1], sys.argv[2]
        exp, seal = make(name, ttl)
        print(f"{GUARD_BASE}/t/{name}/?exp={exp}&seal={seal}")
        print(f"# name={name} exp={exp} ttl={ttl}s")
