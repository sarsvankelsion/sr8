"""seal.py — provisioner tạo Sealed Link dùng một lần.
Usage:
  set SEAL_SECRET=loopback-test-seal-1234567890
  python seal.py demo 300            -> in link http://127.0.0.1:19090/t/demo/?exp=..&seal=..
  python seal.py demo 300 --tcp      -> in thêm gợi ý TCP (seal chỉ guard HTTP; TCP dùng frps token)
Stdlib only.
"""
import hashlib
import hmac
import os
import sys
import time

SECRET = os.environ.get("SEAL_SECRET", "CHANGE-ME-SEAL-SECRET-32-CHARS")
GUARD_BASE = os.environ.get("GUARD_BASE", "http://127.0.0.1:19090")


def make(name, ttl):
    exp = int(time.time()) + int(ttl)
    seal = hmac.new(SECRET.encode(), f"{name}:{exp}".encode(), hashlib.sha256).hexdigest()
    return exp, seal


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python seal.py <name> <ttl_seconds>")
        sys.exit(2)
    name, ttl = sys.argv[1], sys.argv[2]
    exp, seal = make(name, ttl)
    print(f"{GUARD_BASE}/t/{name}/?exp={exp}&seal={seal}")
    print(f"# name={name} exp={exp} ttl={ttl}s")
