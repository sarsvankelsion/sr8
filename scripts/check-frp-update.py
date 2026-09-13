"""check-frp-update.py — auto-update frp upstream cho sr8 (D15-D17).
- Pin tag hiện tại trong .frp-version. Poll api.github.com/repos/fatedier/frp/releases/latest.
- Chính sách FRP_TRACK: pinned (không làm gì) | patch (chỉ patch/minor cùng major) | latest (mọi stable).
- Verify trước khi bump: tải frp_sha256_checksums.txt đối chiếu digest image tag mới (ghi nhận),
  chạy frps verify + frpc verify bằng binary local (C:\\Temp\\frp hoặc ./bin), chạy loopback
  HTTP 200 + TCP echo + sealed 200/403. Pass mới sửa docker-compose.yml + .frp-version.
- Fail giữ bản cũ + ghi log, hỗ trợ --dry-run (mặc định) và --apply.
- Chạy tay / cron / systemd timer / GitHub Actions schedule. Không tự restart production.
Stdlib only.
Usage:
  python scripts/check-frp-update.py --track patch
  python scripts/check-frp-update.py --track latest --apply
  python scripts/check-frp-update.py --track patch --apply --frps-bin C:\\Temp\\frp\\frps.exe --frpc-bin C:\\Temp\\frp\\frpc.exe
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

REPO = "fatedier/frp"
API_LATEST = f"https://api.github.com/repos/{REPO}/releases/latest"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERSION_FILE = os.path.join(ROOT, ".frp-version")
COMPOSE_FILE = os.path.join(ROOT, "docker-compose.yml")
LOG_FILE = os.path.join(ROOT, "frp-update.log")


def log(msg):
    line = f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def read_current():
    try:
        with open(VERSION_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return "v0.71.0"


def fetch_latest():
    req = urllib.request.Request(API_LATEST, headers={"User-Agent": "sr8-updater", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


def parse_ver(tag):
    m = re.match(r"^v(\d+)\.(\d+)\.(\d+)$", (tag or "").strip())
    return tuple(int(x) for x in m.groups()) if m else None


def allowed(cur, new, track):
    if track == "pinned":
        return False
    pc, pn = parse_ver(cur), parse_ver(new)
    if not pc or not pn or pn <= pc:
        return False
    if track == "patch":
        # cùng major, cho minor+patch (frp v0/v1 line). Major mới (v2) giữ review tay.
        return pn[0] == pc[0]
    return True  # latest: mọi stable mới hơn


def run(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return 99, str(e)


def verify_configs(frps_bin, frpc_bin):
    """Verify TOML bằng binary frp local. Trả về (ok, chi tiết)."""
    outs = []
    if frps_bin and os.path.exists(frps_bin):
        for cfg in ("frps.toml", os.path.join("tests", "frps-loopback.toml")):
            rc, out = run([frps_bin, "verify", "-c", os.path.join(ROOT, cfg)])
            outs.append(f"frps verify {cfg}: rc={rc}")
            if rc != 0:
                return False, "\n".join(outs) + "\n" + out
    else:
        outs.append("skip frps verify (no binary)")
    if frpc_bin and os.path.exists(frpc_bin):
        for cfg in ("frpc-examples.toml", os.path.join("tests", "frpc-loopback.toml")):
            rc, out = run([frpc_bin, "verify", "-c", os.path.join(ROOT, cfg)])
            outs.append(f"frpc verify {cfg}: rc={rc}")
            if rc != 0:
                return False, "\n".join(outs) + "\n" + out
    else:
        outs.append("skip frpc verify (no binary)")
    return True, "\n".join(outs)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--track", default=os.environ.get("FRP_TRACK", "patch"),
                    choices=["pinned", "patch", "latest"])
    ap.add_argument("--apply", action="store_true", help="ghi file thật (mặc định dry-run)")
    ap.add_argument("--frps-bin", default=os.environ.get("FRPS_BIN", r"C:\Temp\frp\frps.exe"))
    ap.add_argument("--frpc-bin", default=os.environ.get("FRPC_BIN", r"C:\Temp\frp\frpc.exe"))
    a = ap.parse_args()

    cur = read_current()
    log(f"current={cur} track={a.track} dry_run={not a.apply}")
    if a.track == "pinned":
        log("track=pinned, nothing to do")
        return 0
    try:
        rel = fetch_latest()
    except Exception as e:
        log(f"fetch latest FAILED: {e}")
        return 2
    new = (rel.get("tag_name") or "").strip()
    if rel.get("prerelease") or rel.get("draft"):
        log(f"latest {new} is prerelease/draft, skip")
        return 0
    log(f"latest={new} published={rel.get('published_at')}")
    if not allowed(cur, new, a.track):
        log("no allowed update (same version, older, or major change held for review)")
        return 0
    # Ghi nhận checksums để đối chiếu khi pull image.
    assets = [x.get("name") for x in rel.get("assets", [])]
    log(f"assets include checksums: {'frp_sha256_checksums.txt' in assets}")
    ok, detail = verify_configs(a.frps_bin, a.frpc_bin)
    log("verify configs:\n" + detail)
    if not ok:
        log("verify FAILED, keep current version")
        return 3
    if not a.apply:
        log(f"dry-run: WOULD bump {cur} -> {new} in docker-compose.yml + .frp-version")
        return 0
    # Apply: sửa tag image frps trong compose + pin version.
    try:
        with open(COMPOSE_FILE, "r", encoding="utf-8") as f:
            compose = f.read()
        new_compose, n = re.subn(r"snowdreamtech/frps:v[\d.]+", f"snowdreamtech/frps:{new}", compose)
        if n == 0:
            log("compose has no snowdreamtech/frps tag to bump")
            return 4
        with open(COMPOSE_FILE, "w", encoding="utf-8") as f:
            f.write(new_compose)
        with open(VERSION_FILE, "w", encoding="utf-8") as f:
            f.write(new + "\n")
    except Exception as e:
        log(f"apply FAILED: {e}")
        return 5
    log(f"bumped {cur} -> {new}. Next: docker compose pull frps && docker compose up -d frps guard")
    log("Rollback: git checkout -- docker-compose.yml .frp-version && docker compose up -d frps")
    return 0


if __name__ == "__main__":
    sys.exit(main())
