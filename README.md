```text
                 ______
  _____________ /  __  \
 /  ___/\_  __ \>      <
 \___ \  |  | \/   --   \
/____  > |__|  \______  /
     \/               \/
```

**Share localhost once. The link dies after one click.**

[Why sr8](#why-sr8) · [Demo](#30-second-demo) · [Features](#features) · [Use cases](#use-cases) · [Quickstart](#quickstart) · [Security](#security-model) · [Free hosts](#free-hosts) · [FAQ](#faq)

![frp v0.71.0](https://img.shields.io/badge/frp-v0.71.0_verified-38BDF8?style=flat-square) ![stdlib only](https://img.shields.io/badge/python-stdlib_only-3776AB?style=flat-square) ![MIT](https://img.shields.io/badge/license-MIT-D97757?style=flat-square) ![tests](https://img.shields.io/badge/tests-loopback_passing-16A34A?style=flat-square)

> **One-liner:** sr8 is a thin sealing layer over [frp](https://github.com/fatedier/frp). frp moves the bytes. sr8 decides **who gets to see them, once, and for how long** — with a signed link instead of a password, a config edit, or a new tunnel per share.

```text
normal share:   you → edit frpc.toml → reload → send long-lived URL + password → hope they don't forward it
sr8 share:      you → python sealed/seal.py demo 300 → send link → link dies after 1 click or 300s
```

---

## Why sr8

**The problem with every tunnel tool:**

| Tool | What hurts on every share |
|---|---|
| frp raw | edit TOML, pick a port, reload, rotate passwords by hand |
| ngrok / PortBuddy hosted | one tunnel per share, quotas, someone else's edge sees your traffic |
| bore | fast TCP, but no HTTP routing, no expiry, no single-use |
| cloudflared quick tunnel | fast HTTPS, but random domain, no revocation model |

**sr8's answer — the Sealed Link:**

```text
visitor → guard :19090 → frps vhost :8080 → your backend
            │ HMAC(secret, "name:exp") + expiry + single-use check
            │ then forwards with the right Host so frp routes 1 static proxy
```

- frp keeps **exactly 1 static HTTP proxy**. The guard multiplexes **infinite links** over `/t/<name>/`.
- No new tunnel, no new subdomain, no reload, no password to type or leak.
- Verified end-to-end on frp `v0.71.0`: first click `200`, second click `403`, bad/expired/missing seal `403`.

---

## 30-second demo

```powershell
# 1. dummy backend
python -m http.server 18081 --bind 127.0.0.1

# 2. frps + frpc (configs in tests/, ports 17000/18080)
C:\Temp\frp\frps.exe -c tests\frps-loopback.toml
C:\Temp\frp\frpc.exe -c tests\frpc-loopback.toml

# 3. guard
$env:SEAL_SECRET="loopback-test-seal-1234567890"
python sealed/guard.py
# → guard :19090 -> 127.0.0.1:18080 (Host=loopback.test) single_use=True

# 4. mint a link that lives 5 minutes and dies after 1 click
$env:GUARD_BASE="http://127.0.0.1:19090"
python sealed/seal.py demo 300
# → http://127.0.0.1:19090/t/demo/?exp=…&seal=…
```

Open it once → your page. Refresh → `403 link already used`. That is the whole product.

---

## Features

### Sealed Links (the breakthrough)
- `HMAC-SHA256(secret, "name:exp")` — unforgeable without the secret, no DB lookup on the hot path.
- **Expiry** per link (`exp` unix timestamp). **Single-use** tracked in a JSON store (swap for Redis on multi-instance).
- Wrong seal, missing seal, expired, replayed — all `403` with no info leak.
- `seal.py` is stdlib only. Pipe it into anything: `python sealed/seal.py client-a 900`.

### Rotating rooms (shared link that can't be forwarded forever)
- `/r/<room>/?ticket=..` — one shared URL, ticket = `HMAC(secret, "room:<round>")`, round rotates every `SEAL_ROTATE_SECS` (default 60s).
- A leaked screenshot/forwarded link dies after ~2 rounds. Guard accepts current + previous round for clock-skew only.
- `SEAL_ROOM_MAX_USES` caps successful hits per round per room (anti-F5, anti-bot, anti-mass-share). `SEAL_RATE_PER_MIN` throttles seal brute-force per IP.
- `python sealed/seal.py --room team 60` mints the current ticket. Verified: current `200`, 3-min-old `403`.

### Anti-leak guard (`sealed/guard.py`, 1 file, stdlib only)
- Strips inbound `X-Forwarded-*, Forwarded, CF-Connecting-IP, True-Client-IP, X-Real-IP, Referer` — your backend never learns the visitor's IP unless you opt in with `SEAL_FORWARD_IP=1`.
- Strips outbound `Server`, rewrites `Location` headers pointing at `127.0.0.1/localhost/:1808x` back to `/`.
- Generic `Server: nginx` fingerprint, plus `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store` on every response.
- Generic `502 upstream fail` — never echoes tracebacks or internal addresses.
- Forwards `GET/POST/PUT/DELETE/PATCH` with bodies, preserves backend status codes and headers.
- Dynamic vhost: `VHOST_HOST="{name}.tunnel.example.com"` for per-link subdomains, or one fixed subdomain for a single static proxy.
- `/healthz` for monitors without a seal.

### Full frp core underneath
- `tcp / udp / http / https / tcpmux / stcp / xtcp` — private `stcp`, P2P `xtcp`, SSH gateway without frpc.
- Load balancing groups, TCP/HTTP healthchecks, per-proxy bandwidth limits, connection pooling, `tcpMux`, `KCP`/`QUIC` transports, forced TLS.
- 8 ready-made blocks in `frpc-examples.toml`: web demo, SSH, Postgres share, Minecraft Bedrock UDP, secret SSH, P2P SSH, HA pair + visitor.

### Speed wrappers
- `fast-frp.sh` (Linux) and `fast-frp.ps1` (Windows): portbuddy-style one-liners that generate a temp frpc config and exec frpc.
- Remote ports auto-fit `allowPorts 20000–40000` via modulo — the old `2$port` formula overflowed past `65535` and is fixed.
- `bore-server` sidecar in compose for throwaway raw-TCP demos with zero config.

### Deploy stack
- `docker-compose.yml`: `snowdreamtech/frps:v0.71.0` + `caddy:2-alpine` + `ekzhang/bore:latest`, `network_mode: host` (VPS Linux only).
- Caddy terminates TLS once and forwards plain HTTP to frps `vhostHTTPPort` — no double-TLS.
- Dashboard locked to `127.0.0.1:7500`, view remotely via `ssh -L`.

---

## Use cases

| # | Job | How with sr8 |
|---|---|---|
| U1 | Demo a local web app | `seal.py demo 300` → send link, dies after review |
| U2 | Webhooks (Stripe/GitHub/Twilio) | 1 static frp `http` proxy + long-TTL seal per provider |
| U3 | Client review without staging | 1-click link, no password call, no forwarded-URL risk |
| U4 | Test on a real phone | valid cert at edge, `no-store` so no stale cache |
| U5 | SSH/RDP into homelab behind CGNAT | frp `tcp remotePort` (long-lived) + sealed HTTP for the dashboard |
| U6 | Share Postgres/Redis temporarily | frp `tcp` + rotate `remotePort`; HTTP admin via sealed link |
| U7 | 24/7 self-host (Home Assistant, NAS, files) | frps on Oracle free VPS + Caddy wildcard TLS |
| U8 | Game servers / UDP / VoIP | frp `udp` raw, no 5-min idle cleanup like hosted edges |
| U9 | Fleet of nodes → 1 center | frp groups + `allowPorts`, guard per-team secrets |
| U10 | Private access instead of VPN | `stcp` (no public port) or `xtcp` P2P hole-punch |
| U11 | HA / bad networks | LB group + healthcheck + `bandwidthLimit` + QUIC/KCP |
| U12 | One-off vs permanent | bore/`cloudflared --url` for 10s demos, sealed links for everything accountable |

---

## Quickstart

### A. Loopback on one machine (no VPS, no Docker)

See [`tests/README.md`](tests/README.md). Ports `17000/18080/18081/18082/19090/20001` avoid production.

### B. VPS production (Oracle Always Free recommended)

```bash
docker compose up -d
ss -tlnp | grep -E '7000|7835|8080|5002|2222'
```

1. DNS: `A tunnel.example.com → VPS_IP`, `A *.tunnel.example.com → VPS_IP`.
2. Firewall ingress TCP `7000,5002,7835,8080,8443,2222,20000-40000`, UDP `7000,20000-40000`.
3. Replace every `CHANGE-ME-*` in `frps.toml` and set a 32+ char `SEAL_SECRET`.
4. Guard env on the VPS: `GUARD_PORT=19090 FRPS_VHOST=127.0.0.1:8080 VHOST_HOST="{name}.tunnel.example.com"`.
5. Point Caddy at the guard, not at frps directly.

Full matrix (what runs raw TCP free and what doesn't) → [`FREE-HOSTS.md`](FREE-HOSTS.md).

### Guard environment

| Var | Default | Meaning |
|---|---|---|
| `GUARD_PORT` | `19090` | listen port (binds `127.0.0.1`) |
| `FRPS_VHOST` | `127.0.0.1:18080` | frps vhost to forward into |
| `VHOST_HOST` | `loopback.test` | `Host` sent to frps; supports `{name}` template |
| `SEAL_SECRET` | `CHANGE-ME-…` | HMAC key, 32+ chars in production |
| `SEAL_SINGLE_USE` | `1` | `1` = burn after first success |
| `SEAL_USED_DB` | tempdir `sealed-used.json` | single-use store (use a volume / Redis later) |
| `SEAL_FORWARD_IP` | `0` | `1` = send `X-Sealed-Visitor` to backend (opts out of IP hiding) |

---

## Security model

**What sr8 hides:**
- Backend topology — strips `Server`, internal `Location`, tracebacks; generic fingerprint.
- Visitor IP from backend by default; seal values via `no-referrer` + query stripping.
- Long-lived credentials — the link *is* the credential, and it self-destructs.

**What sr8 does not magically fix:**
- A public `IP:port` TCP tunnel inherently exposes that IP. Hide origins with a relay VPS, Tailscale, Tor onion, or `cloudflared` — see the relay discussion in `FREE-HOSTS.md`.
- TLS-terminating edges (Cloudflare, any CDN) can read traffic. Keep E2E TLS passthrough if that matters.
- SNI leaks hostnames on the wire without ECH. A compromised backend still knows the VPS egress IP.
- Rotate `SEAL_SECRET` + VPS IP if either ever leaked (DNS history, Shodan, screenshots with URLs).

> Guard before the fix forwarded `X-Forwarded-For`/`Referer` and echoed upstream errors; after the fix all three are stripped and re-tested (`Server: nginx`, replay `403`). The retest commands are in [`sealed/README.md`](sealed/README.md).

---

## Support

- **frp upstream moves fast** — latest verified here is `v0.71.0` (2026-08-14; prior `v0.70.1` on 2026-07-23, ~1.5k commits on `dev`). Upgrade path: bump `snowdreamtech/frps:<tag>` in `docker-compose.yml`, then run `frps verify` + `frpc verify` (both must print `syntax is ok`).
- **Supported:** Linux VPS (compose), Windows 10/11 + Python 3.10+ (loopback + guard + `fast-frp.ps1`), any frp-supported arch for `frpc`.
- **Not supported:** `network_mode: host` on Docker Desktop for Win/Mac (use the loopback configs instead); multi-guard single-use without shared storage (bring Redis).
- **Bugs:** open an issue with your frp version (`frps --help`), guard env (redact `SEAL_SECRET`), and the failing `verify` output.

## Roadmap

- [ ] Revocation CLI (`seal revoke <name>`) + TTL listing
- [ ] Redis/Postgres used-store for multi-guard deployments
- [ ] Sealed TCP: one-time `remotePort` grants via the same HMAC scheme
- [ ] Minimal web UI: mint/revoke/audit without touching TOML
- [ ] ECH + origin-pull hardening guides for Cloudflare/Tor/Tailscale setups

## Contributing

PRs welcome. Keep the guard stdlib-only, keep every new frp version verified with `frps verify`/`frpc verify` + the loopback HTTP `200` and TCP echo checks in [`tests/README.md`](tests/README.md).

## License

MIT — see [`LICENSE`](LICENSE). frp itself is Apache-2.0 by [fatedier](https://github.com/fatedier/frp); sr8 ships configs and a guard around it, no frp fork required.
