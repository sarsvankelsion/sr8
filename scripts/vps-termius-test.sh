#!/bin/bash
# sr8 VPS Termius test — paste toàn bộ vào terminal Termius của VPS #2 rồi Enter.
# Dùng secret vứt đi, không dùng secret thật, không dùng domain chính.
set -x
echo "=== 1. fingerprint ==="
whoami; hostname; uptime; uname -a; cat /etc/os-release | head -3; free -h | head -3; df -h / | tail -1
systemd-detect-virt 2>&1; ss -tlnp 2>&1 | head -n 40
echo "=== 2. audit nhanh read-only ==="
awk -F: '$3>=1000{print $1":"$3}' /etc/passwd
ls -la /root/.ssh/ 2>&1 | head -10
crontab -l 2>&1 | head -10
systemctl list-unit-files --state=enabled 2>&1 | head -n 30
docker --version 2>&1; docker compose version 2>&1
echo "=== 3. lấy sr8 ==="
rm -rf /tmp/sr8test; mkdir -p /tmp/sr8test; cd /tmp/sr8test
git clone --depth 1 https://github.com/sarsvankelsion/sr8 src 2>&1 | tail -3
cd src
cat > .env <<'EOF'
SEAL_SECRET=test-only-seal-1234567890abcdef
GUARD_PORT=19090
FRPS_VHOST=127.0.0.1:8080
VHOST_HOST=loopback.test
SEAL_SINGLE_USE=1
SEAL_ROTATE_SECS=60
SEAL_ROOM_MAX_USES=50
SEAL_RATE_PER_MIN=120
SEAL_TRUSTED_PROXIES=127.0.0.1
SEAL_FORWARD_IP=0
TCP_SEAL_PORT=19091
TCP_BACKEND=127.0.0.1:18082
CF_API_TOKEN=dummy
FRP_TOKEN=test-only-frp-token-12345678
FRP_TRACK=patch
EOF
echo "=== 4. up frps+guard ==="
docker compose build guard 2>&1 | tail -5
docker compose up -d frps guard 2>&1 | tail -10
sleep 8
docker compose ps
ss -tln | grep -E '7000|8080|19090|19091' || true
curl -s http://127.0.0.1:19090/healthz; echo
echo "=== 5. backend + frpc test ==="
nohup python3 tests/backend-echo.py > /tmp/sr8test/echo.log 2>&1 &
curl -fsSL -o /tmp/sr8test/frp.tar.gz https://github.com/fatedier/frp/releases/download/v0.71.0/frp_0.71.0_linux_amd64.tar.gz
tar xzf /tmp/sr8test/frp.tar.gz -C /tmp/sr8test
cat > /tmp/sr8test/frpc-test.toml <<'EOF'
serverAddr = "127.0.0.1"
serverPort = 7000
auth.method = "token"
auth.token = "test-only-frp-token-12345678"
transport.tcpMux = true
transport.tls.enable = false
[[proxies]]
name = "loopback-web"
type = "http"
localIP = "127.0.0.1"
localPort = 18081
customDomains = ["loopback.test"]
EOF
sed -e 's/^transport.tls.force = true/transport.tls.force = false/' -e 's/^auth.token = .*/auth.token = "test-only-frp-token-12345678"/' frps.toml > /tmp/sr8test/frps-test.toml
nohup docker run --rm --network host --name sr8-frps-test -v /tmp/sr8test/frps-test.toml:/etc/frp/frps.toml:ro --entrypoint /usr/bin/frps snowdreamtech/frps:0.71.0-debian -c /etc/frp/frps.toml > /tmp/sr8test/frps-test.log 2>&1 &
sleep 5
nohup /tmp/sr8test/frp_0.71.0_linux_amd64/frpc -c /tmp/sr8test/frpc-test.toml > /tmp/sr8test/frpc.log 2>&1 &
sleep 4
cat /tmp/sr8test/frpc.log | tail -8
curl -s -H 'Host: loopback.test' http://127.0.0.1:8080/ | head -c 200; echo
echo "=== 6. sealed E2E ==="
export SEAL_SECRET=test-only-seal-1234567890 GUARD_BASE=http://127.0.0.1:19090 SEAL_ROTATE_SECS=60 TCP_SEAL_PORT=19091
python3 tests/test-e2e.py 2>&1 | tail -25
echo "=== DONE. Dọn: docker compose down -v; docker rm -f sr8-frps-test; rm -rf /tmp/sr8test ==="
