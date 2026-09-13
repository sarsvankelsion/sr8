#!/bin/bash
# sr8 WSL2 deploy test — chạy BÊN TRONG Ubuntu WSL sau reboot.
# Mục tiêu: xác minh compose host-network, guard-go, Caddy HTTP thuần, volume, healthcheck.
# Không cần IP public / DNS thật. Dùng http://<WSL-IP>:8080 + hosts file.
set -e
cd "$(dirname "$0")/.."
echo "== 1. check docker =="
docker --version
docker compose version
echo "== 2. build guard-go =="
docker compose build guard
echo "== 3. up frps+guard (bỏ caddy TLS, dùng caddy http thuần) =="
cat > /tmp/sr8-test.env <<'EOF'
SEAL_SECRET=loopback-test-seal-1234567890
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
FRP_TOKEN=loopback-test-token-12345678
FRP_TRACK=patch
EOF
cp /tmp/sr8-test.env .env
docker compose --profile demo up -d
sleep 5
echo "== 4. ports =="
ss -tlnp | grep -E '17000|18080|19090|19091|7835' || ss -tln | grep -E '17000|18080|19090'
echo "== 5. healthz =="
curl -s http://127.0.0.1:19090/healthz; echo
echo "== 6. sealed E2E =="
export SEAL_SECRET=loopback-test-seal-1234567890 GUARD_BASE=http://127.0.0.1:19090 SEAL_ROTATE_SECS=60
python3 sealed/seal.py e2e1 300
echo "== DONE — xem log: docker compose logs frps guard =="
