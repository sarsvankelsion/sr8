#!/bin/bash
# Script tự động triển khai sr8 lên VPS khi SSH connect thành công.
# Đặt SEAL_MODE=open để làm dịch vụ mở không cần seal (như bạn yêu cầu).
# Muốn bật lại seal: đổi SEAL_MODE=sealed trong /opt/sr8/.env rồi docker compose restart guard.
set -e
echo "=== 1. Cài đặt dependencies ==="
apt-get update -qq
apt-get install -y -qq git python3 curl
# Cài docker compose standalone plugin nếu chưa có
mkdir -p /usr/local/lib/docker/cli-plugins
if ! docker compose version >/dev/null 2>&1; then
    curl -fsSL -o /usr/local/lib/docker/cli-plugins/docker-compose https://github.com/docker/compose/releases/download/v2.29.7/docker-compose-linux-x86_64
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
fi
docker --version
docker compose version
git --version
python3 --version

echo "=== 2. Lấy sr8 và cấu hình production ==="
mkdir -p /opt/sr8
rm -rf /tmp/sr8_clone
git clone --depth 1 https://github.com/sarsvankelsion/sr8 /tmp/sr8_clone
cp -r /tmp/sr8_clone/. /opt/sr8/
rm -rf /tmp/sr8_clone
cd /opt/sr8

# Sinh token ngẫu nhiên mạnh
SEAL_SEC=$(python3 -c "import secrets; print(secrets.token_hex(24))")
FRP_TOK=$(python3 -c "import secrets; print(secrets.token_hex(24))")
ADMIN_TOK=$(python3 -c "import secrets; print(secrets.token_hex(16))")
DASH_PASS=$(python3 -c "import secrets; print(secrets.token_hex(12))")

cat > .env <<EOF
# SEAL_MODE: "open" = dịch vụ mở, ai cũng vào được không cần seal/ticket
#             "sealed" = bật HMAC, link 1 lần /r xoay vòng
SEAL_MODE=open
SEAL_SECRET=${SEAL_SEC}
GUARD_PORT=19090
FRPS_VHOST=127.0.0.1:8080
VHOST_HOST={name}.tunnel.example.com
SEAL_SINGLE_USE=1
SEAL_ROTATE_SECS=60
SEAL_ROOM_MAX_USES=0
SEAL_RATE_PER_MIN=300
SEAL_TRUSTED_PROXIES=127.0.0.1
SEAL_FORWARD_IP=0
TCP_SEAL_PORT=19091
TCP_BACKEND=127.0.0.1:18082
CF_API_TOKEN=dummy
FRP_TOKEN=${FRP_TOK}
FRP_TRACK=patch
ADMIN_TOKEN=${ADMIN_TOK}
PUBLIC_BASE=
FRPS_BIND_ADDR=127.0.0.1:7000
FRPS_DASH_ADDR=127.0.0.1:7500
FRPS_DASH_USER=admin
FRPS_DASH_PASS=${DASH_PASS}
SR8_VERSION=v0.71.0-guard
ADMIN_ENV_FILE=/opt/sr8/.env
EOF

# Cập nhật frps.toml với token thật + port tách biệt + đồng bộ dashboard password
sed -i "s/auth.token = .*/auth.token = \"${FRP_TOK}\"/" frps.toml
sed -i 's/transport.tls.force = true/transport.tls.force = false/' frps.toml
sed -i "s/webServer.password = .*/webServer.password = \"${DASH_PASS}\"/" frps.toml

echo "=== 3. Build guard-go và khởi động dịch vụ ==="
docker compose build guard
docker compose up -d frps guard
sleep 6
docker compose ps

echo "=== 4. Kiểm tra dịch vụ ==="
curl -s http://127.0.0.1:19090/healthz; echo
ss -tln | grep -E '7000|8080|19090|19091' || true

echo "=== 5. Tạo systemd service tự chạy khi reboot ==="
cat > /etc/systemd/system/sr8.service <<EOF
[Unit]
Description=sr8 tunnel service
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/sr8
ExecStart=/usr/local/lib/docker/cli-plugins/docker-compose up -d frps guard
ExecStop=/usr/local/lib/docker/cli-plugins/docker-compose down

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sr8.service 2>/dev/null || true

echo "============================================="
echo "  SR8 DỊCH VỤ ĐÃ TRIỂN KHAI THÀNH CÔNG!"
echo "  - Vị trí: /opt/sr8"
echo "  - Mode: SEAL_MODE=open (dịch vụ mở, không cần seal)"
echo "  - frps port: 7000 (bindPort cho client kết nối)"
echo "  - guard HTTP: 19090 (reverse proxy về vhost 8080)"
echo "  - guard TCP: 19091 (TCP proxy mở)"
echo "  - DASHBOARD: http://127.0.0.1:19090/admin/ (ssh -L 19090:127.0.0.1:19090 root@VPS)"
echo "  - ADMIN_TOKEN: ${ADMIN_TOK}"
echo "  - FRPS_DASH_PASS: ${DASH_PASS}"
echo "  - FRP_TOKEN: ${FRP_TOK}"
echo "  - SEAL_SECRET: ${SEAL_SEC}"
echo "  - Bật lại seal: sửa SEAL_MODE=sealed trong /opt/sr8/.env"
echo "    rồi chạy: cd /opt/sr8 && docker compose restart guard"
echo "============================================="
