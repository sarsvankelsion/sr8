#!/bin/bash
# fast-frp: wrapper tốc độ kiểu portbuddy trên nền frp
# Usage: ./fast-frp.sh 3000 [subdomain] | ./fast-frp.sh --tcp 5432 25432 | ./fast-frp.sh --udp 19132 31913
set -e
FRP_SERVER="${FRP_SERVER:-VPS_IP_HOAC_tunnel.example.com}"
FRP_DOMAIN="${FRP_DOMAIN:-tunnel.example.com}"
FRP_PORT="${FRP_PORT:-7000}"
FRP_TOKEN="${FRP_TOKEN:-CHANGE-ME-32-CHARS-MIN}"
# Giữ remotePort trong allowPorts 20000-40000 của frps.toml + valid TCP/UDP 1-65535.
# Công thức cũ 2$LOCAL / 3$LOCAL gây tràn (vd 19132 -> 319132). Đã fix bằng modulo.
default_tcp_port() { echo $((20000 + ($1 % 10000))); }
default_udp_port() { echo $((30000 + ($1 % 10000))); }
MODE="http"
if [ "$1" = "--tcp" ]; then MODE="tcp"; shift; fi
if [ "$1" = "--udp" ]; then MODE="udp"; shift; fi
LOCAL_PORT="$1"
NAME="${2:-demo-$RANDOM}"
REMOTE_PORT="$3"
if [ -z "$LOCAL_PORT" ]; then echo "Usage: $0 [--tcp|--udp] <localPort> [name] [remotePort]"; exit 2; fi
TMP_CONF="/tmp/frpc-fast-$NAME.toml"
if [ "$MODE" = "http" ]; then
cat > "$TMP_CONF" <<EOF
serverAddr = "$FRP_SERVER"
serverPort = $FRP_PORT
auth.method = "token"
auth.token = "$FRP_TOKEN"
transport.tls.enable = true
[[proxies]]
name = "$NAME"
type = "http"
localIP = "127.0.0.1"
localPort = $LOCAL_PORT
subdomain = "$NAME"
EOF
echo "-> https://$NAME.$FRP_DOMAIN (via Caddy -> frps 8080)"
elif [ "$MODE" = "tcp" ]; then
REMOTE_PORT="${REMOTE_PORT:-$(default_tcp_port "$LOCAL_PORT")}"
cat > "$TMP_CONF" <<EOF
serverAddr = "$FRP_SERVER"
serverPort = $FRP_PORT
auth.method = "token"
auth.token = "$FRP_TOKEN"
transport.tls.enable = true
[[proxies]]
name = "$NAME"
type = "tcp"
localIP = "127.0.0.1"
localPort = $LOCAL_PORT
remotePort = $REMOTE_PORT
EOF
echo "-> raw TCP $FRP_SERVER:$REMOTE_PORT => 127.0.0.1:$LOCAL_PORT"
else
REMOTE_PORT="${REMOTE_PORT:-$(default_udp_port "$LOCAL_PORT")}"
cat > "$TMP_CONF" <<EOF
serverAddr = "$FRP_SERVER"
serverPort = $FRP_PORT
auth.method = "token"
auth.token = "$FRP_TOKEN"
transport.tls.enable = true
[[proxies]]
name = "$NAME"
type = "udp"
localIP = "127.0.0.1"
localPort = $LOCAL_PORT
remotePort = $REMOTE_PORT
EOF
echo "-> raw UDP $FRP_SERVER:$REMOTE_PORT => 127.0.0.1:$LOCAL_PORT"
fi
exec frpc -c "$TMP_CONF"
