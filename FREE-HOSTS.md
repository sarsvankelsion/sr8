# Free-host cho fast-tunnel — TCP thô có chạy được không?

Kết luận trước: TCP/UDP thô cần VPS có IP public + mở được inbound port tùy ý.
Hầu hết PaaS free (Render/Vercel/Netlify/HF Spaces/Railway free) KHÔNG chạy được frps TCP thô.

## 1. Chạy được TCP/UDP thô

### A. Oracle Cloud Always Free (khuyên dùng cho frps 24/7)
- VM Ampere A1 (4 OCPU/24GB) hoặc 2x E2 micro, IP public tĩnh, free vĩnh viễn.
- Mở Ingress trong Security List / NSG: 7000/tcp, 5002/tcp, 7835/tcp (bore control),
  8080/8443/tcp (vhost), 20000-40000/tcp+udp (remotePort), 2222/tcp (SSH gateway).
- Chạy: `docker compose up -d` trong `work/fast-tunnel`.
- Đây là phương án duy nhất free mà đủ P5-P11 dài hạn.

### B. GCP/AWS/Azure free tier (tạm 12 tháng / 750h)
- e2-micro / t2.micro / B1s đều có IP public, mở firewall cho các port như trên là chạy frps ngon.
- Hết free thì migrate sang Oracle.

### C. Fly.io (chạy được TCP nhưng giới hạn)
- Fly cho expose TCP qua `[[services]]` với `internal_port = 7000`, hỗ trợ cả UDP.
- Phải khai báo từng port, không có range 20000-40000 thoải mái như VPS.
- Free allowance ít (shared-cpu 256MB), sleep/scale-to-zero gây rớt tunnel.
- Chỉ hợp demo, không hợp frps chính.

### D. bore.pub — free TCP tạm, không cần host gì cả
- Public bore-server sẵn: control `bore.pub:7835`.
- Client: `bore local 3000 --to bore.pub` -> nhận `bore.pub:<random-port>` TCP thô ngay.
- Không cần VPS, không cần config. Phù hợp P1/P3 dùng một lần.
- Nhược: port random, không UDP, không HTTP routing, không auth mạnh, không SLA.

## 2. KHÔNG chạy được TCP thô (đừng cố)

- Render free: chỉ HTTP inbound, sleep sau idle, không mở port tùy ý.
- Railway free: TCP Proxy là tính năng trả phí, free chỉ HTTP.
- Vercel/Netlify/Cloudflare Pages/HF Spaces: chỉ HTTP(S), không listen TCP/UDP.
- Cloudflare Tunnel free: `cloudflared --url localhost:3000` cho HTTPS `*.trycloudflare.com` rất nhanh,
  nhưng không cho public TCP `IP:port` thô. Muốn TCP public phải dùng Spectrum (trả phí).
- GitHub Codespaces/Replit/Glitch: port forward qua UI của họ, không có public TCP ổn định.

## 3. Kiến trúc khuyên dùng 0đ

```
demo tạm (P1/P3): bore local 3000 --to bore.pub   (0đ, không cần VPS)
webhook cần ổn định (P2): frps trên Oracle + subdomain *.tunnel.domain.com + Caddy TLS
TCP/UDP/game/SSH dài hạn (P5-P8): frps trên Oracle, remotePort 20000-40000
kín/P2P/HA (P10-P11): frp stcp/xtcp/LB, không host SaaS nào free làm được
```

## 4. Kiểm chứng TCP thô (sau khi `docker compose up -d` trên VPS)

```bash
# Trên VPS: kiểm tra các port đang nghe
ss -tlnp | grep -E '7000|7835|8080|5002|2222'

# Trên máy local: mở TCP 5432 ra VPS:25432
./fast-frp.sh --tcp 5432 pg-demo 25432
# Máy khác test:
nc -vz VPS_IP 25432
psql -h VPS_IP -p 25432 -U postgres

# Test bore sidecar (TCP thô random, không cần frp):
bore local 3000 --to VPS_IP
# hoặc dùng free public:
bore local 3000 --to bore.pub
```

## 5. Lưu ý an toàn khi mở TCP public

- Đổi `auth.token`, `webServer.password`, `secretKey` trong `frps.toml` trước khi up.
- DB/SSH share qua TCP thô là byte-for-byte, auth của service gốc lộ ra Internet:
  DB phải có password mạnh, SSH nên key-only + fail2ban.
- Dashboard 7500 đã bind `127.0.0.1`, muốn xem từ xa thì `ssh -L 7500:127.0.0.1:7500 user@VPS`.
