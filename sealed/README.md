# Sealed Link — tính năng đột phá biến frp thành của riêng bạn

PortBuddy/frp nguyên bản chia sẻ bằng URL sống lâu + password chung.
Sealed Link chia sẻ bằng link dùng một lần, hết hạn tự hủy, không password.

## Kiến trúc
```
visitor -> guard(:19090) -> frps vhost(:18080, Host=loopback.test) -> backend(:18081)
              | verify HMAC(secret, "name:exp") + expiry + single-use
              | forward giữ Host để frp routing đúng 1 proxy duy nhất
```
Điểm đột phá: frp chỉ cần **1 http proxy tĩnh**. Guard multiplex vô hạn link
bằng path `/t/<name>/`, không cần tạo proxy/domain mới cho mỗi lần share.
PortBuddy cần 1 tunnel cho mỗi lần share. frp nguyên bản cần sửa TOML + reload.

## Tạo link
```powershell
$env:SEAL_SECRET="loopback-test-seal-1234567890"
$env:GUARD_BASE="http://127.0.0.1:19090"
python sealed/seal.py demo 300
# -> http://127.0.0.1:19090/t/demo/?exp=...&seal=...
```

## Chạy production (VPS Linux)
1. frps giữ nguyên, chỉ mở vhost `127.0.0.1:8080`, không public trực tiếp.
2. Guard public `:443` (qua Caddy) thay cho frps. Env:
   `GUARD_PORT=19090 FRPS_VHOST=127.0.0.1:8080 VHOST_HOST="{name}.tunnel.example.com"`
   Muốn 1 proxy phục vụ mọi link thì để `VHOST_HOST` cố định 1 subdomain duy nhất.
   Muốn mỗi link 1 subdomain thì pre-create N proxy `link-01..link-N` và đặt VHOST theo name.
3. `SEAL_SECRET` 32+ ký tự, `SEAL_SINGLE_USE=1`, `SEAL_USED_DB` ra volume persistent.
4. Caddy reverse `*.tunnel.example.com` về guard, không về frps trực tiếp.

## Kết quả kiểm chứng loopback (frp v0.71.0, Win 11, 2026-09-13)
- Lần 1 đúng seal: `200`
- Lần 2 dùng lại link: `403 link already used`
- Sai seal / thiếu seal / hết hạn: `403`
- HTTP xuyên `guard -> frps vhost -> backend` giữ nguyên body (200 len 309).
- TCP thô frp vẫn độc lập: `127.0.0.1:20001 -> 18082` echo `FRP-TCP-OK`.

## Giới hạn v1
- Guard hiện tại chỉ bọc HTTP. TCP/UDP thô vẫn dùng frps `remotePort + token` (xem FREE-HOSTS.md).
- Single-use lưu file JSON local. Multi-instance cần Redis/postgres thay `load_used/save_used`.
- Chưa có UI thu hồi link. Muốn revoke sớm thì xóa key khỏi USED_DB hoặc đổi exp về quá khứ.
