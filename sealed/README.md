# Sealed Link + Rotating Room — tính năng đột phá biến frp thành của riêng bạn

2 chế độ share trên cùng 1 guard, cùng 1 frp proxy tĩnh:

- `/t/<name>/?exp=..&seal=..` — link 1-1: dùng một lần, hết hạn tự hủy, không password.
- `/r/<room>/?ticket=..` — phòng chung xoay vòng: 1 URL chung, ticket đổi mỗi `SEAL_ROTATE_SECS`,
  link leak/forward ra ngoài tự chết sau ~2 vòng. Giới hạn lượt/vòng chống phá.

## Kiến trúc
```
visitor -> guard(:19090) -> frps vhost(:18080, Host=loopback.test) -> backend(:18081)
              | /t: HMAC(secret,"name:exp") + expiry + single-use
              | /r: HMAC(secret,"room:<round>") + round hiện tại + 1 vòng trước
              | rate-limit/IP + strip header lộ IP + fingerprint nginx
```

## Tạo link
```powershell
$env:SEAL_SECRET="loopback-test-seal-1234567890"
$env:GUARD_BASE="http://127.0.0.1:19090"
python sealed/seal.py demo 300
# -> http://127.0.0.1:19090/t/demo/?exp=...&seal=...

$env:SEAL_ROTATE_SECS="60"
python sealed/seal.py --room team 60
# -> http://127.0.0.1:19090/r/team/?ticket=...
# ticket xoay mỗi 60s. Muốn test vòng cũ: python sealed/seal.py --room team 60 --at <unix>
```

## Vì sao rotating chống phá tốt hơn link tĩnh

- Link `/t` dùng 1 lần: ai forward cũng chỉ xài được 1 lượt rồi chết. Hợp share 1-1.
- Room `/r` dùng chung: không single-use, nhưng ticket gắn với `round = floor(now/60)`.
  Link bị chụp màn hình/forward ra ngoài quá ~2 vòng là vô dụng, không cần revoke tay.
- `SEAL_ROOM_MAX_USES=50` giới hạn 50 lượt/vòng/room: chống spam F5, bot cày, share tràn lan.
- `SEAL_RATE_PER_MIN=120` giới hạn brute-force seal theo IP.
- Guard chấp nhận vòng hiện tại + 1 vòng trước để trừ clock-skew và request đang bay
  khi chạm biên vòng. Vòng cũ hơn 1 vòng luôn `403 bad or rotated ticket`.

## Chạy production (VPS Linux)
1. frps giữ nguyên, chỉ mở vhost `127.0.0.1:8080`, không public trực tiếp.
2. Guard public `:443` (qua Caddy) thay cho frps. Env:
   `GUARD_PORT=19090 FRPS_VHOST=127.0.0.1:8080 VHOST_HOST="{name}.tunnel.example.com"`
   `SEAL_ROTATE_SECS=60 SEAL_ROOM_MAX_USES=50 SEAL_RATE_PER_MIN=120`
3. `SEAL_SECRET` 32+ ký tự, `SEAL_SINGLE_USE=1`, `SEAL_USED_DB` + `SEAL_ROOM_DB` ra volume persistent.
4. Caddy reverse `*.tunnel.example.com` về guard, không về frps trực tiếp.

## Kết quả kiểm chứng loopback (frp v0.71.0, Win 11, 2026-09-13)
- `/t` lần 1: `200`, lần 2 dùng lại: `403 link already used`.
- `/t` sai/thiếu/hết hạn seal: `403`.
- `/r` ticket hiện tại: `200`, dùng chung nhiều lần trong vòng vẫn `200`.
- `/r` ticket cách 3 phút (2+ vòng): `403 bad or rotated ticket`.
- HTTP xuyên `guard -> frps vhost -> backend` giữ nguyên body.
- TCP thô frp vẫn độc lập: `127.0.0.1:20001 -> 18082` echo `FRP-TCP-OK`.

## Giới hạn
- Guard chỉ bọc HTTP. TCP/UDP thô vẫn dùng frps `remotePort + token` (xem FREE-HOSTS.md).
- Single-use + room-count lưu file JSON local. Multi-instance cần Redis/postgres.
- Chưa có UI thu hồi. `/t` revoke bằng cách xóa key khỏi USED_DB; `/r` tự chết theo vòng,
  muốn kill ngay thì đổi `SEAL_SECRET` hoặc set `ROOM_MAX_USES=0` tạm thời rồi mở lại.
