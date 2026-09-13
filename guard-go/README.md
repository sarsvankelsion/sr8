# guard-go — bản Go của Sealed Guard + TCP sealed splice

Port Go của `sealed/guard.py`, stdlib only, 1 binary tĩnh ~10MB.
Giữ nguyên mọi check HTTP `/t` + `/r` (HMAC, expiry, burn-on-valid, rotating ticket,
quota vòng, rate-limit, strip header, sanitize Location), đồng thời sửa 5 điểm Python thua frp:

- **Keep-alive pool**: `http.Transport` 200 idle conn, 50/host, thay vì `HTTPConnection` mới mỗi request.
- **Stream thật**: `FlushInterval: -1`, không buffer full body vào RAM, SSE/WebSocket-friendly.
- **Cap upload**: `http.MaxBytesReader` 10MB ngay tại edge.
- **TCP sealed splice** (`TCP_SEAL_PORT`, mặc định `19091`): frp gốc không có.
  Client gửi 1 dòng handshake trong 5s rồi mới được splice về `TCP_BACKEND`:
  - sealed: `<name>:<exp>:<seal>\n` (seal HTTP cũ vẫn tương thích)
  - room: `<room>:<ticket>\n` (ticket vòng hiện tại)
  Sai handshake trả `403 bad seal` và đóng. Đúng thì `io.Copy` 2 chiều, giữ phần dư sau dòng handshake.

## Chạy

```powershell
$env:SEAL_SECRET="loopback-test-seal-1234567890"
$env:SEAL_ROTATE_SECS="60"
$env:TCP_SEAL_PORT="19091"
$env:TCP_BACKEND="127.0.0.1:18082"
go run .                # dev
go build -o guard-go.exe .   # binary Win (~10MB)
```

Docker production dùng `guard-go/Dockerfile` (multi-stage, distroless).
`sealed/guard.py` giữ lại cho dev/test 1 máy không có toolchain Go.

## Kiểm chứng loopback (frp v0.71.0, 2026-09-13)

- `/t` lần 1 `200`, lần 2 `403`; `/r` ticket hiện tại `200`.
- TCP sealed: `name:exp:seal\n + hello-go` qua `:19091` về backend `:18082` trả `GO-TCP-OK:hello-go`.
