# Test loopback single-machine — không cần VPS, không cần Docker
# Đã kiểm chứng OK trên Windows 11 + frp v0.71.0 (2026-09-13).

## Nguyên tắc
Chạy cả frps + frpc + backend trên 127.0.0.1, port dải test tránh đụng production:
- frps bind 17000, vhost 18080, tcpmux 15002, dashboard 17500
- backend HTTP 18081, backend TCP 18082
- remotePort public 20001 trong allowPorts 20000-20100

## Cách chạy tay (PowerShell, path ngắn C:\Temp\frp để tránh lỗi space)
```powershell
# 1. backend HTTP dummy
python -m http.server 18081 --bind 127.0.0.1
# 2. frps
C:\Temp\frp\frps.exe -c C:\Temp\frp\s.toml
# 3. frpc
C:\Temp\frp\frpc.exe -c C:\Temp\frp\c.toml
# 4. kiểm chứng HTTP qua vhost (phải kèm Host header)
Invoke-WebRequest -Uri http://127.0.0.1:18080/ -Headers @{Host="loopback.test"} -UseBasicParsing
# 5. kiểm chứng TCP thô (backend TCP phải chạy ở 18082 trước)
python -c "import socket; s=socket.create_connection(('127.0.0.1',20001),timeout=5); s.sendall(b'hello-frp'); print(s.recv(1024)); s.close()"
```

## Verify cú pháp chính thức (không cần chạy)
```powershell
C:\Temp\frp\frps.exe verify -c work\fast-tunnel\frps.toml
C:\Temp\frp\frpc.exe verify -c work\fast-tunnel\frpc-examples.toml
```

## Vì sao background runner lỗi trước đó
- Lệnh chứa `& "..."` + path có dấu cách `Default Project` bị CommandNotFound.
- `Start-Process` cũng fail khi path dài có space + AV chặn.
- Fix: copy binary + toml ra `C:\Temp\frp\` rồi chạy trực tiếp, không quote lồng nhau.
- `network_mode: host` trong compose CHỈ chạy trên Linux. Docker Desktop Win/Mac bỏ qua host mode,
  nên đừng test compose trên Win — test loopback binary như trên mới đúng.
