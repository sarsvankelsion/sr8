#Requires -Version 5.1
<#
.SYNOPSIS
  fast-frp Windows: wrapper tốc độ kiểu portbuddy trên nền frp (không cần bash/WSL).
.EXAMPLE
  $env:FRP_SERVER="127.0.0.1"; $env:FRP_PORT="17000"; $env:FRP_TOKEN="loopback-test-token-12345678"
  .\fast-frp.ps1 18081 demo          # http subdomain demo
  .\fast-frp.ps1 --tcp 18082 pg-demo 20002
  .\fast-frp.ps1 --udp 19132 mc 30001
#>
param(
  [Parameter(Position=0)][string]$ModeOrPort,
  [Parameter(Position=1)][string]$Arg2,
  [Parameter(Position=2)][string]$Arg3
)
$ErrorActionPreference = 'Stop'
$FrpServer = if ($env:FRP_SERVER) { $env:FRP_SERVER } else { 'VPS_IP_HOAC_tunnel.example.com' }
$FrpDomain = if ($env:FRP_DOMAIN) { $env:FRP_DOMAIN } else { 'tunnel.example.com' }
$FrpPort = if ($env:FRP_PORT) { [int]$env:FRP_PORT } else { 7000 }
$FrpToken = if ($env:FRP_TOKEN) { $env:FRP_TOKEN } else { 'CHANGE-ME-32-CHARS-MIN' }
$FrpcBin = if ($env:FRPC_BIN) { $env:FRPC_BIN } else { 'C:\Temp\frp\frpc.exe' }
$Mode = 'http'
$LocalPort = $ModeOrPort
$Name = $null
$RemotePort = $null
if ($ModeOrPort -eq '--tcp') { $Mode = 'tcp'; $LocalPort = $Arg2; $Name = $Arg3 }
elseif ($ModeOrPort -eq '--udp') { $Mode = 'udp'; $LocalPort = $Arg2; $Name = $Arg3 }
else { $Name = $Arg2; $RemotePort = $Arg3 }
if (-not $LocalPort) { Write-Host 'Usage: .\fast-frp.ps1 [--tcp|--udp] <localPort> [name] [remotePort]'; exit 2 }
if (-not $Name) { $Name = "demo-$(Get-Random -Minimum 1000 -Maximum 9999)" }
function Default-TcpPort([int]$p) { return 20000 + ($p % 10000) }
function Default-UdpPort([int]$p) { return 30000 + ($p % 10000) }
$Tmp = Join-Path $env:TEMP "frpc-fast-$Name.toml"
if ($Mode -eq 'http') {
  $Body = @"
serverAddr = "$FrpServer"
serverPort = $FrpPort
auth.method = "token"
auth.token = "$FrpToken"
transport.tls.enable = true
[[proxies]]
name = "$Name"
type = "http"
localIP = "127.0.0.1"
localPort = $LocalPort
subdomain = "$Name"
"@
  Write-Host "-> https://$Name.$FrpDomain"
} elseif ($Mode -eq 'tcp') {
  if (-not $RemotePort) { $RemotePort = Default-TcpPort ([int]$LocalPort) }
  $Body = @"
serverAddr = "$FrpServer"
serverPort = $FrpPort
auth.method = "token"
auth.token = "$FrpToken"
transport.tls.enable = true
[[proxies]]
name = "$Name"
type = "tcp"
localIP = "127.0.0.1"
localPort = $LocalPort
remotePort = $RemotePort
"@
  Write-Host "-> raw TCP ${FrpServer}:${RemotePort} => 127.0.0.1:${LocalPort}"
} else {
  if (-not $RemotePort) { $RemotePort = Default-UdpPort ([int]$LocalPort) }
  $Body = @"
serverAddr = "$FrpServer"
serverPort = $FrpPort
auth.method = "token"
auth.token = "$FrpToken"
transport.tls.enable = true
[[proxies]]
name = "$Name"
type = "udp"
localIP = "127.0.0.1"
localPort = $LocalPort
remotePort = $RemotePort
"@
  Write-Host "-> raw UDP ${FrpServer}:${RemotePort} => 127.0.0.1:${LocalPort}"
}
Set-Content -LiteralPath $Tmp -Value $Body -Encoding UTF8
& $FrpcBin -c $Tmp
