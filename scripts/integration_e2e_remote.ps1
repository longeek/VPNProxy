#Requires -Version 5.1
<#
.SYNOPSIS
  End-to-end integration checks against a deployed VPNProxy server (local client + curl + optional SSH).

.DESCRIPTION
  Covers feedback from manual debugging:
  - curl uses Schannel on Windows: pass --ssl-no-revoke to avoid CRYPT_E_REVOCATION_OFFLINE
  - Chrome must use SOCKS5 (not HTTP proxy on the SOCKS port) and often needs --disable-quic

  Remote checks (optional): systemd + port 8443 via SSH (requires your key: BatchMode).

.PARAMETER RemoteHost
  VPNProxy server address (default 47.88.49.28).

.PARAMETER SshUser
  SSH login user for remote checks and optional cert sync (e.g. admin). Omit to skip SSH.

.PARAMETER SkipSsh
  Do not run SSH remote checks.

.PARAMETER Token
  VPN_PROXY_TOKEN; default $env:VPN_PROXY_TOKEN

.PARAMETER FetchCert
  When set with -SshUser, scp /etc/vpn-proxy/server.crt to -CaCert path before tests.

.PARAMETER TokenFile
  Path to a text file whose first non-empty line is the token (alternative to -Token / env).
  Or set env VPN_PROXY_TOKEN_FILE to the same path.

.PARAMETER HttpPort
  Local HTTP CONNECT port (--http-port). Use 0 to disable extra listener.

.PARAMETER TcpLinePort
  Local TCP line port (--tcp-line-port). Use 0 to disable.

.EXAMPLE
  $env:VPN_PROXY_TOKEN = 'your-token'
  .\scripts\integration_e2e_remote.ps1 -SshUser admin -FetchCert

.EXAMPLE
  .\scripts\integration_e2e_remote.ps1 -SkipSsh -Token $env:VPN_PROXY_TOKEN
#>
param(
  [string]$RemoteHost = "47.88.49.28",
  [string]$SshUser = "",
  [switch]$SkipSsh,
  [string]$Token = $env:VPN_PROXY_TOKEN,
  [string]$TokenFile = "",
  [int]$RemotePort = 8443,
  [string]$Listen = "127.0.0.1",
  [int]$ListenPort = 1080,
  [int]$HttpPort = 8080,
  [int]$TcpLinePort = 1081,
  [string]$CaCertRelative = "certs\server.crt",
  [switch]$FetchCert,
  [string]$ProjectRoot = ""
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ProjectRoot) {
  $ProjectRoot = (Resolve-Path (Join-Path $ScriptDir "..")).Path
}

Set-Location $ProjectRoot

if (-not $Token -and $TokenFile -and (Test-Path -LiteralPath $TokenFile)) {
  $Token = (Get-Content -LiteralPath $TokenFile -Encoding UTF8 | Where-Object { $_.Trim() -ne "" -and -not $_.Trim().StartsWith("#") } | Select-Object -First 1).Trim()
}
if (-not $Token -and $env:VPN_PROXY_TOKEN_FILE -and (Test-Path -LiteralPath $env:VPN_PROXY_TOKEN_FILE)) {
  $Token = (Get-Content -LiteralPath $env:VPN_PROXY_TOKEN_FILE -Encoding UTF8 | Where-Object { $_.Trim() -ne "" -and -not $_.Trim().StartsWith("#") } | Select-Object -First 1).Trim()
}

function Write-Step {
  param([string]$Message)
  Write-Host ""
  Write-Host "=== $Message ===" -ForegroundColor Cyan
}

function Test-TcpPort {
  param([string]$ComputerName, [int]$Port, [int]$TimeoutSec = 8)
  try {
    $client = New-Object System.Net.Sockets.TcpClient
    $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)
    if (-not $iar.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSec), $false)) {
      $client.Close()
      return $false
    }
    $client.EndConnect($iar)
    $client.Close()
    return $true
  } catch {
    return $false
  }
}

Write-Step "T00: TCP reachability ${RemoteHost}:${RemotePort}"
if (Test-TcpPort -ComputerName $RemoteHost -Port $RemotePort) {
  Write-Host "[PASS] Port ${RemotePort} is reachable." -ForegroundColor Green
} else {
  Write-Host "[FAIL] Cannot connect to ${RemoteHost}:${RemotePort} (firewall, wrong IP, or service down)." -ForegroundColor Red
  exit 2
}

if (-not $SkipSsh -and $SshUser) {
  Write-Step "T01/T02: SSH remote service + listen (user=$SshUser)"
  $sshTarget = "${SshUser}@${RemoteHost}"
  $remoteCmd = 'systemctl is-active vpn-proxy 2>/dev/null || echo vpn-proxy_not_active; ss -lntp 2>/dev/null | grep -E ":8443\b" || true'
  try {
    $out = ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new $sshTarget $remoteCmd
    Write-Host $out
    if ($out -match "vpn-proxy_not_active") {
      Write-Host "[WARN] vpn-proxy service is not active on remote; fix systemd before release." -ForegroundColor Yellow
    } else {
      Write-Host "[INFO] SSH remote checks completed (see output above)." -ForegroundColor Green
    }
  } catch {
    Write-Host "[SKIP] SSH failed: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "       Run this script from a machine where: ssh $sshTarget (BatchMode/key) works."
  }

  if ($FetchCert) {
    Write-Step "Fetch server.crt via scp"
    $caPath = Join-Path $ProjectRoot $CaCertRelative
    $caDir = Split-Path -Parent $caPath
    if (-not (Test-Path $caDir)) { New-Item -ItemType Directory -Path $caDir | Out-Null }
    scp -o BatchMode=yes -o ConnectTimeout=15 "${sshTarget}:/etc/vpn-proxy/server.crt" $caPath
    Write-Host "[OK] Wrote $caPath"
  }
} elseif (-not $SkipSsh -and -not $SshUser) {
  Write-Step "T01/T02: SSH skipped (pass -SshUser admin to enable)"
}

$caFull = Join-Path $ProjectRoot $CaCertRelative
if (-not (Test-Path $caFull)) {
  Write-Host "[FAIL] CA cert not found: $caFull (use -FetchCert with SSH or copy server.crt manually)." -ForegroundColor Red
  exit 3
}

if (-not $Token) {
  Write-Host "[FAIL] Missing token: set `$env:VPN_PROXY_TOKEN, pass -Token, -TokenFile <path>, or `$env:VPN_PROXY_TOKEN_FILE (first non-comment line)." -ForegroundColor Red
  exit 4
}

Write-Step "T04-T08: Local client (SOCKS5 + HTTP + TCP line) + curl + channel smoke"
$clientArgs = @(
  "-u", "client.py",
  "--listen", $Listen,
  "--listen-port", "$ListenPort",
  "--server", $RemoteHost,
  "--server-port", "$RemotePort",
  "--token", $Token,
  "--ca-cert", $CaCertRelative,
  "--connect-retries", "3",
  "--retry-delay", "0.8"
)
if ($HttpPort -gt 0) {
  $clientArgs += @("--http-port", "$HttpPort")
}
if ($TcpLinePort -gt 0) {
  $clientArgs += @("--tcp-line-port", "$TcpLinePort")
}

$py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $py) { $py = (Get-Command python3 -ErrorAction SilentlyContinue).Source }
if (-not $py) { throw "python not found in PATH" }

$requiredPorts = [System.Collections.ArrayList]@($ListenPort)
if ($HttpPort -gt 0) { [void]$requiredPorts.Add($HttpPort) }
if ($TcpLinePort -gt 0) { [void]$requiredPorts.Add($TcpLinePort) }

$proc = Start-Process -FilePath $py -ArgumentList $clientArgs -WorkingDirectory $ProjectRoot `
  -WindowStyle Hidden -PassThru
try {
  $deadline = (Get-Date).AddSeconds(25)
  $listening = $false
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) {
      throw "client.py exited early with code $($proc.ExitCode)"
    }
    $allUp = $true
    foreach ($p in $requiredPorts) {
      if (-not (Test-TcpPort -ComputerName $Listen -Port $p -TimeoutSec 1)) {
        $allUp = $false
        break
      }
    }
    if ($allUp) {
      $listening = $true
      break
    }
    Start-Sleep -Milliseconds 200
  }
  if (-not $listening) {
    throw "Local client not listening on ${Listen} ports: $($requiredPorts -join ', ')"
  }

  $curlCommon = @("--ssl-no-revoke", "--socks5-hostname", "${Listen}:${ListenPort}", "-sS", "--max-time", "25")

  Write-Host "T04: SOCKS5 curl ifconfig.me..."
  & curl.exe @curlCommon "https://ifconfig.me"
  if ($LASTEXITCODE -ne 0) { throw "curl ifconfig.me failed with exit $LASTEXITCODE" }
  Write-Host ""

  Write-Host "T04b: SOCKS5 curl Google HEAD..."
  & curl.exe @curlCommon "-I" "https://www.google.com"
  if ($LASTEXITCODE -ne 0) { throw "curl google failed with exit $LASTEXITCODE" }
  Write-Host ""
  Write-Host "[PASS] T04 SOCKS5 (curl) OK." -ForegroundColor Green

  if ($HttpPort -gt 0) {
    Write-Host "T05: HTTP CONNECT proxy curl https://ifconfig.me ..."
    $hp = "http://${Listen}:${HttpPort}"
    & curl.exe "--ssl-no-revoke", "--proxy", $hp, "-sS", "--max-time", "25" "https://ifconfig.me"
    if ($LASTEXITCODE -ne 0) { throw "curl via HTTP proxy failed with exit $LASTEXITCODE" }
    Write-Host ""
    Write-Host "[PASS] T05 HTTP CONNECT OK." -ForegroundColor Green
  } else {
    Write-Host "[SKIP] T05 HTTP (HttpPort=0)." -ForegroundColor DarkGray
  }

  $smoke = Join-Path $ProjectRoot "scripts\proxy_channel_smoke.py"
  if (-not (Test-Path $smoke)) {
    throw "Missing smoke script: $smoke"
  }

  if ($TcpLinePort -gt 0) {
    Write-Host "T06: TCP line (httpbin GET via tunnel)..."
    $tcpArgs = @(
      $smoke, "--tcp-line-host", $Listen, "--tcp-line-port", "$TcpLinePort", "--skip-socks-udp"
    )
    & $py @tcpArgs
    if ($LASTEXITCODE -ne 0) { throw "proxy_channel_smoke TCP line failed with exit $LASTEXITCODE" }
    Write-Host "[PASS] T06 TCP line OK." -ForegroundColor Green
  } else {
    Write-Host "[SKIP] T06 TCP line (TcpLinePort=0)." -ForegroundColor DarkGray
  }

  Write-Host "T07: SOCKS5 UDP ASSOCIATE (DNS to 8.8.8.8)..."
  $udpArgs = @(
    $smoke, "--socks-host", $Listen, "--socks-port", "$ListenPort", "--skip-tcp-line"
  )
  & $py @udpArgs
  if ($LASTEXITCODE -ne 0) { throw "proxy_channel_smoke SOCKS UDP failed with exit $LASTEXITCODE" }
  Write-Host "[PASS] T07 SOCKS5 UDP OK." -ForegroundColor Green

  Write-Host ""
  Write-Host "[PASS] T08 All enabled channel checks completed." -ForegroundColor Green
} finally {
  if (-not $proc.HasExited) {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
  }
}

Write-Step "Browser (Chrome on Windows): avoid ERR_TUNNEL_CONNECTION_FAILED"
$chrome = "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe"
if (-not (Test-Path $chrome)) {
  $chrome = "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
}
if (Test-Path $chrome) {
  $hint = "`"$chrome`" --proxy-server=`"socks5://${Listen}:${ListenPort}`" --disable-quic"
  Write-Host "Use SOCKS5 (not HTTP) on port $ListenPort, disable QUIC, e.g.:" -ForegroundColor DarkGray
  Write-Host $hint -ForegroundColor Gray
  if ($HttpPort -gt 0) {
    Write-Host "Or HTTP proxy: --proxy-server=`"http://${Listen}:${HttpPort}`"" -ForegroundColor Gray
  }
} else {
  Write-Host "Chrome path not found; set proxy to SOCKS5 ${Listen}:${ListenPort} and disable QUIC in chrome://flags" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "Integration script finished." -ForegroundColor Cyan
