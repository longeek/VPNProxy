#Requires -Version 5.1
<#
.SYNOPSIS
  Cross-compile Go VPN proxy server, deploy to remote, start local Go client, and run E2E throughput tests.

.DESCRIPTION
  Full end-to-end pipeline for Go-based VPN proxy:
    1. Cross-compile vpn-proxy-server for linux/amd64
    2. Upload + deploy to remote via SSH (replace binary + restart systemd)
    3. Start local Go client (SOCKS5 + HTTP proxy, background)
    4. Run throughput benchmarks (baidu.com / youtube.com / speedtest)
    5. Collect server-side session stats for verification
    6. Clean up local client process

  Requirements:
    - Go toolchain (go build)
    - SSH key-based login to remote (BatchMode)
    - curl.exe on PATH
    - $env:VPN_PROXY_TOKEN set, or pass -Token

.PARAMETER RemoteHost
  VPNProxy server address (default 47.88.49.28)

.PARAMETER SshUser
  SSH login user (default admin)

.PARAMETER Token
  VPN proxy auth token (default $env:VPN_PROXY_TOKEN)

.PARAMETER ServerPort
  Remote server listening port (default 443)

.PARAMETER ListenPort
  Local SOCKS5 port (default 1080)

.PARAMETER HttpPort
  Local HTTP CONNECT port (default 8080, 0=disable)

.PARAMETER Insecure
  Skip TLS cert verification (default true for self-signed certs)

.PARAMETER TestDuration
  Max seconds per curl test (default 20)

.PARAMETER SkipDeploy
  Skip build + upload; only run tests against existing server

.PARAMETER SkipTests
  Skip throughput tests; only build + deploy

.EXAMPLE
  $env:VPN_PROXY_TOKEN = 'your-token'
  .\scripts\go_deploy_e2e_test.ps1

.EXAMPLE
  .\scripts\go_deploy_e2e_test.ps1 -RemoteHost 47.88.49.28 -SshUser admin -Token '...' -SkipDeploy
#>

param(
  [string]$RemoteHost = "47.88.49.28",
  [string]$SshUser = "admin",
  [string]$Token = $env:VPN_PROXY_TOKEN,
  [int]$ServerPort = 443,
  [int]$ListenPort = 1080,
  [int]$HttpPort = 8080,
  [switch]$Insecure = $true,
  [int]$TestDuration = 20,
  [switch]$SkipDeploy,
  [switch]$SkipTests,
  [string]$ProjectRoot = ""
)

$ErrorActionPreference = "Stop"
$OriginalPreference = $ErrorActionPreference

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ProjectRoot) {
  $ProjectRoot = (Resolve-Path (Join-Path $ScriptDir "..")).Path
}
Set-Location $ProjectRoot

# ── helpers ──────────────────────────────────────────────
function Write-Step { param([string]$Message) Write-Host "`n=== $Message ===" -ForegroundColor Cyan }
function Write-Pass { Write-Host "[PASS]" -ForegroundColor Green -NoNewline; Write-Host " $($args -join ' ')" }
function Write-Fail { Write-Host "[FAIL]" -ForegroundColor Red -NoNewline; Write-Host " $($args -join ' ')" }
function Write-Skip { Write-Host "[SKIP]" -ForegroundColor DarkGray -NoNewline; Write-Host " $($args -join ' ')" }

# ── preflight ────────────────────────────────────────────
if (-not $Token) { throw "Missing token: pass -Token or set VPN_PROXY_TOKEN" }
if (-not (Get-Command go -ErrorAction SilentlyContinue)) { throw "Go not found in PATH" }
if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) { throw "curl.exe not found in PATH" }

$GoServerDir = Join-Path $ProjectRoot "vpn-proxy-go"
$ServerBinary = Join-Path $GoServerDir "bin\vpn-proxy-server-linux"
$ClientBinary = Join-Path $GoServerDir "bin\vpn-proxy-client.exe"

Write-Step "PREFLIGHT"
Write-Host "  Remote: ${SshUser}@${RemoteHost}:${ServerPort}"
Write-Host "  Client binary: $ClientBinary"

# ── Step 1: Cross-compile ────────────────────────────────
if (-not $SkipDeploy) {
  Write-Step "S01: Cross-compile Go server for linux/amd64"
  Push-Location $GoServerDir
  try {
    $env:GOOS = "linux"
    $env:GOARCH = "amd64"
    $result = go build -ldflags="-s -w" -o $ServerBinary ./cmd/server/ 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Go build failed: $result" }
    $size = (Get-Item $ServerBinary).Length
    Write-Pass "vpn-proxy-server-linux ($([math]::Round($size/1KB)) KB)"
  } finally {
    Pop-Location
  }
} else {
  Write-Skip "S01: Cross-compile (-SkipDeploy)"
}

# ── Step 2: Upload + restart server ──────────────────────
if (-not $SkipDeploy) {
  Write-Step "S02: Upload + deploy to $RemoteHost"
  $tmpBin = "/tmp/vpn-proxy-server-linux"
  Write-Host "  scp → ${SshUser}@${RemoteHost}:${tmpBin}..."
  scp -o ConnectTimeout=10 -o BatchMode=yes $ServerBinary "${SshUser}@${RemoteHost}:${tmpBin}" 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "scp failed" }

  $remoteCmds = @(
    "sudo mv $tmpBin /opt/vpn-proxy/vpn-proxy-server",
    "sudo chmod +x /opt/vpn-proxy/vpn-proxy-server",
    "sudo systemctl restart vpn-proxy",
    "sleep 2",
    "sudo ss -tlnp | grep vpn-proxy || true"
  )
  $remoteResult = ssh -o ConnectTimeout=10 -o BatchMode=yes -o StrictHostKeyChecking=accept-new "${SshUser}@${RemoteHost}" ($remoteCmds -join '; ')
  Write-Host $remoteResult
  if ($remoteResult -match "vpn-proxy-serve.*:${ServerPort}") {
    Write-Pass "Server listening on :${ServerPort}"
  } else {
    Write-Fail "Server may not be listening on :${ServerPort} — check manually"
  }
} else {
  Write-Skip "S02: Deploy (-SkipDeploy)"
}

# ── Step 3: Kill old Go client ───────────────────────────
Write-Step "S03: Kill old Go client (if any)"
Get-Process -Name "vpn-proxy-client" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 2
Write-Pass "Old client terminated"

# ── Step 4: Start local Go client ────────────────────────
Write-Step "S04: Start Go client (background)"
$clientArgs = @(
  "--server", $RemoteHost,
  "--server-port", "$ServerPort",
  "--token", $Token,
  "--proxy-user", "longeek",
  "--proxy-pass", "Mengql123",
  "--http-port", "$HttpPort"
)
if ($Insecure) { $clientArgs += "--insecure" }

$clientLog = Join-Path $env:TEMP "vpn-client-e2e.log"
$clientErr = Join-Path $env:TEMP "vpn-client-e2e-err.log"
Remove-Item $clientLog, $clientErr -ErrorAction SilentlyContinue

$clientProc = Start-Process -FilePath $ClientBinary -ArgumentList $clientArgs `
  -NoNewWindow -PassThru -RedirectStandardOutput $clientLog -RedirectStandardError $clientErr

# Wait for ports to be ready
$deadline = (Get-Date).AddSeconds(15)
$portsReady = $false
while ((Get-Date) -lt $deadline) {
  if ($clientProc.HasExited) {
    throw "Go client exited early (code $($clientProc.ExitCode)):`n$(Get-Content $clientErr -ErrorAction SilentlyContinue)"
  }
  $socksUp = $false; $httpUp = $false
  $socksUp = Test-NetConnection -ComputerName 127.0.0.1 -Port $ListenPort -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Select-Object -ExpandProperty TcpTestSucceeded
  if ($HttpPort -gt 0) {
    $httpUp = Test-NetConnection -ComputerName 127.0.0.1 -Port $HttpPort -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Select-Object -ExpandProperty TcpTestSucceeded
  } else {
    $httpUp = $true
  }
  if ($socksUp -and $httpUp) { $portsReady = $true; break }
  Start-Sleep -Milliseconds 500
}
if (-not $portsReady) { throw "Client ports not ready in 15s" }

$clientErrText = Get-Content $clientErr -ErrorAction SilentlyContinue | Select-Object -Last 3
Write-Host "  PID: $($clientProc.Id)"
Write-Host "  $clientErrText"
Write-Pass "Go client ready (SOCKS5 :$ListenPort, HTTP :$HttpPort)"

# ── Step 5: Run throughput tests ─────────────────────────
if (-not $SkipTests) {
  # 5a: baidu.com (HTTP reachability check)
  Write-Step "S05a: baidu.com (reachability)"
  $r = curl.exe --proxy socks5h://longeek:Mengql123@127.0.0.1:$ListenPort -s -o NUL `
    -w "HTTP %{http_code} | %{time_total}s | %{speed_download}B/s" `
    --connect-timeout 10 --max-time 15 https://www.baidu.com 2>&1
  if ($LASTEXITCODE -eq 0) { Write-Pass "baidu.com: $r" } else { Write-Fail "baidu.com: $r" }

  # 5b: youtube.com SOCKS5 (throughput)
  Write-Step "S05b: youtube.com SOCKS5 (throughput, ${TestDuration}s max)"
  $r1 = curl.exe --proxy socks5h://longeek:Mengql123@127.0.0.1:$ListenPort -s -o NUL `
    -w "HTTP %{http_code} | %{size_download}B down | %{speed_download}B/s (%.2f KB/s) | TTFB %{time_starttransfer}s | %{time_total}s" `
    --connect-timeout 10 --max-time $TestDuration https://www.youtube.com 2>&1
  if ($LASTEXITCODE -eq 0) { Write-Pass "youtube SOCKS5: $r1" } else { Write-Fail "youtube SOCKS5: $r1" }

  # 5c: youtube.com HTTP CONNECT (if enabled)
  if ($HttpPort -gt 0) {
    Write-Step "S05c: youtube.com HTTP CONNECT (${TestDuration}s max)"
    $r2 = curl.exe -x http://longeek:Mengql123@127.0.0.1:$HttpPort -s -o NUL `
      -w "HTTP %{http_code} | %{size_download}B down | %{speed_download}B/s (%.2f KB/s) | TTFB %{time_starttransfer}s | %{time_total}s" `
      --connect-timeout 10 --max-time $TestDuration https://www.youtube.com 2>&1
    if ($LASTEXITCODE -eq 0) { Write-Pass "youtube HTTP: $r2" } else { Write-Fail "youtube HTTP: $r2" }
  }

  # 5d: google.com (reachability)
  Write-Step "S05d: google.com SOCKS5"
  $r3 = curl.exe --proxy socks5h://longeek:Mengql123@127.0.0.1:$ListenPort -s -o NUL `
    -w "HTTP %{http_code} | %{time_total}s | %{speed_download}B/s" `
    --connect-timeout 10 --max-time 15 https://www.google.com 2>&1
  if ($LASTEXITCODE -eq 0) { Write-Pass "google.com: $r3" } else { Write-Fail "google.com: $r3" }
} else {
  Write-Skip "S05: Throughput tests (-SkipTests)"
}

# ── Step 6: Collect server-side stats ────────────────────
Write-Step "S06: Server-side session stats (last 10)"
try {
  $sshTarget = "${SshUser}@${RemoteHost}"
  $sshResult = ssh -o ConnectTimeout=10 -o BatchMode=yes -o StrictHostKeyChecking=accept-new $sshTarget `
    "sudo journalctl -u vpn-proxy -n 50 --no-pager 2>/dev/null | grep 'session closed' | tail -10"
  if ($sshResult) {
    Write-Host $sshResult
    # Parse and summarize throughput
    $downSizes = @()
    $sshResult -split "`n" | ForEach-Object {
      if ($_ -match 'up=(\d+) bytes, down=(\d+) bytes') {
        $downSizes += [int]$Matches[2]
      }
    }
    if ($downSizes.Count -gt 0) {
      $avgDown = [math]::Round(($downSizes | Measure-Object -Average).Average / 1KB, 1)
      $totalMb = [math]::Round(($downSizes | Measure-Object -Sum).Sum / 1MB, 1)
      Write-Pass "Avg ${avgDown} KB/session, total ${totalMb} MB across $($downSizes.Count) sessions"
    }
  } else {
    Write-Host "(no sessions found or SSH unavailable)"
  }
} catch {
  Write-Host "[WARN] SSH stats unavailable: $_"
}

# ── Cleanup ──────────────────────────────────────────────
if (-not $clientProc.HasExited) {
  Write-Step "S07: Cleanup — stop Go client"
  Stop-Process -Id $clientProc.Id -Force -ErrorAction SilentlyContinue
  Write-Pass "Client PID $($clientProc.Id) stopped"
}

Write-Step "DONE"
Write-Host "E2E test complete." -ForegroundColor Cyan
