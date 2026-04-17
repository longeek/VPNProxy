#Requires -Version 5.1
<#
.SYNOPSIS
  One-command: deploy VPNProxy server.py to a remote host and run end-to-end verification.

.DESCRIPTION
  Sequence:
    1) Deploy server.py to remote via SSH (admin by default) and restart vpn-proxy
    2) Fetch /etc/vpn-proxy/server.crt into certs/server.crt
    3) Start local client.py (SOCKS5 + optional HTTP CONNECT + optional TCP line)
    4) Run integration + system smoke checks (SOCKS5/HTTP/TCP/UDP)

  Requirements:
    - Passwordless SSH login must work: ssh <user>@<host>
    - Remote user must be able to run required sudo commands non-interactively
    - Local machine must have: python, curl.exe, ssh.exe, scp.exe on PATH
    - VPN proxy token must be provided via -Token or $env:VPN_PROXY_TOKEN

.PARAMETER RemoteHost
  VPNProxy server address (default 47.88.49.28)

.PARAMETER SshUser
  SSH user (default admin)

.PARAMETER Token
  VPN proxy token (defaults to $env:VPN_PROXY_TOKEN)

.PARAMETER RemotePort
  Server listen port (default 8443)

.PARAMETER Listen
  Local listen IP (default 127.0.0.1)

.PARAMETER ListenPort
  Local SOCKS5 port (default 1080)

.PARAMETER HttpPort
  Local HTTP CONNECT port (default 8080). Use 0 to disable.

.PARAMETER TcpLinePort
  Local TCP line port (default 1081). Use 0 to disable.

.PARAMETER SkipDeploy
  Skip remote deployment; only run verification against existing server.

.PARAMETER SkipFetchCert
  Skip fetching server.crt via scp; use existing local cert file.

.EXAMPLE
  $env:VPN_PROXY_TOKEN = '...'
  .\scripts\deploy_and_verify_remote.ps1

.EXAMPLE
  .\scripts\deploy_and_verify_remote.ps1 -RemoteHost 47.88.49.28 -SshUser admin -Token '...'
#>
param(
  [string]$RemoteHost = "47.88.49.28",
  [string]$SshUser = "admin",
  [string]$Token = $env:VPN_PROXY_TOKEN,
  [int]$RemotePort = 8443,
  [string]$Listen = "127.0.0.1",
  [int]$ListenPort = 1080,
  [int]$HttpPort = 8080,
  [int]$TcpLinePort = 1081,
  [switch]$SkipDeploy,
  [switch]$SkipFetchCert,
  [string]$ProjectRoot = ""
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ProjectRoot) {
  $ProjectRoot = (Resolve-Path (Join-Path $ScriptDir "..")).Path
}
Set-Location $ProjectRoot

if (-not $Token) {
  throw "Missing token: pass -Token or set VPN_PROXY_TOKEN"
}

$deployScript = Join-Path $ProjectRoot "scripts\deploy_server_remote.ps1"
$itestScript = Join-Path $ProjectRoot "scripts\integration_e2e_remote.ps1"

if (-not (Test-Path $deployScript)) { throw "Missing: $deployScript" }
if (-not (Test-Path $itestScript)) { throw "Missing: $itestScript" }

Write-Host "" ; Write-Host "=== A01: Preconditions ===" -ForegroundColor Cyan
Write-Host ("Remote: {0}@{1}:{2}" -f $SshUser, $RemoteHost, $RemotePort) -ForegroundColor Gray
Write-Host ("Local:  SOCKS5 {0}:{1}, HTTP {2}, TCP line {3}" -f $Listen, $ListenPort, $HttpPort, $TcpLinePort) -ForegroundColor Gray

if (-not $SkipDeploy) {
  Write-Host "" ; Write-Host "=== A02: Deploy server.py and restart service ===" -ForegroundColor Cyan
  & powershell -NoProfile -ExecutionPolicy Bypass -File $deployScript `
    -RemoteHost $RemoteHost `
    -SshUser $SshUser
  if ($LASTEXITCODE -ne 0) { throw "Deploy step failed (exit $LASTEXITCODE)" }
} else {
  Write-Host "" ; Write-Host "=== A02: Deploy skipped (-SkipDeploy) ===" -ForegroundColor DarkGray
}

$fetchCert = $true
if ($SkipFetchCert) { $fetchCert = $false }

Write-Host "" ; Write-Host "=== A03: Verify (integration + system tests) ===" -ForegroundColor Cyan
$env:VPN_PROXY_TOKEN = $Token

$args = @(
  "-NoProfile",
  "-ExecutionPolicy", "Bypass",
  "-File", $itestScript,
  "-RemoteHost", $RemoteHost,
  "-RemotePort", "$RemotePort",
  "-Listen", $Listen,
  "-ListenPort", "$ListenPort",
  "-HttpPort", "$HttpPort",
  "-TcpLinePort", "$TcpLinePort",
  "-SshUser", $SshUser
)

if ($fetchCert) {
  $args += "-FetchCert"
} else {
  $args += "-SkipSsh"
}

& powershell @args
if ($LASTEXITCODE -ne 0) { throw "Verification step failed (exit $LASTEXITCODE)" }

Write-Host "" ; Write-Host "[DONE] Deploy + verify completed successfully." -ForegroundColor Green

