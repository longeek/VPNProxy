#Requires -Version 5.1
<#
.SYNOPSIS
  Copy server.py to a Linux host and restart vpn-proxy (requires SSH key or agent).

.PARAMETER RemoteHost
  Default 47.88.49.28

.PARAMETER SshUser
  SSH user for key-based login (default admin). Remote steps use sudo.

.PARAMETER RemoteInstallPath
  Directory on server containing server.py (default /opt/vpn-proxy)

.EXAMPLE
  # Passwordless: ssh admin@47.88.49.28 must work (e.g. ssh-copy-id).
  .\scripts\deploy_server_remote.ps1

.EXAMPLE
  .\scripts\deploy_server_remote.ps1 -SshUser admin -RemoteHost 47.88.49.28
#>
param(
  [string]$RemoteHost = "47.88.49.28",
  [string]$SshUser = "admin",
  [string]$RemoteInstallPath = "/opt/vpn-proxy",
  [string]$ProjectRoot = ""
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ProjectRoot) {
  $ProjectRoot = (Resolve-Path (Join-Path $ScriptDir "..")).Path
}

$serverPy = Join-Path $ProjectRoot "server.py"
if (-not (Test-Path $serverPy)) {
  throw "server.py not found: $serverPy"
}

$target = "${SshUser}@${RemoteHost}"
$tmpRemote = "/tmp/vpn-proxy-server-$([Guid]::NewGuid().ToString('N')).py"

Write-Host "Uploading server.py -> ${target}:${tmpRemote}" -ForegroundColor Cyan
& scp.exe -o BatchMode=yes -o ConnectTimeout=20 -o StrictHostKeyChecking=accept-new $serverPy "${target}:${tmpRemote}"
if ($LASTEXITCODE -ne 0) {
  throw "scp failed (exit $LASTEXITCODE). Configure SSH key: ssh $target"
}

$installPath = "${RemoteInstallPath}/server.py"
$remoteCmd = "sudo install -m 644 $tmpRemote $installPath && rm -f $tmpRemote && sudo systemctl restart vpn-proxy && systemctl is-active vpn-proxy; ss -lntp 2>/dev/null | grep -E ':8443\\b' || true"

Write-Host "Installing and restarting vpn-proxy..." -ForegroundColor Cyan
& ssh.exe -o BatchMode=yes -o ConnectTimeout=20 $target $remoteCmd
if ($LASTEXITCODE -ne 0) {
  throw "ssh remote install failed (exit $LASTEXITCODE)"
}

Write-Host "Done." -ForegroundColor Green
