param(
  [string]$ProjectRoot = "",
  [string]$PythonExe = "",
  [Parameter(Mandatory = $false)]
  [string]$Token = $env:VPN_PROXY_TOKEN,
  [string]$Server = "47.88.49.28",
  [int]$ServerPort = 8443,
  [string]$Listen = "127.0.0.1",
  [int]$ListenPort = 1080,
  # HTTP CONNECT proxy; set 0 to omit --http-port (do not listen).
  [int]$HttpPort = 8080,
  # TCP line proxy (first line host:port, then OK + raw stream); set 0 to omit.
  [int]$TcpLinePort = 1081,
  [string]$CaCertRelative = "certs\server.crt",
  [string]$DesktopPath = "",
  [string]$LinkName = "VPNProxy Client.lnk"
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ProjectRoot) {
  $ProjectRoot = (Resolve-Path (Join-Path $ScriptDir "..")).Path
}

if (-not $PythonExe) {
  $pyCmd = Get-Command python -ErrorAction SilentlyContinue
  if (-not $pyCmd) {
    Write-Error "python not found in PATH; pass -PythonExe"
  }
  $PythonExe = $pyCmd.Source
}

if (-not $Token) {
  Write-Error "Missing token: set VPN_PROXY_TOKEN or pass -Token"
}

if (-not $DesktopPath) {
  $DesktopPath = [Environment]::GetFolderPath("Desktop")
}

$linkPath = Join-Path $DesktopPath $LinkName
$arguments = "-u client.py --listen $Listen --listen-port $ListenPort --server $Server --server-port $ServerPort --token $Token --ca-cert $CaCertRelative"
if ($HttpPort -gt 0) {
  $arguments += " --http-port $HttpPort"
}
if ($TcpLinePort -gt 0) {
  $arguments += " --tcp-line-port $TcpLinePort"
}

$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($linkPath)
$shortcut.TargetPath = $PythonExe
$shortcut.Arguments = $arguments
$shortcut.WorkingDirectory = $ProjectRoot
$shortcut.WindowStyle = 1
# UDP uses SOCKS5 UDP ASSOCIATE on the same --listen-port (no extra CLI flag).
$shortcutDescription = "VPNProxy client; SOCKS5+UDP ${Listen}:${ListenPort} (UDP ASSOCIATE)"
if ($HttpPort -gt 0) {
  $shortcutDescription += "; HTTP CONNECT ${Listen}:${HttpPort}"
}
if ($TcpLinePort -gt 0) {
  $shortcutDescription += "; TCP line ${Listen}:${TcpLinePort}"
}
$shortcut.Description = $shortcutDescription
$shortcut.IconLocation = "$PythonExe,0"
$shortcut.Save()

Write-Host "Created: $linkPath"
