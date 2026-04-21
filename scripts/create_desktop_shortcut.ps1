param(
  [string]$ProjectRoot = "",
  [string]$PythonExe = "",
  [Parameter(Mandatory = $false)]
  [string]$Token = $env:VPN_PROXY_TOKEN,
  [string]$Server = "47.88.49.28",
  [int]$ServerPort = 8443,
  [string]$Listen = "127.0.0.1",
  [int]$ListenPort = 1080,
  [int]$HttpPort = 8080,
  [int]$TcpLinePort = 0,
  [string]$CaCertRelative = "",
  [switch]$Insecure = $false,
  [int]$PoolSize = 2,
  [double]$PoolTtl = 8.0,
  [string]$DesktopPath = "",
  [string]$LinkName = "VPNProxy Client.lnk"
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ProjectRoot) {
  $ProjectRoot = (Resolve-Path (Join-Path $ScriptDir "..")).Path
}

if (-not $PythonExe) {
  $candidates = @(
    Join-Path $env:LOCALAPPDATA "Programs\Python\Python311\python.exe"
    Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\python.exe"
    Join-Path $env:LOCALAPPDATA "Programs\Python\Python313\python.exe"
  )
  foreach ($c in $candidates) {
    if (Test-Path $c) {
      $PythonExe = $c
      break
    }
  }
  if (-not $PythonExe) {
    $allPythons = Get-Command python -ErrorAction SilentlyContinue | Where-Object {
      $_.Source -notmatch "venv|virtualenv|\\.venv"
    }
    if ($allPythons) {
      $PythonExe = ($allPythons | Select-Object -First 1).Source
    }
  }
  if (-not $PythonExe) {
    $fallback = Get-Command python -ErrorAction SilentlyContinue
    if ($fallback) {
      $PythonExe = $fallback.Source
    } else {
      Write-Error "python not found in PATH; pass -PythonExe"
    }
  }
}

if (-not (Test-Path $PythonExe)) {
  Write-Error "Python not found at: $PythonExe"
}

if (-not $Token) {
  Write-Error "Missing token: set VPN_PROXY_TOKEN or pass -Token"
}

if (-not $DesktopPath) {
  $DesktopPath = [Environment]::GetFolderPath("Desktop")
}

$pyArgs = "-u `"$ProjectRoot\client.py`" --listen $Listen --listen-port $ListenPort --server $Server --server-port $ServerPort --token $Token"
if ($Insecure) {
  $pyArgs += " --insecure"
} elseif ($CaCertRelative) {
  $pyArgs += " --ca-cert `"$CaCertRelative`""
}
if ($HttpPort -gt 0) {
  $pyArgs += " --http-port $HttpPort"
}
if ($TcpLinePort -gt 0) {
  $pyArgs += " --tcp-line-port $TcpLinePort"
}
if ($PoolSize -gt 0) {
  $pyArgs += " --pool-size $PoolSize --pool-ttl $PoolTtl"
}

$batchContent = "@echo off`r`n"
$batchContent += "title VPNProxy Client`r`n"
$batchContent += "cd /d `"$ProjectRoot`"`r`n"
$batchContent += "`"$PythonExe`" $pyArgs`r`n"
$batchContent += "if errorlevel 1 (`r`n"
$batchContent += "  echo.`r`n"
$batchContent += "  echo VPNProxy exited with error. Press any key to close...`r`n"
$batchContent += "  pause >nul`r`n"
$batchContent += ")`r`n"

$batchPath = Join-Path $ProjectRoot "start_vpn_proxy.cmd"
[System.IO.File]::WriteAllText($batchPath, $batchContent, [System.Text.Encoding]::Default)

$linkPath = Join-Path $DesktopPath $LinkName
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($linkPath)
$shortcut.TargetPath = "cmd.exe"
$shortcut.Arguments = "/k `"$batchPath`""
$shortcut.WorkingDirectory = $ProjectRoot
$shortcut.WindowStyle = 1
$shortcutDescription = "VPNProxy client; SOCKS5+UDP ${Listen}:${ListenPort}"
if ($HttpPort -gt 0) {
  $shortcutDescription += "; HTTP CONNECT ${Listen}:${HttpPort}"
}
if ($TcpLinePort -gt 0) {
  $shortcutDescription += "; TCP line ${Listen}:${TcpLinePort}"
}
if ($PoolSize -gt 0) {
  $shortcutDescription += " [pool=$PoolSize]"
}
$shortcut.Description = $shortcutDescription
$shortcut.Save()

Write-Host "Created shortcut: $linkPath"
Write-Host "Created launcher: $batchPath"
Write-Host "  Python: $PythonExe"
Write-Host "  SOCKS5: ${Listen}:${ListenPort}"
if ($HttpPort -gt 0) { Write-Host "  HTTP:   ${Listen}:${HttpPort}" }