param(
  [string]$ChromePath = "",
  [string]$ProxyServer = "socks5://127.0.0.1:1080",
  [switch]$DisableQuic = $true,
  [string]$DesktopPath = "",
  [string]$LinkName = "Chrome (VPN SOCKS5).lnk"
)

$ErrorActionPreference = "Stop"

if (-not $ChromePath) {
  $candidates = @(
    "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
  )
  foreach ($p in $candidates) {
    if (Test-Path -LiteralPath $p) {
      $ChromePath = $p
      break
    }
  }
  if (-not $ChromePath) {
    Write-Error "Chrome not found under Program Files; pass -ChromePath"
  }
}

if (-not (Test-Path -LiteralPath $ChromePath)) {
  Write-Error "Chrome not found: $ChromePath"
}

if (-not $DesktopPath) {
  $DesktopPath = [Environment]::GetFolderPath("Desktop")
}

$argList = @("--proxy-server=`"$ProxyServer`"")
if ($DisableQuic) {
  $argList += "--disable-quic"
}
$arguments = $argList -join " "

$linkPath = Join-Path $DesktopPath $LinkName
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($linkPath)
$shortcut.TargetPath = $ChromePath
$shortcut.Arguments = $arguments
$shortcut.WorkingDirectory = (Split-Path -Parent $ChromePath)
$shortcut.WindowStyle = 1
$shortcut.Description = "Chrome with SOCKS5 $ProxyServer (QUIC off)"
$shortcut.IconLocation = "$ChromePath,0"
$shortcut.Save()

Write-Host "Created: $linkPath"
