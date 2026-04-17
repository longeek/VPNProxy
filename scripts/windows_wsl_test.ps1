param(
  [string]$Distro = "Ubuntu",
  [switch]$InstallDeps
)

$ErrorActionPreference = "Stop"

function Test-CommandExists {
  param([string]$Name)
  return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

if (-not (Test-CommandExists "wsl.exe")) {
  Write-Error "WSL is not installed. Run: wsl --install"
}

try {
  $wslList = wsl.exe --list --quiet 2>$null
} catch {
  Write-Error "Failed to query WSL distributions. Ensure WSL is enabled."
}

if (-not $wslList) {
  Write-Error "No WSL distro found. Install one first, e.g.: wsl --install -d Ubuntu"
}

$hasDistro = $false
foreach ($line in $wslList) {
  if ($line.Trim() -eq $Distro) {
    $hasDistro = $true
    break
  }
}

if (-not $hasDistro) {
  Write-Error "WSL distro '$Distro' not found. Installed: $($wslList -join ', ')"
}

$winPath = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$drive = $winPath.Substring(0, 1).ToLowerInvariant()
$pathNoDrive = $winPath.Substring(2) -replace "\\", "/"
$wslPath = "/mnt/$drive$pathNoDrive"

$bashParts = @(
  "set -euo pipefail",
  "cd '$wslPath'"
)

if ($InstallDeps) {
  $bashParts += "if command -v apt-get >/dev/null 2>&1; then sudo apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y python3 bash tar grep coreutils; fi"
}

$bashParts += "chmod +x scripts/*.sh"
$bashParts += "find scripts -name '*.sh' -exec sed -i 's/\r//g' {} +"
$bashParts += "bash scripts/linux_ci_smoke.sh"

$bashScript = $bashParts -join "; "

Write-Host "[INFO] Running Linux smoke/integration tests in WSL distro: $Distro"
& wsl.exe -d $Distro -- bash -lc "$bashScript"
if ($LASTEXITCODE -ne 0) {
  throw "WSL test execution failed with exit code $LASTEXITCODE"
}
Write-Host "[INFO] WSL smoke/integration tests completed"
