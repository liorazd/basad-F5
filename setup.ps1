# F5 VIP Portal — first-time setup (Windows / PowerShell).
#
# 1. Installs Python deps from requirements.txt
# 2. Installs frontend deps under frontend\
# 3. Hands off to scripts\install.py for the interactive .env + F5 wizard
#
# Re-running is safe: install.py keeps your existing answers.
#
# Usage:
#   PS> .\setup.ps1

$ErrorActionPreference = 'Stop'
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptRoot

function Need-Cmd($name) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        Write-Error "$name is not on PATH. Install it and re-run."
        exit 1
    }
}

Write-Host "=== Checking prerequisites ===" -ForegroundColor Cyan
Need-Cmd python
Need-Cmd npm
python --version
node --version
npm --version

Write-Host ""
Write-Host "=== Installing Python dependencies ===" -ForegroundColor Cyan
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

Write-Host ""
Write-Host "=== Installing npm dependencies ===" -ForegroundColor Cyan
$portal = Join-Path $ScriptRoot 'frontend'
if (-not (Test-Path $portal)) {
    Write-Error "Portal folder not found at $portal"
    exit 1
}
Push-Location $portal
try {
    if (Test-Path 'package-lock.json') {
        npm ci
    } else {
        npm install
    }
} catch {
    Write-Warning "npm install hit an error; retrying with --legacy-peer-deps"
    npm install --legacy-peer-deps
}
Pop-Location

Write-Host ""
Write-Host "=== Running interactive installer ===" -ForegroundColor Cyan
python "$ScriptRoot\scripts\install.py"
