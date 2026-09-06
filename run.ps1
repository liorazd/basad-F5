# Start backend and frontend in two separate PowerShell windows.
#
# Usage:
#   PS> .\run.ps1            # dev mode (vite dev server on :8080, tornado on :8889)
#   PS> .\run.ps1 -Build     # build frontend/dist/, then run the backend
#
# NOTE: -Build compiles the frontend but Tornado does NOT serve dist/ -- the
# backend registers API routes only, no static-file handler. Serve dist/ with a
# real web server and proxy the API paths to :8889.

param(
    [switch]$Build
)

$ErrorActionPreference = 'Stop'
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptRoot

# Load .env into the current process so child windows inherit it
$envFile = Join-Path $ScriptRoot '.env'
if (Test-Path $envFile) {
    Write-Host "Loading $envFile" -ForegroundColor Cyan
    Get-Content $envFile | ForEach-Object {
        if ($_ -match '^\s*#') { return }
        if ($_ -match '^\s*$') { return }
        if ($_ -match '^\s*([^=]+)=(.*)$') {
            $name = $matches[1].Trim()
            $value = $matches[2].Trim().Trim('"').Trim("'")
            [Environment]::SetEnvironmentVariable($name, $value, 'Process')
        }
    }
} else {
    Write-Warning ".env not found. Copy .env.example to .env, configure F5_ENVIRONMENTS_FILE or legacy F5_* vars, and add FERNET_KEY (or FERNET_KEY_FILE) to enable the read-only cache pre-warm + cert-replace API."
}

$envConfigPath = [Environment]::GetEnvironmentVariable('F5_ENVIRONMENTS_FILE', 'Process')
if ([string]::IsNullOrWhiteSpace($envConfigPath)) {
    $envConfigPath = 'f5_environments.json'
}
if (-not [System.IO.Path]::IsPathRooted($envConfigPath)) {
    $envConfigPath = Join-Path $ScriptRoot $envConfigPath
}

$hasEnvironmentFile = Test-Path $envConfigPath
$hasLegacyPair = -not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable('F5_DMZ_URL', 'Process')) -and `
                 -not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable('F5_LAN_URL', 'Process'))

if (-not $hasEnvironmentFile -and -not $hasLegacyPair) {
    Write-Error "No F5 environment configuration found. Create $envConfigPath with scripts\configure_environments.py or set legacy F5_DMZ_URL/F5_LAN_URL values in $envFile."
    exit 1
}

$portal = Join-Path $ScriptRoot 'frontend'

if ($Build) {
    Write-Host "Building frontend for production..." -ForegroundColor Cyan
    Push-Location $portal
    npm run build
    Pop-Location
    Write-Host "Build complete. Starting backend..." -ForegroundColor Green
    python "$ScriptRoot\app.py"
    exit 0
}

Write-Host "Starting Tornado backend in a new window (port 8889)..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$ScriptRoot'; python app.py"

Start-Sleep -Seconds 2

Write-Host "Starting Vite frontend in a new window (port 8080)..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$portal'; npm run dev"

Write-Host ""
Write-Host "Both processes launched in separate windows." -ForegroundColor Green
Write-Host "Frontend:  http://localhost:8080"
Write-Host "Backend:   http://localhost:8889"
