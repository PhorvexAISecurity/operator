# Phorvex Console — ONE-COMMAND start.
# Builds the data backend + the dashboard if needed, then runs the single binary that
# serves BOTH the web app and the API on one port (http://localhost:8090).
#
#   powershell -ExecutionPolicy Bypass -File .\start-dashboard.ps1
#
$ErrorActionPreference = "Stop"
$Root   = $PSScriptRoot
$Phorvex = Join-Path $Root "phorvex"
$Web    = Join-Path $Root "dashboard-web"
$Bin    = Join-Path $Phorvex "bin\phorvex-console.exe"
$Port   = if ($env:PHORVEX_PORT) { $env:PHORVEX_PORT } else { "8090" }

Write-Host "Phorvex Console — starting..." -ForegroundColor Cyan

# 1. backend binary
if (-not (Test-Path $Bin)) {
  Write-Host "  building data backend..." -ForegroundColor DarkGray
  Push-Location $Phorvex; go build -o bin/phorvex-console.exe ./cmd/console; Pop-Location
}

# 2. dashboard static build
if (-not (Test-Path (Join-Path $Web "out\index.html"))) {
  Write-Host "  building dashboard (first run, ~1 min)..." -ForegroundColor DarkGray
  Push-Location $Web
  if (-not (Test-Path "node_modules")) { npm install --no-audit --no-fund }
  npm run build
  Pop-Location
}

# 3. free the port if a stale instance holds it
Get-Process phorvex-console -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# 4. run the single binary (serves SPA + API) and open the browser
$url = "http://localhost:$Port"
Write-Host "  open $url" -ForegroundColor Green
Start-Process $url
& $Bin --root $Root --addr ":$Port"
