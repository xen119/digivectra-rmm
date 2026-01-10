param(
    [string]$ServiceName = "RMM.Agent",
    [string]$DisplayName = "RMM Remote Agent",
    [string]$Description = "RMM agent that streams shell/screen and services the server via WebSocket.",
    [string]$AgentPath = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)\bin\Debug\net8.0-windows\Agent.exe"
)

function Write-Info($message) {
    Write-Host "[INFO] $message"
}

function Write-ErrorAndExit($message) {
    Write-Host "[ERROR] $message" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path -Path $AgentPath)) {
    Write-ErrorAndExit "Agent binary not found at '$AgentPath'. Publish the agent first (e.g. `dotnet publish -c Release`)."
}

Write-Info "Preparing to install service '$ServiceName' pointing at '$AgentPath'."

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Info "Service already exists. Stopping and deleting..."
    try {
        if ($existing.Status -ne 'Stopped') {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        }
    } catch {
        Write-Warning "Failed to stop service: $_"
    }
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

$binPath = "`"$AgentPath`""
Write-Info "Creating service..."
$createResult = & sc.exe create $ServiceName binPath= $binPath DisplayName= `"$DisplayName`" start= auto 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-ErrorAndExit "Failed to create service: $createResult"
}

Write-Info "Setting description..."
sc.exe description $ServiceName "$Description" | Out-Null

Write-Info "Starting service..."
Start-Service -Name $ServiceName

Write-Info "Service '$ServiceName' installed and started successfully."
