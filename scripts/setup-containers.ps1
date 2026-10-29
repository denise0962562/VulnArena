# Run only when container features are already active. Never reboots Windows or stops processes.
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$featureResult = Join-Path $projectRoot 'verification\windows-features.json'
if (Test-Path -LiteralPath $featureResult) {
    $snapshot = Get-Content -LiteralPath $featureResult -Raw | ConvertFrom-Json
    if (-not $snapshot.Success) { throw 'Windows feature setup failed. Inspect verification\windows-features.json first.' }
    $pendingActivation = $false
    if ($snapshot.RestartNeeded) {
        $lastBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime()
        $configuredAt = (Get-Item -LiteralPath $featureResult).LastWriteTimeUtc
        $pendingActivation = $lastBoot -lt $configuredAt
    }
    if ($pendingActivation -or @($snapshot.Features | Where-Object State -ne 'Enabled').Count) {
        throw 'Windows features are pending activation. Stopping without rebooting; do not run container installation yet.'
    }
}
# Do not pass --allow-reboot. Dependency setup is handled separately, never implicitly.
& wsl.exe --version
if ($LASTEXITCODE -ne 0) {
    winget install --id Microsoft.WSL --exact --source winget --silent --skip-dependencies --accept-source-agreements --accept-package-agreements --disable-interactivity
    if ($LASTEXITCODE -ne 0) { throw 'WSL installation did not succeed. Administrator authorization may be required; Docker installation was not started.' }
    & wsl.exe --version
    if ($LASTEXITCODE -ne 0) { throw 'WSL runtime is unavailable. Docker installation was not started.' }
}
$dockerCli = Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\resources\bin\docker.exe'
$existingDocker = Get-Command docker.exe -ErrorAction SilentlyContinue
if ($existingDocker) { $dockerCli = $existingDocker.Source }
if (-not (Test-Path -LiteralPath $dockerCli)) {
    winget install --id Docker.DockerDesktop --exact --source winget --silent --skip-dependencies --accept-source-agreements --accept-package-agreements --disable-interactivity --override 'install --user --quiet --accept-license --backend=wsl-2'
    if ($LASTEXITCODE -ne 0) { throw 'Docker Desktop installation failed. Check its installer log.' }
}
& $dockerCli --version
if ($LASTEXITCODE -ne 0) { throw 'Docker CLI validation failed.' }
& $dockerCli compose version
if ($LASTEXITCODE -ne 0) { throw 'Docker Compose validation failed.' }
& $dockerCli compose -f (Join-Path $projectRoot 'compose.yaml') config --quiet
if ($LASTEXITCODE -ne 0) { throw 'Compose configuration validation failed.' }
Write-Output 'Docker and Compose are installed. This script never starts the engine, stops remote-access services, or reboots Windows.'
