# Run in an Administrator PowerShell. Does not restart the machine.
$ErrorActionPreference = 'Stop'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) {
    throw 'Administrator PowerShell is required to enable Windows optional features.'
}
$projectRoot = Split-Path -Parent $PSScriptRoot
$logPath = Join-Path $projectRoot 'verification\windows-features.log'
$resultPath = Join-Path $projectRoot 'verification\windows-features.json'
New-Item -ItemType Directory -Force (Split-Path -Parent $logPath) | Out-Null
Start-Transcript -Path $logPath -Append
try {
    $restartNeeded = $false
    $featureNames = @('Microsoft-Windows-Subsystem-Linux', 'VirtualMachinePlatform')
    foreach ($featureName in $featureNames) {
        $before = Get-WindowsOptionalFeature -Online -FeatureName $featureName
        Write-Output ($featureName + ' before: ' + $before.State)
        if ($before.State -eq 'EnablePending') {
            $restartNeeded = $true
        } elseif ($before.State -ne 'Enabled') {
            $result = Enable-WindowsOptionalFeature -Online -FeatureName $featureName -All -NoRestart
            $restartNeeded = $restartNeeded -or $result.RestartNeeded
        }
    }
    $states = @(foreach ($featureName in $featureNames) {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $featureName
        [pscustomobject]@{ Name = $featureName; State = [string]$feature.State }
    })
    [pscustomobject]@{ Success = $true; RestartNeeded = $restartNeeded; Features = $states } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $resultPath -Encoding UTF8
    Write-Output 'Feature configuration finished. This script never restarts Windows. A pending restart is left for the user.'
} catch {
    [pscustomobject]@{ Success = $false; Error = $_.Exception.Message } | ConvertTo-Json | Set-Content -LiteralPath $resultPath -Encoding UTF8
    throw
} finally {
    Stop-Transcript
}
