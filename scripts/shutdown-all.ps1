param(
    [switch]$Force,
    [switch]$StopPostgres
)

$ErrorActionPreference = 'SilentlyContinue'
$ports = @(8000, 8001, 8101, 8102, 8103, 6380, 6379)

function Get-Listeners {
    $rows = netstat -ano | Select-String 'LISTENING'
    foreach ($row in $rows) {
        $cols = ($row.Line -split '\s+') | Where-Object { $_ }
        if ($cols.Count -lt 5) { continue }
        $local = $cols[1]
        $processId = [int]$cols[-1]
        foreach ($port in $ports) {
            if ($local -match ":$port$") {
                [pscustomobject]@{ Port = $port; Address = $local; ProcessId = $processId }
            }
        }
    }
}

$targets = Get-Listeners | Sort-Object ProcessId -Unique

Write-Host '== project listeners =='
if (-not $targets) {
    Write-Host '(none)'
}
else {
    foreach ($t in $targets) {
        $p = Get-Process -Id $t.ProcessId -ErrorAction SilentlyContinue
        $name = 'unknown'
        if ($p) { $name = $p.ProcessName }
        Write-Host ("port={0,-6} pid={1,-7} {2}" -f $t.Port, $t.ProcessId, $name)
    }
}

if (-not $Force) {
    Write-Host ''
    Write-Host 'preview only: add -Force to actually stop them.'
    return
}

foreach ($t in $targets) {
    try {
        Stop-Process -Id $t.ProcessId -Force -ErrorAction Stop
        Write-Host ("stopped port={0} pid={1}" -f $t.Port, $t.ProcessId)
    }
    catch {
        Write-Host ("failed  port={0} pid={1}: {2}" -f $t.Port, $t.ProcessId, $_.Exception.Message)
    }
}

if ($StopPostgres) {
    $pg = Join-Path $PSScriptRoot 'postgres.cmd'
    if (Test-Path $pg) {
        & $pg stop
        Write-Host 'postgres stopped'
    }
}

Write-Host 'done.'
