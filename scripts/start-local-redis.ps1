# Uses the checksum-verified portable community Windows build installed under .tools/redis.
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$server = Get-ChildItem -LiteralPath (Join-Path $projectRoot '.tools\redis') -Recurse -Filter redis-server.exe | Select-Object -First 1
if (-not $server) { throw 'Portable Redis is absent; use Docker or install a Redis service.' }
$redisData = Join-Path $projectRoot 'data\redis'
New-Item -ItemType Directory -Force -Path $redisData | Out-Null
$env:VULNARENA_REDIS_URL = 'redis://127.0.0.1:6380/0'
Write-Output 'Redis runs in this terminal on 127.0.0.1:6380. Logs and AOF: data\redis. Ctrl+C stops it.'
Push-Location -LiteralPath $redisData
try {
    & $server.FullName --bind 127.0.0.1 --port 6380 --protected-mode yes --appendonly yes --dir . --logfile redis.log
} finally {
    Pop-Location
}
