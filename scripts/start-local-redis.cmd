@echo off
setlocal EnableExtensions
rem Native Windows launcher: does not change PowerShell execution policy.
for %%I in ("%~dp0..") do set "VULNARENA_ROOT=%%~fI"
set "VULNARENA_REDIS_SERVER="
for /d %%D in ("%VULNARENA_ROOT%\.tools\redis\*") do if exist "%%~fD\redis-server.exe" set "VULNARENA_REDIS_SERVER=%%~fD\redis-server.exe"
if not defined VULNARENA_REDIS_SERVER (
    echo Portable Redis was not found under .tools\redis.
    exit /b 1
)
if /i "%~1"=="--check" (
    echo Redis executable found. Bind: 127.0.0.1:6380. Data: data\redis.
    exit /b 0
)
for %%I in ("%VULNARENA_REDIS_SERVER%") do set "VULNARENA_REDIS_CLI=%%~dpIredis-cli.exe"
if exist "%VULNARENA_REDIS_CLI%" (
    "%VULNARENA_REDIS_CLI%" -h 127.0.0.1 -p 6380 -e ping >nul 2>&1
    if not errorlevel 1 (
        echo Redis is already running on 127.0.0.1:6380. No duplicate process started.
        exit /b 0
    )
)
if not exist "%VULNARENA_ROOT%\data\redis" mkdir "%VULNARENA_ROOT%\data\redis"
if not exist "%VULNARENA_ROOT%\data\redis" exit /b 1
pushd "%VULNARENA_ROOT%\data\redis"
if errorlevel 1 exit /b 1
echo Redis runs in this terminal on 127.0.0.1:6380. Press Ctrl+C to stop.
echo Logs and AOF are stored in data\redis. No reboot or system service changes.
"%VULNARENA_REDIS_SERVER%" --bind 127.0.0.1 --port 6380 --protected-mode yes --appendonly yes --dir . --logfile redis.log
set "VULNARENA_REDIS_EXIT=%errorlevel%"
popd
exit /b %VULNARENA_REDIS_EXIT%
