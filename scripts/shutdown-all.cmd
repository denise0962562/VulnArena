@echo off
rem Shutdown every process this project started (ports 8000/8001/81xx + redis).
rem   scripts\shutdown-all.cmd                     preview
rem   scripts\shutdown-all.cmd -Force              kill them
rem   scripts\shutdown-all.cmd -Force -StopPostgres also stop PostgreSQL
setlocal EnableExtensions
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0shutdown-all.ps1" %*
exit /b %errorlevel%
