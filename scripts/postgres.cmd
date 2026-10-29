@echo off
setlocal EnableExtensions
for %%I in ("%~dp0..") do set "VULNARENA_ROOT=%%~fI"
"%VULNARENA_ROOT%\.venv\Scripts\python.exe" "%VULNARENA_ROOT%\scripts\local_postgres.py" %*
exit /b %errorlevel%
