@echo off
REM ===================================================================
REM  MILNET SSO - Fleet Commander
REM  Double-click this file to discover your LAN, pick the machines that
REM  will become the 21-node MILNET SSO cluster, and deploy the whole
REM  quantum-safe stack to them automatically.
REM
REM  This launcher only:
REM    1. Requests Administrator rights (needed for LAN scan + WSL setup)
REM    2. Hands off to fleet-commander.ps1 with a safe execution policy
REM
REM  It changes nothing on its own.
REM ===================================================================

setlocal
title MILNET SSO - Fleet Commander

REM --- Elevate to Administrator if not already ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  MILNET Fleet Commander needs Administrator rights.
    echo  A UAC prompt will appear - choose "Yes".
    echo.
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b 0
)

REM --- Run the controller ---
set "PS1=%~dp0fleet-commander.ps1"
if not exist "%PS1%" (
    echo ERROR: fleet-commander.ps1 not found next to this launcher.
    echo Expected: %PS1%
    pause
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -STA -File "%PS1%" %*
set "RC=%errorlevel%"

echo.
if "%RC%"=="0" (
    echo  Fleet Commander finished. You can close this window.
) else (
    echo  Fleet Commander exited with code %RC%. Review the log above.
)
pause
exit /b %RC%
