@echo off
REM ===================================================================
REM  MILNET SSO - Enroll This Node
REM  Double-click on each Windows 11 machine you want to add to the
REM  MILNET SSO cluster. It authorizes the Fleet Commander to deploy
REM  here. Run it ONCE per machine. It is idempotent.
REM
REM  Requires: fleet-authorized-key.pub in this folder (the Fleet
REM  Commander exports it on first run - copy it here before running).
REM ===================================================================
setlocal
title MILNET SSO - Enroll This Node

net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b 0
)

set "PS1=%~dp0enroll-node.ps1"
if not exist "%PS1%" (
    echo ERROR: enroll-node.ps1 not found next to this launcher.
    pause
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%"
echo.
pause
