@echo off
rem Double-click launcher: bootstrap.ps1 handles elevation and maximizing.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0bootstrap.ps1"
if errorlevel 1 (
    echo bootstrap.ps1 failed with exit code %errorlevel%.
    pause
)
