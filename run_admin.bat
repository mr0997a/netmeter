@echo off
setlocal
title NetMeter - Elevated Admin Launcher

:: Verify if already running as Administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Administrator privileges are required for promiscuous raw packet sniffing.
    echo [*] Opening Windows UAC elevation prompt...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath cmd.exe -ArgumentList '/k cd /d %~dp0 && call run.bat' -Verb RunAs"
    exit /b
)

call "%~dp0run.bat"
