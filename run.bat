@echo off
setlocal
title NetMeter - Local Subnet Traffic Monitor

cd /d "%~dp0"

echo ========================================================
echo   NetMeter - Per-Device Subnet Data Usage Monitor
echo ========================================================
echo.

if not exist ".venv\Scripts\python.exe" (
    echo [!] Virtual environment not found. Initializing...
    uv venv --python 3.12 .venv
    uv pip install -r requirements.txt --python .venv\Scripts\python.exe
)

echo [*] Starting NetMeter server on http://127.0.0.1:8000
echo [*] Open in browser: http://127.0.0.1:8000
echo.

.venv\Scripts\python.exe -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

pause
