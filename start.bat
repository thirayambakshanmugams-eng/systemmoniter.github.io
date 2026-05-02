@echo off
cd /d "%~dp0"
title "SysMon Pro - System Monitor & Security Scanner"
color 0A

echo.
echo ==========================================
echo SysMon Pro - System Monitor ^& Scanner
echo ==========================================
echo.

echo [1/3] Checking Python...
python --version 2>NUL
if errorlevel 1 (
    echo ERROR: Python not found. Please install Python 3.8+
    pause
    exit /b 1
)

echo [2/3] Installing dependencies...
python -m pip install flask flask-cors psutil fpdf2 --quiet --disable-pip-version-check

echo [3/3] Starting backend server at http://localhost:5000
echo.
echo >> Open your browser at: http://localhost:5000
echo >> Press Ctrl+C to stop the server
echo.

REM Open browser after 2 seconds
start /b cmd /c "timeout /t 2 /nobreak >NUL && start http://localhost:5000"

REM Start the server
python backend\server.py
pause