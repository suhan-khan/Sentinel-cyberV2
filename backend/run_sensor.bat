@echo off
echo ========================================================
echo       Sentinel Cyber - Starting Windows Live Sensor
echo ========================================================
cd /d "%~dp0\sensor"

if exist ..\.venv\Scripts\activate.bat (
    call ..\.venv\Scripts\activate.bat
)

python windows_monitor.py
pause
