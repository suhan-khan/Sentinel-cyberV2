@echo off
echo ========================================================
echo       Sentinel Cyber - Starting FastAPI Server
echo ========================================================
cd /d "%~dp0"

if exist .venv\Scripts\activate.bat (
    call .venv\Scripts\activate.bat
)

python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
pause
