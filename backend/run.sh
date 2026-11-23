#!/usr/bin/env bash
echo "========================================================"
echo "      Sentinel Cyber - Starting FastAPI Server"
echo "========================================================"
cd "$(dirname "$0")"

if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi

uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}
