@echo off
setlocal
cd /d "%~dp0"
echo NIDA - local benchmark workspace
if not exist ".venv\Scripts\python.exe" (
  py -3.12 -m venv .venv
  if errorlevel 1 (
    echo Install Python 3.12, or use the Docker commands in README.md.
    pause
    exit /b 1
  )
)
".venv\Scripts\python.exe" -c "import fastapi, xgboost, sklearn" >nul 2>&1
if errorlevel 1 (
  ".venv\Scripts\python.exe" -m pip install -r requirements.txt
  if errorlevel 1 (
    echo Dependency installation failed. Check the error above.
    pause
    exit /b 1
  )
)
echo Open http://127.0.0.1:8000 - Ctrl+C stops the server.
".venv\Scripts\python.exe" main.py
if errorlevel 1 pause
