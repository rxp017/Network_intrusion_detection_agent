@echo off
echo =======================================================
echo  Starting NIDA Network Intrusion Detection Agent...
echo =======================================================
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" main.py
) else (
    python main.py
)
pause
