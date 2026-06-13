@echo off
echo ThreatLens TIP - Starting...
cd /d "%~dp0backend"
pip install -r requirements.txt --quiet
start "ThreatLens Backend" python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
timeout /t 2 /nobreak >nul
start "" "%~dp0frontend\index.html"
echo.
echo ThreatLens is running!
echo API: http://localhost:8000
echo Dashboard: frontend/index.html
echo Admin: frontend/index.html?admin=threatlens2024
echo.
pause
