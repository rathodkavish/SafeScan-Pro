@echo off
REM ════════════════════════════════════════════════════════════════════
REM   SafeScan-Pro Testing Server Launcher
REM   Exposes your local backend to the internet via ngrok
REM   Testers access: https://YOUR-NGROK-URL with username/password
REM ════════════════════════════════════════════════════════════════════

echo.
echo  ╔══════════════════════════════════════════════════╗
echo  ║          SafeScan Pro Testing Server             ║
echo  ╚══════════════════════════════════════════════════╝
echo.

REM ── Step 1: Start Flask Backend ─────────────────────────────────────
echo [1/2] Starting Flask Backend on port 5000...
cd /d "%~dp0backend"
start "SafeScan-Backend" cmd /k "call venv\Scripts\activate && set PYTHONUTF8=1 && python app.py"
timeout /t 5 /nobreak > nul

REM ── Step 2: Start ngrok tunnel with Basic Auth ──────────────────────
echo [2/2] Starting ngrok tunnel (password protected)...
echo.
echo  Username: tester
echo  Password: SafeScan2026
echo.
start "ngrok-tunnel" cmd /k "ngrok http 5000 --basic-auth ""tester:SafeScan2026"""
timeout /t 5 /nobreak > nul

echo.
echo ════════════════════════════════════════════════════════════
echo  BOTH SERVERS ARE RUNNING!
echo.
echo  1. Check the ngrok window for your PUBLIC URL
echo     (it looks like: https://xxxx-xxxx.ngrok-free.app)
echo.
echo  2. Share this with your tester:
echo     URL:      [copy from ngrok window]
echo     Username: tester
echo     Password: SafeScan2026
echo.
echo  3. Keep this laptop ON and CONNECTED to internet
echo     for 5 days while testing.
echo.
echo  4. To STOP: close both command windows.
echo ════════════════════════════════════════════════════════════
echo.
pause
