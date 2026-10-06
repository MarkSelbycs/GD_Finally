@echo off
rem ============================================================
rem  Campus portal dialer (Python) - login + keepalive
rem  Usage: dial.bat
rem         dial.bat 1111111111
rem ============================================================
chcp 65001 >nul 2>&1
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1
cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 (
  echo [!] python not found in PATH. Install Python 3, or edit this file.
  pause
  exit /b 1
)

python dialer.py %*
echo.
pause
