@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  set "PY=py -3"
) else (
  where python >nul 2>nul
  if not %errorlevel%==0 (
    echo Python 3 was not found. Install Python 3 and try again.
    pause
    exit /b 1
  )
  set "PY=python"
)
set /p "ACCOUNT=Account: "
%PY% enet_dialer.py --user "%ACCOUNT%"
if errorlevel 1 pause
endlocal
