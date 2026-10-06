@echo off
rem ============================================================
rem  Campus portal dialer - logout
rem  Usage:  logout.bat 12345678910
rem ============================================================
setlocal
cd /d "%~dp0"

set ACCOUNT=%1
if "%ACCOUNT%"=="" goto ask

dialer.exe %ACCOUNT% -t %2 %3
goto end

:ask
dialer.exe -t %2 %3

:end
endlocal
