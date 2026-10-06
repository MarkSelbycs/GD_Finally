@echo off
rem ============================================================
rem  Campus portal dialer - login + keepalive
rem  Usage:  dial.bat
rem          dial.bat 12345678910
rem ============================================================
setlocal
cd /d "%~dp0"

set ACCOUNT=%1
if "%ACCOUNT%"=="" goto ask

dialer.exe %ACCOUNT% %2 %3 %4 %5
goto end

:ask
dialer.exe %2 %3 %4 %5

:end
endlocal
