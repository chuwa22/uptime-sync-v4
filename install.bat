@echo off
rem Uptime Sync 4 - Windows installer. Double-click it, or run it from a prompt.
rem
rem It asks for administrator rights (autostart is a SYSTEM scheduled task),
rem finds the system Python 3.8 or newer, and runs install.py with it.
rem All the work is done by install.py; options are passed through:
rem     install.bat --no-autostart
rem     install.bat --recreate
rem     install.bat --wheels C:\wheels
rem For an option value with spaces, run install.py from an elevated prompt.
rem To pick one Python yourself:  py -3.8 install.py
rem
rem Keep this file ASCII with CRLF line endings (.gitattributes).

setlocal EnableExtensions
cd /d "%~dp0"
title Uptime Sync 4 - install

set "ELEVATED="
set "ARGS="
:collect
if "%~1"=="" goto collected
if /i "%~1"=="/elevated" (set "ELEVATED=1") else (set ARGS=%ARGS% %1)
shift
goto collect
:collected

rem fltmc works on Windows 7 and later and, unlike "net session", does not
rem need the Server service.
fltmc >nul 2>&1
if not errorlevel 1 goto admin
if defined ELEVATED goto not_admin
echo [INFO] Asking for administrator rights...
if defined ARGS (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '/elevated%ARGS%' -Verb RunAs"
) else (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '/elevated' -Verb RunAs"
)
if errorlevel 1 goto not_admin
exit /b 0

:not_admin
echo [ERROR] Administrator rights are needed: autostart runs as SYSTEM.
echo [INFO] Right-click install.bat and choose "Run as administrator".
goto done_fail

:admin
set "PY="
set "CHECK=import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"
py -3 -c "%CHECK%" >nul 2>&1
if not errorlevel 1 set "PY=py -3"
if defined PY goto found
python -c "%CHECK%" >nul 2>&1
if not errorlevel 1 set "PY=python"
if defined PY goto found
echo [ERROR] Python 3.8 or newer was not found (tried "py -3" and "python").
echo [INFO] Install it for all users and tick "Add Python to PATH".
echo [INFO] Windows 7: use Python 3.8.10, the last release that supports it.
goto done_fail

:found
%PY% -c "import sys; print('[INFO] Python ' + sys.version.split()[0] + ' ' + sys.executable)"
echo [INFO] Folder %CD%
echo.
%PY% "%~dp0install.py"%ARGS%
set "RC=%ERRORLEVEL%"
echo.
if not "%RC%"=="0" goto done_rc
echo [OK] Done. Check it any time with:  python main.py status
goto done

:done_rc
echo [ERROR] install.py stopped with exit code %RC% (see above).
goto done

:done_fail
set "RC=1"

:done
echo.
pause
exit /b %RC%
