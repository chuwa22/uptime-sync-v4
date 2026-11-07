@echo off
rem Uptime Sync 4 - control panel for Windows. Double-click it.
rem
rem A menu over main.py: status, start/stop/restart, the web UI, monitor
rem checks, logs, password reset, install/uninstall. Every action runs
rem   .venv\Scripts\python.exe main.py <command>
rem so it does exactly what the same command does at a prompt.
rem It asks for administrator rights: the service is a SYSTEM scheduled
rem task, and stopping or starting it needs them.
rem
rem Rules (lessons from the 3.x Launcher):
rem   - nothing is spawned to draw the menu; the version comes from the
rem     VERSION file, the web address only when you open the web UI;
rem   - an empty answer three times in a row quits: with a broken stdin
rem     (scheduled task, piped input) set /p returns at once, and the
rem     menu would otherwise spin at full CPU.
rem
rem Keep this file ASCII with CRLF line endings (.gitattributes).

setlocal EnableExtensions
set "SELF=%~f0"
set "HERE=%~dp0"
cd /d "%HERE%"

fltmc >nul 2>&1
if not errorlevel 1 goto admin
if /i "%~1"=="/elevated" goto not_admin
echo [INFO] Asking for administrator rights...
powershell -NoProfile -Command "Start-Process -FilePath '%SELF%' -ArgumentList '/elevated' -Verb RunAs"
if errorlevel 1 goto not_admin
exit /b 0

:not_admin
echo [ERROR] Administrator rights are needed: the service runs as SYSTEM.
echo [INFO] Right-click Launcher.bat and choose "Run as administrator".
pause
exit /b 1

:admin
set "VER="
if exist "%HERE%VERSION" set /p VER=<"%HERE%VERSION"
set "PY=%HERE%.venv\Scripts\python.exe"
set "MAIN=%HERE%main.py"
set "EMPTY=0"

:menu
title Uptime Sync %VER% - control panel
cls
echo  ==========================================================
echo    Uptime Sync %VER%  -  control panel
echo    %HERE%
echo  ==========================================================
if not exist "%PY%" echo    [WARN] Not installed yet - no .venv here. Choose I.
echo.
echo    Run it
echo      1  Status
echo      2  Start
echo      3  Stop          - stays stopped, also across reboots
echo      4  Restart
echo.
echo    Look at it
echo      5  Open the web UI in the browser
echo      6  Check every monitor now - no push
echo      7  Recent log lines - last 50
echo      8  Warnings and errors only - last 50
echo.
echo    Set it up
echo      9  Reset a web UI password
echo      I  Install or repair - runs install.bat
echo      U  Uninstall autostart - keeps data\
echo.
echo      H  Every command - main.py help
echo      Q  Quit
echo.
set "CHOICE="
set /p "CHOICE=   Choose: "
if defined CHOICE goto chosen
set /a EMPTY+=1
if %EMPTY% geq 3 goto quit
goto menu

:chosen
set "EMPTY=0"
if "%CHOICE%"=="1" goto do_status
if "%CHOICE%"=="2" goto do_start
if "%CHOICE%"=="3" goto do_stop
if "%CHOICE%"=="4" goto do_restart
if "%CHOICE%"=="5" goto do_open
if "%CHOICE%"=="6" goto do_check
if "%CHOICE%"=="7" goto do_logs
if "%CHOICE%"=="8" goto do_warnings
if "%CHOICE%"=="9" goto do_password
if /i "%CHOICE%"=="I" goto do_install
if /i "%CHOICE%"=="U" goto do_uninstall
if /i "%CHOICE%"=="H" goto do_help
if /i "%CHOICE%"=="Q" goto quit
echo.
echo [WARN] Unknown choice: %CHOICE%
goto wait

:do_status
call :run status
goto wait
:do_start
call :run start
goto wait
:do_stop
call :run stop
goto wait
:do_restart
call :run restart
goto wait
:do_check
call :run check
goto wait
:do_logs
call :run logs -n 50
goto wait
:do_warnings
call :run logs -n 50 --level WARNING
goto wait
:do_help
call :run help
goto wait

:do_open
if not exist "%PY%" goto not_installed
set "URL="
set "TMPURL=%TEMP%\uptime_sync_v4_url.txt"
"%PY%" "%MAIN%" help 2>nul | findstr /b /c:"Web UI:" > "%TMPURL%"
for /f "usebackq tokens=3" %%u in ("%TMPURL%") do set "URL=%%u"
del "%TMPURL%" >nul 2>&1
if not defined URL set "URL=http://127.0.0.1:5000/"
echo.
echo [INFO] Opening %URL%
start "" "%URL%"
goto wait

:do_password
if not exist "%PY%" goto not_installed
set "WHO="
echo.
set /p "WHO=   User name [admin]: "
if not defined WHO set "WHO=admin"
call :run reset-password "%WHO%"
goto wait

:do_install
echo.
call "%HERE%install.bat" /elevated
goto menu

:do_uninstall
if not exist "%PY%" goto not_installed
echo.
echo    This stops Uptime Sync and removes its autostart task.
echo    data\ - settings, monitors, users - is kept.
set "SURE="
set /p "SURE=   Type YES to go on: "
if /i not "%SURE%"=="YES" goto cancelled
call :run uninstall
goto wait

:cancelled
echo [INFO] Nothing changed.
goto wait

:not_installed
echo.
echo [ERROR] Not installed yet - no .venv in this folder. Choose I first.
goto wait

:wait
echo.
pause
goto menu

:run
if not exist "%PY%" (
    echo.
    echo [ERROR] Not installed yet - no .venv in this folder. Choose I first.
    exit /b 1
)
echo.
"%PY%" "%MAIN%" %*
exit /b %ERRORLEVEL%

:quit
endlocal
exit /b 0
