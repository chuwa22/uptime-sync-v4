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
rem Install (menu I, or without the menu):
rem     Launcher.bat install
rem     Launcher.bat install --no-autostart
rem     Launcher.bat install --recreate
rem     Launcher.bat install --wheels C:\wheels
rem finds the system Python 3.8 or newer and runs  main.py install  with
rem it; uptime_sync\bootstrap.py builds .venv and hands over to it.
rem For an option value with spaces, run  py -3 main.py install ...  from
rem an elevated prompt. To pick one Python yourself:  py -3.8 main.py install
rem
rem Rules (lessons from the 3.x Launcher):
rem   - nothing is spawned to draw the menu; the version comes from the
rem     VERSION file, the web address only when you open the web UI;
rem   - a .venv copied from another machine is spotted from pyvenv.cfg
rem     and sent to I (main.py install rebuilds it, stopping the agent first);
rem   - an empty answer three times in a row quits: with a broken stdin
rem     (scheduled task, piped input) set /p returns at once, and the
rem     menu would otherwise spin at full CPU.
rem
rem Keep this file ASCII with CRLF line endings (.gitattributes).

setlocal EnableExtensions
rem Saved before the argument loop: SHIFT moves %0 too, so %~f0 / %~dp0
rem would name the last argument afterwards.
set "SELF=%~f0"
set "HERE=%~dp0"
cd /d "%HERE%"
set "PY=%HERE%.venv\Scripts\python.exe"
set "MAIN=%HERE%main.py"

set "ELEVATED="
set "MODE="
set "ARGS="
:collect
if "%~1"=="" goto collected
if /i "%~1"=="/elevated" goto arg_elevated
if not defined MODE if not defined ARGS if /i "%~1"=="install" goto arg_install
set ARGS=%ARGS% %1
goto arg_next
:arg_elevated
set "ELEVATED=1"
goto arg_next
:arg_install
set "MODE=install"
:arg_next
shift
goto collect
:collected
if defined ARGS if not defined MODE goto usage

rem fltmc works on Windows 7 and later and, unlike "net session", does not
rem need the Server service.
fltmc >nul 2>&1
if not errorlevel 1 goto admin
if defined ELEVATED goto not_admin
echo [INFO] Asking for administrator rights...
set "PASS=/elevated"
if defined MODE set "PASS=/elevated install%ARGS%"
powershell -NoProfile -Command "Start-Process -FilePath '%SELF%' -ArgumentList '%PASS%' -Verb RunAs"
if errorlevel 1 goto not_admin
exit /b 0

:usage
echo Usage:  Launcher.bat                  the control panel
echo         Launcher.bat install [--no-autostart] [--recreate] [--wheels DIR]
exit /b 2

:not_admin
echo [ERROR] Administrator rights are needed: the service runs as SYSTEM.
echo [INFO] Right-click Launcher.bat and choose "Run as administrator".
pause
exit /b 1

:admin
if not defined MODE goto panel
title Uptime Sync 4 - install
call :install %ARGS%
echo.
pause
exit /b %RC%

:panel
set "VER="
if exist "%HERE%VERSION" set /p VER=<"%HERE%VERSION"
set "EMPTY=0"

:menu
title Uptime Sync %VER% - control panel
cls
echo  ==========================================================
echo    Uptime Sync %VER%  -  control panel
echo    %HERE%
echo  ==========================================================
if not exist "%PY%" echo    [WARN] Not installed yet - no .venv here. Choose I.
rem An update cut off mid-swap (power cut) can leave no main.py: nothing
rem then starts to put the old code back. Say where the copy is.
set "NOCODE="
if not exist "%MAIN%" set "NOCODE=1"
if not exist "%HERE%uptime_sync\__init__.py" set "NOCODE=1"
if defined NOCODE echo    [ERROR] main.py or uptime_sync\ is missing - an update was cut off.
if defined NOCODE echo            Copy back the files of the newest backups\v^<version^>-^<date^>
if defined NOCODE echo            folder - not a failed-v or interrupted-v one, those hold the
if defined NOCODE echo            new build - then choose I. data\ is not touched by an update.
rem A .venv copied from another machine (folder synced from a Mac) points
rem at that machine's Python: its python.exe fails with "No Python at ...".
rem Read home from pyvenv.cfg with for /f, a built-in - no process.
set "VHOME="
set "BROKEN="
if exist "%HERE%.venv\pyvenv.cfg" for /f "usebackq tokens=1,* delims== " %%a in ("%HERE%.venv\pyvenv.cfg") do if /i "%%a"=="home" set "VHOME=%%b"
if exist "%PY%" if defined VHOME if not exist "%VHOME%\python.exe" set "BROKEN=1"
if defined BROKEN echo    [WARN] .venv was made on another machine - it needs a Python at
if defined BROKEN echo           %VHOME%
if defined BROKEN echo           which is not on this box. Choose I to rebuild it.
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
echo      I  Install or repair - builds .venv, autostart, starts
echo      R  Rebuild .venv from scratch, then install
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
if /i "%CHOICE%"=="R" goto do_rebuild
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
if defined BROKEN goto broken
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
if defined BROKEN goto broken
set "WHO="
echo.
set /p "WHO=   User name [admin]: "
if not defined WHO set "WHO=admin"
call :run reset-password "%WHO%"
goto wait

:do_install
call :install
goto wait
:do_rebuild
echo.
echo    This deletes .venv and builds it again. data\ is kept.
set "SURE="
set /p "SURE=   Type YES to go on: "
if /i not "%SURE%"=="YES" goto cancelled
call :install --recreate
goto wait

:do_uninstall
if not exist "%PY%" goto not_installed
if defined BROKEN goto broken
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

:broken
echo.
echo [ERROR] .venv does not work on this box - choose I to rebuild it.
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
if defined BROKEN (
    echo.
    echo [ERROR] .venv does not work on this box - choose I to rebuild it.
    exit /b 1
)
echo.
"%PY%" "%MAIN%" %*
exit /b %ERRORLEVEL%

:install
rem Runs main.py install with the SYSTEM Python, never the .venv one: the
rem .venv may be missing or copied from another machine, and --recreate
rem deletes it. main.py hands over to uptime_sync\bootstrap.py for that.
echo.
set "SYSPY="
set "CHECK=import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"
py -3 -c "%CHECK%" >nul 2>&1
if not errorlevel 1 set "SYSPY=py -3"
if defined SYSPY goto install_found
python -c "%CHECK%" >nul 2>&1
if not errorlevel 1 set "SYSPY=python"
if defined SYSPY goto install_found
echo [ERROR] Python 3.8 or newer was not found (tried "py -3" and "python").
echo [INFO] Install it for all users and tick "Add Python to PATH".
echo [INFO] Windows 7: use Python 3.8.10, the last release that supports it.
set "RC=1"
exit /b 1
:install_found
%SYSPY% -c "import sys; print('[INFO] Python ' + sys.version.split()[0] + ' ' + sys.executable)"
echo [INFO] Folder %HERE%
echo.
%SYSPY% "%MAIN%" install %*
set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="0" echo [OK] Done. Check it any time with:  Launcher.bat, then 1
if not "%RC%"=="0" echo [ERROR] main.py install stopped with exit code %RC% (see above).
exit /b %RC%

:quit
endlocal
exit /b 0
