#!/bin/bash
# Uptime Sync 4 - control panel for macOS. Double-click it in Finder.
#
# The macOS twin of Launcher.bat: a menu over main.py (status,
# start/stop/restart, the web UI, monitor checks, logs, password reset,
# install/uninstall). Every action runs
#   .venv/bin/python main.py <command>
# so it does exactly what the same command does in Terminal.
#
# Install (menu I, or without the menu):
#     ./Launcher.command install
#     ./Launcher.command install --no-autostart
#     ./Launcher.command install --recreate
#     ./Launcher.command install --wheels /path/to/wheels
# finds the system python3 (3.8 or newer) and runs  main.py install  with
# it through sudo, so autostart is a LaunchDaemon that starts at boot;
# uptime_sync/bootstrap.py builds .venv and hands over to it. A folder
# already installed as a LaunchAgent (python3 main.py install without
# sudo) is repaired as one, without sudo.
#
# First run: a folder unzipped from a download is quarantined, and Finder
# refuses to open this file. Right-click it > Open (macOS 15 and later:
# System Settings > Privacy & Security > Open Anyway), or in Terminal:
#     xattr -d com.apple.quarantine Launcher.command
# "You do not have appropriate access privileges": the unzip tool dropped
# the executable bit. chmod +x Launcher.command  (or: bash Launcher.command)
#
# Rules (the same as Launcher.bat):
#   - nothing is spawned to draw the menu; the version comes from the
#     VERSION file, the web address only when you open the web UI;
#   - a .venv copied from another machine is spotted from pyvenv.cfg
#     and sent to I (main.py install rebuilds it, stopping the agent first);
#   - an empty answer three times in a row, or end of input, quits: the
#     menu never spins on a broken stdin.
#
# Runs on the macOS bash 3.2 and on zsh (no arrays, no [[ ]], no local).
# Keep this file ASCII with LF line endings (.gitattributes), executable.

# Finder starts a .command file in the home folder: go to our own.
HERE="$(cd "$(dirname "$0")" && pwd)" || exit 1
cd "$HERE" || exit 1
PY="$HERE/.venv/bin/python"
MAIN="$HERE/main.py"
STATE="$HERE/data/autostart.json"
CHECK='import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)'

say() {
    printf '%s\n' "$*"
}

title() {
    printf '\033]0;%s\007' "$*"
}

pause() {
    say ''
    printf '   Press Return to go on... '
    read -r DUMMY || return 1
    return 0
}

# Which service kind data/autostart.json names: "system" (a LaunchDaemon,
# launchctl needs root), "user" (a LaunchAgent) or "" (none yet).
service_kind() {
    KIND=''
    if [ -f "$STATE" ]; then
        if [ ! -r "$STATE" ]; then
            KIND='system'
            return 0
        fi
        while IFS= read -r LINE || [ -n "$LINE" ]; do
            case "$LINE" in
                *'"domain": "system"'*) KIND='system' ;;
                *'"domain": "gui/'*) KIND='user' ;;
            esac
        done < "$STATE"
    fi
    return 0
}

# Prefix for the commands launchctl needs root for (install, start,
# restart, uninstall) when the service is a LaunchDaemon.
root_prefix() {
    ASROOT=''
    if [ "$(id -u)" != "0" ]; then
        service_kind
        if [ "$KIND" = "system" ]; then
            ASROOT='sudo'
            say '[INFO] The service is a LaunchDaemon: sudo asks for your Mac password.'
        fi
    fi
    return 0
}

# Reads VERSION, pyvenv.cfg and the code files with shell built-ins only.
look() {
    VER=''
    if [ -f "$HERE/VERSION" ]; then
        read -r VER < "$HERE/VERSION"
    fi
    NOCODE=''
    if [ ! -f "$MAIN" ] || [ ! -f "$HERE/uptime_sync/__init__.py" ]; then
        NOCODE=1
    fi
    # A .venv copied from another machine (a folder synced from another
    # Mac or from Windows) points at that machine's Python.
    VHOME=''
    BROKEN=''
    if [ -f "$HERE/.venv/pyvenv.cfg" ]; then
        while IFS= read -r LINE || [ -n "$LINE" ]; do
            case "$LINE" in
                home*=*)
                    VHOME="${LINE#*=}"
                    VHOME="${VHOME# }"
                    ;;
            esac
        done < "$HERE/.venv/pyvenv.cfg"
    fi
    if [ -n "$VHOME" ] && [ ! -d "$VHOME" ]; then
        BROKEN=1
    elif [ -L "$PY" ] && [ ! -e "$PY" ]; then
        BROKEN=1
    fi
    return 0
}

usable() {
    if [ -n "$BROKEN" ]; then
        say ''
        say '[ERROR] .venv does not work on this Mac - choose I to rebuild it.'
        return 1
    fi
    if [ ! -x "$PY" ]; then
        say ''
        say '[ERROR] Not installed yet - no .venv in this folder. Choose I first.'
        return 1
    fi
    return 0
}

run() {
    usable || return 1
    say ''
    "$PY" "$MAIN" "$@"
}

run_root() {
    usable || return 1
    say ''
    root_prefix
    $ASROOT "$PY" "$MAIN" "$@"
}

sure() {
    SURE=''
    printf '   Type YES to go on: '
    read -r SURE || SURE=''
    case "$SURE" in
        YES|yes|Yes) return 0 ;;
    esac
    say '[INFO] Nothing changed.'
    return 1
}

# Finds the system python3, 3.8 or newer. Never the .venv one: the .venv
# may be missing or copied from another machine, and --recreate deletes it.
find_python() {
    SYSPY=''
    for CAND in "$(command -v python3 2>/dev/null)" /usr/local/bin/python3 /opt/homebrew/bin/python3 \
            /Library/Frameworks/Python.framework/Versions/Current/bin/python3 /usr/bin/python3; do
        case "$CAND" in
            ''|"$HERE"/.venv/*) continue ;;
        esac
        if [ -x "$CAND" ] && "$CAND" -c "$CHECK" >/dev/null 2>&1; then
            SYSPY="$CAND"
            return 0
        fi
    done
    say '[ERROR] Python 3.8 or newer was not found (tried python3 on PATH, /usr/local/bin,'
    say '        /opt/homebrew/bin, /Library/Frameworks and /usr/bin).'
    say '[INFO] Install it from https://www.python.org/downloads/macos/'
    say '[INFO] or install the Apple command line tools:  xcode-select --install'
    return 1
}

do_install() {
    say ''
    find_python || { RC=1; return 1; }
    "$SYSPY" -c "import sys; print('[INFO] Python ' + sys.version.split()[0] + ' ' + sys.executable)"
    say "[INFO] Folder $HERE"
    ASROOT=''
    if [ "$(id -u)" != "0" ]; then
        service_kind
        if [ "$KIND" = "user" ]; then
            say '[INFO] Installed as a LaunchAgent (no sudo): repairing it as one.'
        else
            ASROOT='sudo'
            say '[INFO] sudo asks for your Mac password: autostart is a LaunchDaemon (starts at boot).'
        fi
    fi
    say ''
    $ASROOT "$SYSPY" "$MAIN" install "$@"
    RC=$?
    say ''
    if [ "$RC" = "0" ]; then
        say '[OK] Done. Check it any time with:  Launcher.command, then 1'
    else
        say "[ERROR] main.py install stopped with exit code $RC (see above)."
    fi
    return "$RC"
}

do_open() {
    usable || return 1
    URL="$("$PY" "$MAIN" help 2>/dev/null | sed -n 's/^Web UI: *//p' | head -n 1)"
    if [ -z "$URL" ]; then
        URL='http://127.0.0.1:5000/'
    fi
    say ''
    say "[INFO] Opening $URL"
    open "$URL"
}

do_password() {
    usable || return 1
    WHO=''
    say ''
    printf '   User name [admin]: '
    read -r WHO || WHO=''
    if [ -z "$WHO" ]; then
        WHO='admin'
    fi
    run reset-password "$WHO"
}

menu() {
    look
    title "Uptime Sync $VER - control panel"
    printf '\033[H\033[2J'
    say ' =========================================================='
    say "   Uptime Sync $VER  -  control panel"
    say "   $HERE"
    say ' =========================================================='
    if [ ! -x "$PY" ] && [ -z "$BROKEN" ]; then
        say '   [WARN] Not installed yet - no .venv here. Choose I.'
    fi
    # An update cut off mid-swap (power cut) can leave no main.py: nothing
    # then starts to put the old code back. Say where the copy is.
    if [ -n "$NOCODE" ]; then
        say '   [ERROR] main.py or uptime_sync/ is missing - an update was cut off.'
        say '           Copy back the files of the newest backups/v<version>-<date>'
        say '           folder - not a failed-v or interrupted-v one, those hold the'
        say '           new build - then choose I. data/ is not touched by an update.'
    fi
    if [ -n "$BROKEN" ]; then
        say '   [WARN] .venv was made on another machine - it needs a Python at'
        say "          $VHOME"
        say '          which is not on this Mac. Choose I to rebuild it.'
    fi
    say ''
    say '   Run it'
    say '     1  Status'
    say '     2  Start'
    say '     3  Stop          - stays stopped, also across reboots'
    say '     4  Restart'
    say ''
    say '   Look at it'
    say '     5  Open the web UI in the browser'
    say '     6  Check every monitor now - no push'
    say '     7  Recent log lines - last 50'
    say '     8  Warnings and errors only - last 50'
    say ''
    say '   Set it up'
    say '     9  Reset a web UI password'
    say '     I  Install or repair - builds .venv, autostart, starts'
    say '     R  Rebuild .venv from scratch, then install'
    say '     U  Uninstall autostart - keeps data/'
    say ''
    say '     H  Every command - main.py help'
    say '     Q  Quit'
    say ''
}

panel() {
    EMPTY=0
    while :; do
        menu
        CHOICE=''
        printf '   Choose: '
        read -r CHOICE || { say ''; return 0; }
        if [ -z "$CHOICE" ]; then
            EMPTY=$((EMPTY + 1))
            if [ "$EMPTY" -ge 3 ]; then
                return 0
            fi
            continue
        fi
        EMPTY=0
        case "$CHOICE" in
            1) run status ;;
            2) run_root start ;;
            3) run stop ;;
            4) run_root restart ;;
            5) do_open ;;
            6) run check ;;
            7) run logs -n 50 ;;
            8) run logs -n 50 --level WARNING ;;
            9) do_password ;;
            I|i) do_install ;;
            R|r)
                say ''
                say '   This deletes .venv and builds it again. data/ is kept.'
                if sure; then
                    do_install --recreate
                fi
                ;;
            U|u)
                if usable; then
                    say ''
                    say '   This stops Uptime Sync and removes its autostart job.'
                    say '   data/ - settings, monitors, users - is kept.'
                    if sure; then
                        run_root uninstall
                    fi
                fi
                ;;
            H|h) run help ;;
            Q|q) return 0 ;;
            *)
                say ''
                say "[WARN] Unknown choice: $CHOICE"
                ;;
        esac
        pause || return 0
    done
}

if [ "$#" -eq 0 ]; then
    panel
    exit 0
fi
if [ "$1" = "install" ]; then
    shift
    title 'Uptime Sync 4 - install'
    do_install "$@"
    RC=$?
    exit "$RC"
fi
say 'Usage:  ./Launcher.command                 the control panel'
say '        ./Launcher.command install [--no-autostart] [--recreate] [--wheels DIR]'
exit 2
