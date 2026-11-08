"""The step before `main.py install` can run: build <root>/.venv.

main.py calls prepare() when `main.py install` is started by a Python that
is not .venv's (the system Python, 3.8 or newer):

    Windows (elevated):  py -3 main.py install      (or Launcher.bat -> I)
    macOS:               sudo python3 main.py install   (or Launcher.command -> I)
    Linux:               sudo python3 main.py install

prepare() creates .venv/ (or rebuilds it when it is broken or --recreate is
given) and installs requirements.txt into it. main.py then re-launches
itself on .venv's python with the same arguments, and `install` registers
autostart and starts the agent. Safe to run again: a working .venv is reused.

Standard library only: it runs before .venv (and its packages) exist.
"""

import argparse
import os
import shutil
import subprocess
import sys
import time

from . import paths, procs

IS_WINDOWS = os.name == 'nt'
DONE_FLAG = 'UPTIME_SYNC_BOOTSTRAPPED'   # set for the re-launched `install`


def works(python):
    try:
        out = subprocess.run([python, '-c', 'import sys, ssl, sqlite3; print(sys.version_info[:2])'],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return out.returncode == 0


def step(msg):
    print('[INFO] ' + msg)
    sys.stdout.flush()


def agent_running():
    """True while a supervisor holds this install's lock."""
    try:
        return procs.InstanceLock(paths.LOCK_FILE).held_by_other()
    except Exception:
        return False


def stop_agent(timeout=30):
    """Stop a running agent the way `main.py stop` does (run/stopped +
    run/shutdown), stdlib only, before its .venv is rebuilt (--recreate, or
    a .venv synced from another machine that main.py cannot even run on).
    `main.py install` starts it again at the end."""
    os.makedirs(paths.RUN_DIR, exist_ok=True)
    for flag in (paths.STOPPED_FLAG, paths.SHUTDOWN_FLAG):
        open(flag, 'a').close()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not agent_running():
            time.sleep(2)     # the process outlives its lock by ~1 s
            try:
                os.remove(paths.SHUTDOWN_FLAG)
            except OSError:
                pass
            return True
        time.sleep(0.5)
    return False


def parse(argv):
    """The options prepare() uses; the rest (--no-autostart) are for
    `main.py install` itself, which validates them after the re-launch."""
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument('--wheels')
    p.add_argument('--recreate', action='store_true')
    a, _ = p.parse_known_args(argv)
    return a


def prepare(argv):
    """Create or repair .venv and install requirements.txt. 0 = ready."""
    a = parse(argv)
    venv_dir, py = paths.VENV_DIR, paths.venv_python()
    broken = os.path.isdir(venv_dir) and not works(py)
    rebuild = os.path.isdir(venv_dir) and (a.recreate or broken)
    if rebuild and agent_running():
        # Deleting .venv under a running agent removes part of it and then
        # fails on the files Windows keeps open -- the agent is left broken.
        # So stop it first; `main.py install` starts it again at the end.
        step('The agent runs from this .venv - stopping it before the rebuild')
        if not stop_agent():
            print('[ERROR] The agent did not stop within 30 s. Stop it in Task Manager '
                  '(pythonw.exe from this folder) and run this again.')
            return 1
    if a.recreate and os.path.isdir(venv_dir):
        step('Removing the old .venv')
        shutil.rmtree(venv_dir)
    if os.path.isdir(venv_dir) and broken and not a.recreate:
        step('.venv is broken - rebuilding it')
        shutil.rmtree(venv_dir)
    if not os.path.isdir(venv_dir):
        step('Creating .venv with Python %s (%s)' % (sys.version.split()[0], sys.executable))
        try:
            import venv
            # Copies, not symlinks, on Windows: the venv keeps working if the
            # system Python is moved or upgraded in place.
            venv.EnvBuilder(with_pip=True, symlinks=not IS_WINDOWS, clear=True).create(venv_dir)
        except Exception as e:
            print('[ERROR] Could not create the venv: %s' % e)
            if sys.platform.startswith('linux'):
                print('[INFO] On Debian/Ubuntu: sudo apt install python3-venv')
            return 1
    if not works(py):
        print('[ERROR] %s does not run.' % py)
        return 1

    step('Installing requirements')
    cmd = [py, '-m', 'pip', 'install', '--disable-pip-version-check', '-r',
           os.path.join(paths.ROOT, 'requirements.txt')]
    if a.wheels:
        cmd += ['--no-index', '--find-links', os.path.abspath(a.wheels)]
    if subprocess.call(cmd) != 0:
        print('[ERROR] pip install failed (see above).')
        return 1
    step('Running: main.py install on .venv')
    return 0
