"""First-time setup. Run with the system Python (3.8 or newer):

    Windows (elevated prompt):  py -3 install.py      or  python install.py
    Linux / macOS:              python3 install.py    (sudo for a boot-time service)

It creates .venv/ inside this folder, installs requirements.txt into it,
then runs `.venv/.../python main.py install`, which registers autostart and
starts the agent. Safe to run again: an existing working .venv is reused.

Options:
    --wheels DIR      install from wheel files in DIR, no internet needed
    --no-autostart    set up the venv only; start with `main.py run`
    --recreate        delete .venv and build it again
"""

import argparse
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
VENV = os.path.join(ROOT, '.venv')
IS_WINDOWS = os.name == 'nt'


def venv_python():
    if IS_WINDOWS:
        return os.path.join(VENV, 'Scripts', 'python.exe')
    return os.path.join(VENV, 'bin', 'python')


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
    """True while a supervisor holds this install's lock. paths/procs are
    stdlib-only, so this works before .venv exists."""
    sys.path.insert(0, ROOT)
    try:
        from uptime_sync import paths, procs
        return procs.InstanceLock(paths.LOCK_FILE).held_by_other()
    except Exception:
        return False
    finally:
        sys.path.remove(ROOT)


def stop_broken_agent(timeout=30):
    """Stop a running agent the way `main.py stop` does (run/stopped +
    run/shutdown), stdlib only. For a .venv that broke under a running agent
    (the folder was synced from another machine): main.py cannot run on it,
    so `main.py stop` is not an option. `main.py install` starts it again."""
    sys.path.insert(0, ROOT)
    try:
        import time
        from uptime_sync import paths, procs
        os.makedirs(paths.RUN_DIR, exist_ok=True)
        for flag in (paths.STOPPED_FLAG, paths.SHUTDOWN_FLAG):
            open(flag, 'a').close()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not procs.InstanceLock(paths.LOCK_FILE).held_by_other():
                time.sleep(2)     # the process outlives its lock by ~1 s
                try:
                    os.remove(paths.SHUTDOWN_FLAG)
                except OSError:
                    pass
                return True
            time.sleep(0.5)
        return False
    finally:
        sys.path.remove(ROOT)


def main():
    p = argparse.ArgumentParser(description='Set up Uptime Sync 4 in this folder.')
    p.add_argument('--wheels', help='folder of wheel files for an offline install')
    p.add_argument('--no-autostart', action='store_true')
    p.add_argument('--recreate', action='store_true')
    a = p.parse_args()

    if sys.version_info < (3, 8):
        print('[ERROR] Python 3.8 or newer is required (this is %s).' % sys.version.split()[0])
        return 1
    if os.path.abspath(sys.prefix) == os.path.abspath(VENV):
        print('[ERROR] Run install.py with the system Python, not the one inside .venv.')
        return 1

    py = venv_python()
    broken = os.path.isdir(VENV) and not works(py)
    rebuild = os.path.isdir(VENV) and (a.recreate or broken)
    if broken and agent_running():
        step('.venv is broken but the agent still runs from it - stopping the agent')
        if not stop_broken_agent():
            print('[ERROR] The agent did not stop within 30 s. Stop it in Task Manager '
                  '(pythonw.exe from this folder) and run this again.')
            return 1
    if rebuild and agent_running():
        # Deleting .venv under a running agent removes part of it and then
        # fails on the files Windows keeps open -- the agent is left broken.
        print('[ERROR] The agent is running from this .venv. Stop it first:')
        print('        %s main.py stop' % venv_python())
        print('        then run this again (and `main.py start` afterwards if needed).')
        return 1
    if a.recreate and os.path.isdir(VENV):
        step('Removing the old .venv')
        shutil.rmtree(VENV)
    if os.path.isdir(VENV) and broken and not a.recreate:
        step('.venv is broken - rebuilding it')
        shutil.rmtree(VENV)
    if not os.path.isdir(VENV):
        step('Creating .venv with Python %s (%s)' % (sys.version.split()[0], sys.executable))
        try:
            import venv
            # Copies, not symlinks, on Windows: the venv keeps working if the
            # system Python is moved or upgraded in place.
            venv.EnvBuilder(with_pip=True, symlinks=not IS_WINDOWS, clear=True).create(VENV)
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
           os.path.join(ROOT, 'requirements.txt')]
    if a.wheels:
        cmd += ['--no-index', '--find-links', os.path.abspath(a.wheels)]
    if subprocess.call(cmd) != 0:
        print('[ERROR] pip install failed (see above).')
        return 1

    args = [py, os.path.join(ROOT, 'main.py'), 'install']
    if a.no_autostart:
        args.append('--no-autostart')
    step('Running: main.py install')
    return subprocess.call(args, cwd=ROOT)


if __name__ == '__main__':
    sys.exit(main())
