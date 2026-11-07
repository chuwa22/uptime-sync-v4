"""Uptime Sync 4 entry point. `python main.py` lists the commands.

The agent always runs on <this folder>/.venv's interpreter, so the packages
from requirements.txt live there and never in (or from) the system Python.
Started with any other Python -- `python main.py status` from a prompt --
this file re-launches itself on .venv's python with the same arguments.
install.py creates .venv; it is the one script meant for the system Python.
"""

import os
import subprocess
import sys

if sys.version_info < (3, 8):
    sys.stderr.write('Uptime Sync needs Python 3.8 or newer (this is %s)\n' % sys.version.split()[0])
    sys.exit(1)

from uptime_sync import paths  # noqa: E402  (stdlib only: safe outside .venv)

REEXEC_FLAG = 'UPTIME_SYNC_REEXEC'
REQUIRED = ('requests', 'certifi', 'flask', 'werkzeug', 'waitress')


def _fail(msg):
    if sys.stderr:   # None under pythonw
        sys.stderr.write('[ERROR] %s\n' % msg)
        sys.stderr.write('[INFO] Fix: run  python install.py  in %s (with the system Python)\n'
                         % paths.ROOT)
    sys.exit(1)


def ensure_venv():
    if paths.in_venv():
        return
    py = paths.venv_python()
    if os.environ.get(REEXEC_FLAG):
        _fail('re-launched on %s but it does not run as this folder\'s .venv' % py)
    if not os.path.isfile(py):
        _fail('no .venv in %s (it holds the packages the agent needs)' % paths.ROOT)
    home = paths.venv_home_missing()
    if home:
        _fail('.venv was made on another machine: it needs the Python in %s, which is not '
              'here (was the folder copied with its .venv?)' % home)
    env = dict(os.environ)
    env[REEXEC_FLAG] = '1'
    args = [py, os.path.abspath(__file__)] + sys.argv[1:]
    if os.name == 'nt':
        # No exec on Windows: run it as a child with the same console.
        try:
            sys.exit(subprocess.call(args, env=env))
        except KeyboardInterrupt:
            sys.exit(130)
    os.execve(py, args, env)


def ensure_packages():
    import importlib.util
    missing = [name for name in REQUIRED if importlib.util.find_spec(name) is None]
    if missing:
        _fail('.venv is missing package(s): %s' % ', '.join(missing))


if __name__ == '__main__':
    ensure_venv()
    os.environ.pop(REEXEC_FLAG, None)
    ensure_packages()
    from uptime_sync.cli import main
    sys.exit(main())
