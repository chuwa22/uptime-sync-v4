"""Where everything lives. One install = one root directory.

    <root>/uptime_sync/   code (replaced by updates)
    <root>/config/        shipped defaults (replaced by updates)
    <root>/data/          site data -- never touched by updates, never in git
    <root>/logs/          logs.db (SQLite) + fallback text files
    <root>/run/           pid/lock/sentinel files of the running instance
    <root>/backups/       the code an update replaced (for rollback)

UPTIME_SYNC_ROOT overrides the root; the tests use it to run a throwaway copy.
"""

import os
import sys

ROOT = os.path.abspath(os.environ.get('UPTIME_SYNC_ROOT') or
                       os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CONFIG_DIR = os.path.join(ROOT, 'config')
DATA_DIR = os.path.join(ROOT, 'data')
LOG_DIR = os.path.join(ROOT, 'logs')
RUN_DIR = os.path.join(ROOT, 'run')
BACKUP_DIR = os.path.join(ROOT, 'backups')
STAGING_DIR = os.path.join(ROOT, 'update_staging')
DOWNLOAD_DIR = os.path.join(RUN_DIR, 'download')

DEFAULTS_FILE = os.path.join(CONFIG_DIR, 'defaults.json')
SETTINGS_FILE = os.path.join(DATA_DIR, 'settings.json')
MONITORS_FILE = os.path.join(DATA_DIR, 'monitors.json')
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
SECRET_KEY_FILE = os.path.join(DATA_DIR, 'secret.key')
ENV_FILE = os.path.join(DATA_DIR, '.env')
HISTORY_FILE = os.path.join(DATA_DIR, 'history.json')
LATCH_FILE = os.path.join(DATA_DIR, 'response_signing.json')
UPDATE_STATE_FILE = os.path.join(DATA_DIR, 'update_state.json')

# run/ -- the supervisor and its children talk through these files.
LOCK_FILE = os.path.join(RUN_DIR, 'supervisor.lock')
SUPERVISOR_PID = os.path.join(RUN_DIR, 'supervisor.pid')
STOPPED_FLAG = os.path.join(RUN_DIR, 'stopped')        # stays until `start`
SHUTDOWN_FLAG = os.path.join(RUN_DIR, 'shutdown')      # one-shot "exit now"
RESTART_FLAG = os.path.join(RUN_DIR, 'restart')        # one-shot "restart children"
UPDATE_READY = os.path.join(RUN_DIR, 'update_ready.json')
UPDATE_PENDING = os.path.join(RUN_DIR, 'update_pending.json')
INSTALL_TRIGGER = os.path.join(RUN_DIR, 'install.trigger')
STATUS_FILE = os.path.join(RUN_DIR, 'status.json')

# What an update replaces and what the release zip holds (tools/build-release.py
# reads this tuple). Everything else under ROOT belongs to the site. tools/ is
# developer tooling for a git clone and never ships.
SHIPPED = ('uptime_sync', 'config', 'main.py', 'install.py', 'VERSION',
           'requirements.txt', 'README.md', 'LICENSE', 'install.bat', 'Launcher.bat')


# The agent always runs on the interpreter inside <root>/.venv, so its
# packages (requirements.txt) never mix with the system Python's.
# install.py creates it; main.py re-launches itself into it.
VENV_DIR = os.path.join(ROOT, '.venv')


def venv_python(background=False):
    """<root>/.venv's interpreter. background=True: pythonw.exe on Windows
    (no console window); the same python elsewhere."""
    if os.name == 'nt':
        return os.path.join(VENV_DIR, 'Scripts', 'pythonw.exe' if background else 'python.exe')
    return os.path.join(VENV_DIR, 'bin', 'python')


def venv_home_missing():
    """The `home` of .venv/pyvenv.cfg when that folder is not on this
    machine, else ''. A .venv copied from another computer (a folder synced
    from a Mac to a Windows box) has the other machine's home, and its
    python fails before any Python code runs ("No Python at ...")."""
    try:
        with open(os.path.join(VENV_DIR, 'pyvenv.cfg')) as f:
            for line in f:
                key, sep, value = line.partition('=')
                if sep and key.strip().lower() == 'home':
                    home = value.strip()
                    return '' if not home or os.path.isdir(home) else home
    except (OSError, UnicodeDecodeError):
        pass
    return ''


def in_venv():
    """True when this process runs on <root>/.venv's interpreter."""
    def norm(p):
        return os.path.normcase(os.path.realpath(p))
    return norm(sys.prefix) == norm(VENV_DIR)


def child_stop_flag(name):
    return os.path.join(RUN_DIR, name + '.stop')


def child_pid_file(name):
    return os.path.join(RUN_DIR, name + '.pid')


def ensure_dirs():
    for d in (DATA_DIR, LOG_DIR, RUN_DIR):
        os.makedirs(d, mode=0o700, exist_ok=True)
