"""Owner-only permissions on data/ and logs/, re-applied on every start.

data/ holds the HMAC secret, the api_key, push tokens and password hashes;
logs/ holds everything the agent did. Setting permissions only when a file
is created is not enough: a hand-made `cp config/env.example data/.env`, a
file restored from a backup, or an `import` all arrive with default modes.
So the supervisor calls harden() each time it starts, and `main.py status`
reports what check() finds.

    POSIX    directories 0700, files 0600 (and umask 077 for new files).
    Windows  icacls: inheritance removed from data\\ and logs\\, full control
             for SYSTEM and Administrators (well-known SIDs, so a Thai or
             German Windows works the same), plus the user who ran
             `main.py install`; everything inside is reset to inherit that.
             Without this, a folder under C:\\ inherits "Users: read".

A failure is logged and never stops the agent: a permission problem must
not be the reason a monitoring box stays down.
"""

import os
import subprocess

from . import paths

IS_WINDOWS = os.name == 'nt'
SID_SYSTEM = '*S-1-5-18'
SID_ADMINS = '*S-1-5-32-544'
PROTECTED = (paths.DATA_DIR, paths.LOG_DIR)


def _dirs():
    return [d for d in PROTECTED if os.path.isdir(d)]


# -- POSIX -------------------------------------------------------------------

def _posix_harden():
    problems = []
    for top in _dirs():
        for root, dirs, files in os.walk(top):
            for name, mode in [(root, 0o700)] + [(os.path.join(root, f), 0o600) for f in files]:
                try:
                    if os.path.islink(name):
                        continue
                    if os.stat(name).st_mode & 0o777 != mode:
                        os.chmod(name, mode)
                except OSError as e:
                    problems.append('%s: %s' % (name, e))
    return problems


def _posix_check():
    found = []
    for top in _dirs():
        for root, dirs, files in os.walk(top):
            for name in [root] + [os.path.join(root, f) for f in files]:
                try:
                    if not os.path.islink(name) and os.stat(name).st_mode & 0o077:
                        found.append(name)
                except OSError:
                    pass
    return found


# -- Windows -----------------------------------------------------------------

def current_user_sid():
    """'*S-1-5-21-...' for the user running this process, or ''."""
    try:
        out = _run(['whoami', '/user', '/fo', 'csv', '/nh'])[1]
        sid = out.strip().splitlines()[-1].split(',')[-1].strip().strip('"')
        return '*' + sid if sid.startswith('S-1-') else ''
    except Exception:
        return ''


def icacls_commands(directory, extra_sids=()):
    """The icacls calls that lock `directory` down (pure: unit-tested)."""
    grants = []
    for sid in (SID_SYSTEM, SID_ADMINS) + tuple(s for s in extra_sids if s):
        grants += ['/grant:r', '%s:(OI)(CI)F' % sid]
    return [
        ['icacls', directory, '/inheritance:r'] + grants + ['/Q'],
        # children: drop explicit ACEs (e.g. a file copied in with its own
        # ACL) so they inherit exactly the folder's.
        ['icacls', os.path.join(directory, '*'), '/reset', '/T', '/C', '/Q'],
    ]


def _run(cmd):
    flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       stdin=subprocess.DEVNULL, timeout=60, creationflags=flags)
    return p.returncode, p.stdout.decode('utf-8', 'replace')


def _windows_harden(grant_current_user):
    extra = (current_user_sid(),) if grant_current_user else ()
    problems = []
    for d in _dirs():
        for i, cmd in enumerate(icacls_commands(d, extra)):
            if i == 1 and not os.listdir(d):
                continue          # nothing inside; icacls would report "no files"
            code, out = _run(cmd)
            if code != 0:
                problems.append('%s: icacls exit %d: %s' % (d, code, out.strip()[-200:]))
    return problems


def _windows_check():
    """Folders that still inherit permissions (icacls marks inherited ACEs
    "(I)" in every language)."""
    found = []
    for d in _dirs():
        try:
            code, out = _run(['icacls', d])
        except Exception:
            continue
        if code == 0 and '(I)' in out:
            found.append(d)
    return found


def return_to_sudo_user():
    """After a `sudo main.py ...` command, hand data/, logs/ and run/ back to
    the user who ran sudo: the systemd unit / LaunchDaemon runs the agent as
    that user (User= / UserName=), and with 0700/0600 a root-owned file there
    would lock the agent out of its own settings. POSIX only; quiet."""
    if IS_WINDOWS or os.geteuid() != 0:
        return
    try:
        uid, gid = int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
    except (KeyError, ValueError):
        return
    if uid == 0:
        return
    for top in (paths.DATA_DIR, paths.LOG_DIR, paths.RUN_DIR):
        for root, dirs, files in os.walk(top):
            for name in [root] + [os.path.join(root, f) for f in files]:
                try:
                    if os.lstat(name).st_uid != uid:
                        os.lchown(name, uid, gid)
                except OSError:
                    pass


# -- public --------------------------------------------------------------------

def restrict_umask():
    """New files and folders owner-only (POSIX; no-op on Windows)."""
    if not IS_WINDOWS:
        os.umask(0o077)


def harden(grant_current_user=False):
    """Apply owner-only permissions. Returns a list of problems (empty = ok).
    grant_current_user: also give the user running this full control
    (Windows; used by `main.py install` so the admin's CLI keeps working)."""
    try:
        if IS_WINDOWS:
            return _windows_harden(grant_current_user)
        return _posix_harden()
    except Exception as e:     # never fatal
        return ['%s' % e]


def check():
    """Paths that other local users can read. Empty = locked down."""
    try:
        return _windows_check() if IS_WINDOWS else _posix_check()
    except Exception:
        return []

