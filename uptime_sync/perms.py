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
             The install folder itself gets the same treatment, except that
             Users keep read+execute: a folder made under C:\\ inherits
             "Authenticated Users: Modify", and its code runs as SYSTEM every
             minute -- any local user could edit a .py file and own the box.

A failure is logged and never stops the agent: a permission problem must
not be the reason a monitoring box stays down.
"""

import hashlib
import os

from . import paths, procs

IS_WINDOWS = os.name == 'nt'
SID_SYSTEM = '*S-1-5-18'
SID_ADMINS = '*S-1-5-32-544'
SID_USERS = '*S-1-5-32-545'
SID_AUTH_USERS = 'S-1-5-11'
SID_EVERYONE = 'S-1-1-0'
PROTECTED = (paths.DATA_DIR, paths.LOG_DIR)
ACL_STAMP = os.path.join(paths.RUN_DIR, 'acl.stamp')
# WriteData | AppendData | WriteExtendedAttributes | WriteAttributes, plus
# GENERIC_ALL / GENERIC_WRITE as they appear on inherit-only entries.
_WRITE_BITS = 0x116 | 0x10000000 | 0x40000000


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


def root_icacls_command(root, extra_sids=()):
    """Lock the install folder (pure: unit-tested): inheritance from the
    drive removed, SYSTEM/Administrators (and the installing user) full
    control, Users read+execute. Children that inherit pick it up; data\\
    and logs\\ have inheritance removed and keep their own, stricter ACL."""
    grants = []
    for sid in (SID_SYSTEM, SID_ADMINS) + tuple(s for s in extra_sids if s):
        grants += ['/grant:r', '%s:(OI)(CI)F' % sid]
    return ['icacls', root, '/inheritance:r'] + grants + ['/grant:r', '%s:(OI)(CI)RX' % SID_USERS, '/Q']


def _run(cmd, timeout=300):
    # 300 s: the root icacls rewrites the ACL of every file below it, .venv
    # included -- thousands of files on a slow Windows 7 disk.
    code, raw, error = procs.run(cmd, timeout)
    if code is None:
        return -1, error
    # schtasks / icacls / whoami print in the OEM code page (cp874 on Thai
    # Windows), not UTF-8; ASCII-safe so the message can always be printed.
    return code, _console_text(raw)


def _console_text(raw):
    enc = 'oem' if IS_WINDOWS else 'utf-8'
    try:
        text = raw.decode(enc, 'replace')
    except LookupError:
        text = raw.decode('utf-8', 'replace')
    return text.encode('ascii', 'replace').decode('ascii')


def _root_acl_digest(root):
    """Hash of the install folder's own ACL as icacls lists it; '' if unknown."""
    code, out = _run(['icacls', root], timeout=30)
    return hashlib.sha256(out.encode('ascii', 'replace')).hexdigest() if code == 0 else ''


def _windows_harden(grant_current_user):
    extra = (current_user_sid(),) if grant_current_user else ()
    problems = []
    root = paths.ROOT
    if os.path.dirname(root) != root:      # never a drive root such as C:\\
        # The root icacls rewrites the inherited ACL of every file below it,
        # .venv included: minutes on a slow disk. Re-apply it only when the
        # folder's ACL is not the one this agent left last time.
        stamp = ''
        try:
            with open(ACL_STAMP, 'r') as f:
                stamp = f.read().strip()
        except OSError:
            pass
        if grant_current_user or not stamp or stamp != _root_acl_digest(root):
            code, out = _run(root_icacls_command(root, extra))
            if code != 0:
                problems.append('%s: icacls exit %d: %s' % (root, code, out.strip()[-200:]))
            else:
                digest = _root_acl_digest(root)
                if digest:
                    try:
                        from .util import atomic_write_text
                        atomic_write_text(ACL_STAMP, digest)
                    except OSError:
                        pass
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


# -- install-time checks (Windows) -------------------------------------------------

def set_owner_admins(root):
    """Make Administrators the owner of everything under the install folder.
    The owner of a file may always rewrite its ACL, so a .py file still owned
    by the user who unzipped the release could be made writable again by
    that user -- and the agent runs it as SYSTEM. Problems as a list."""
    if not IS_WINDOWS or os.path.dirname(root) == root:
        return []
    code, out = _run(['icacls', root, '/setowner', SID_ADMINS, '/T', '/C', '/Q'], timeout=600)
    return [] if code == 0 else ['%s: icacls /setowner exit %d: %s' % (root, code, out.strip()[-200:])]


def venv_base_home():
    """The base Python folder .venv runs on (pyvenv.cfg `home`), or ''."""
    try:
        with open(os.path.join(paths.VENV_DIR, 'pyvenv.cfg'), 'r', encoding='utf-8') as f:
            for line in f:
                key, _, value = line.partition('=')
                if key.strip().lower() == 'home':
                    return value.strip()
    except OSError:
        pass
    return ''


def acl_ps_command(path):
    """PowerShell that prints '<SID> <rights>' per Allow entry of `path`.
    SIDs, not names: group names are translated on a Thai or German Windows."""
    lit = path.replace("'", "''")
    script = ("$a = Get-Acl -LiteralPath '%s'; foreach ($r in $a.Access) { "
              "if ($r.AccessControlType -eq 'Allow') { "
              "try { $s = $r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } "
              "catch { $s = '' }; '{0} {1}' -f $s, [int]$r.FileSystemRights } }" % lit)
    return ['powershell', '-NoProfile', '-NonInteractive', '-Command', script]


def broad_writers(acl_lines):
    """Which of Users / Authenticated Users / Everyone may write, from the
    output of acl_ps_command (pure: unit-tested)."""
    names = {SID_USERS.lstrip('*'): 'Users', SID_AUTH_USERS: 'Authenticated Users',
             SID_EVERYONE: 'Everyone'}
    found = []
    for line in acl_lines.splitlines():
        parts = line.split()
        if len(parts) != 2 or parts[0] not in names:
            continue
        try:
            rights = int(parts[1])
        except ValueError:
            continue
        if rights & _WRITE_BITS and names[parts[0]] not in found:
            found.append(names[parts[0]])
    return found


def base_python_writable():
    """(folder, [groups]) when ordinary users may write the base Python that
    .venv loads its DLL and standard library from; (folder, []) when not or
    unknown. Windows only."""
    home = venv_base_home()
    if not IS_WINDOWS or not home or not os.path.isdir(home):
        return home, []
    code, out = _run(acl_ps_command(home), timeout=60)
    return home, broad_writers(out) if code == 0 else []


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

