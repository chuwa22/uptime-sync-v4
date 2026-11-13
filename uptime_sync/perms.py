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
import stat
import sys

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

def _posix_executables():
    """Give paths.EXECUTABLE back its x bit (wherever it is readable) when
    an update or an unzip tool dropped it (4.0.13). Not a security setting,
    so a failure is not a problem to report."""
    for name in paths.EXECUTABLE:
        path = os.path.join(paths.ROOT, name)
        try:
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            mode = os.stat(path).st_mode & 0o777
            want = mode | ((mode & 0o444) >> 2)
            if want != mode:
                os.chmod(path, want)
        except OSError:
            pass


def _posix_harden():
    _posix_executables()
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
            with open(ACL_STAMP, 'r', encoding='ascii') as f:
                stamp = f.read().strip()
        except (OSError, ValueError):   # a torn stamp: just apply the ACL again
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
    except (OSError, ValueError):
        pass
    return ''


def acl_ps_command(path):
    """PowerShell that prints '<SID> <rights>' per Allow entry of `path`.
    SIDs, not names: group names are translated on a Thai or German Windows."""
    lit = path.replace("'", "''")
    script = ("$a = Get-Acl -LiteralPath '%s'; foreach ($r in $a.Access) { "
              "if ($r.AccessControlType -eq 'Allow') { "
              "try { $s = $r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } "
              "catch { $s = '' }; '{0} {1}' -f $s, [int]$r.FileSystemRights } }; "
              "try { 'OWNER {0}' -f $a.GetOwner([System.Security.Principal.SecurityIdentifier]).Value } "
              "catch { }" % lit)
    return ['powershell', '-NoProfile', '-NonInteractive', '-Command', script]


# May write the base Python without that being a way up to SYSTEM.
_TRUSTED_SIDS = frozenset((SID_SYSTEM.lstrip('*'), SID_ADMINS.lstrip('*'),
                           'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464',  # TrustedInstaller
                           'S-1-3-0'))   # CREATOR OWNER: a template for new files, not a grant


def broad_writers(acl_lines):
    """Who other than SYSTEM / Administrators / TrustedInstaller may write
    (or, as the owner, may give itself the right to write), from the output
    of acl_ps_command (pure: unit-tested). A per-user Python install is
    owned and writable by that one user: it is not a broad group, but the
    SYSTEM task loading it lets that user run code as SYSTEM all the same."""
    names = {SID_USERS.lstrip('*'): 'Users', SID_AUTH_USERS: 'Authenticated Users',
             SID_EVERYONE: 'Everyone'}
    found = []
    for line in acl_lines.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        if parts[0] == 'OWNER':
            sid = parts[1]
            if sid not in _TRUSTED_SIDS:
                label = 'its owner %s' % names.get(sid, sid)
                if label not in found:
                    found.append(label)
            continue
        if parts[0] in _TRUSTED_SIDS or not parts[0].startswith('S-1-'):
            continue
        try:
            rights = int(parts[1])
        except ValueError:
            continue
        label = names.get(parts[0], parts[0])
        if rights & _WRITE_BITS and label not in found:
            found.append(label)
    return found


def under_user_profile(path, system_drive=None):
    """True for a folder inside C:\\Users\\<name> (a per-user Python install)."""
    drive = system_drive or os.environ.get('SystemDrive') or 'C:'
    profiles = os.path.normcase(os.path.join(drive + os.sep, 'Users')) + os.sep
    return os.path.normcase(os.path.abspath(path)).startswith(profiles)


def base_python_writable():
    """(folder, [groups]) when ordinary users may write the base Python that
    .venv loads its DLL and standard library from; (folder, []) when not or
    unknown. Windows only."""
    home = venv_base_home()
    if not IS_WINDOWS or not home or not os.path.isdir(home):
        return home, []
    code, out = _run(acl_ps_command(home), timeout=60)
    found = broad_writers(out) if code == 0 else []
    if under_user_profile(home) and not found:
        found = ['the user whose profile it is in (a per-user Python install)']
    return home, found


# -- a service that runs as root (POSIX, 4.3.3) ------------------------------------

# Groups whose write access is no way up to root: root's own group, and on
# macOS `admin` (gid 80), whose members may sudo already (the python.org
# installer leaves its framework writable by admin).
ROOT_GIDS = (0, 80) if sys.platform == 'darwin' else (0,)
ROOT_SCAN_LIMIT = 200
_lstat = os.lstat       # the tests swap it to play root


def _account(uid):
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError):
        return 'uid %d' % uid


def _group(gid):
    try:
        import grp
        return grp.getgrgid(gid).gr_name
    except (ImportError, KeyError):
        return 'gid %d' % gid


def root_unsafe_reason(mode, uid, gid, ancestor=False):
    """Why a user other than root could change this path, '' when none can
    (pure: unit-tested). ancestor: a folder above the ones the agent runs
    from, where a sticky bit (as on /tmp) stops others renaming what root
    owns inside. A symlink's own mode means nothing: its folder decides."""
    if stat.S_ISLNK(mode):
        return ''
    if uid != 0:
        return 'owned by %s' % _account(uid)
    sticky = ancestor and stat.S_ISDIR(mode) and mode & stat.S_ISVTX
    if mode & 0o002 and not sticky:
        return 'writable by everyone'
    if mode & 0o020 and gid not in ROOT_GIDS and not sticky:
        return 'writable by group %s' % _group(gid)
    return ''


def _ancestors(path):
    """The folders above `path` up to /, for both the path as given and
    the one its symlinks resolve to."""
    out = []
    for p in (os.path.abspath(path), os.path.realpath(path)):
        while os.path.dirname(p) != p:
            p = os.path.dirname(p)
            if p not in out:
                out.append(p)
    return out


def root_service_unsafe():
    """What a user other than root could change, for an agent that runs as
    root: [(path, reason, where)], where is 'folder' (the install folder or
    inside it), 'above' (a folder above it) or 'python' (the base Python
    .venv runs on). Only the topmost path of a subtree is listed. Reads
    only, never changes a mode. POSIX; [] on Windows.

    Any of these lets that user run code as root: edit a .py file, swap
    .venv's packages or the base Python's standard library, rename the
    install folder and put another in its place, or edit data/settings.json
    (the update source)."""
    if IS_WINDOWS:
        return []
    found = []
    seen = set()

    def ok(path, where, ancestor=False):
        if path in seen:
            return True
        seen.add(path)
        try:
            st = _lstat(path)
        except OSError:
            return True
        why = root_unsafe_reason(st.st_mode, st.st_uid, st.st_gid, ancestor)
        if why and len(found) < ROOT_SCAN_LIMIT:
            found.append((path, why, where))
        return not why

    def tree(top, where):
        if not ok(top, where) or os.path.islink(top) or not os.path.isdir(top):
            return
        for base, dirs, files in os.walk(top):
            for name in files:
                ok(os.path.join(base, name), where)
            dirs[:] = [d for d in dirs if ok(os.path.join(base, d), where)]

    root = paths.ROOT
    for d in _ancestors(root):
        ok(d, 'above', ancestor=True)
    if ok(root, 'folder'):
        for name in paths.SHIPPED:
            tree(os.path.join(root, name), 'folder')
        for d in (paths.VENV_DIR, paths.DATA_DIR, paths.RUN_DIR):
            tree(d, 'folder')
    home = venv_base_home()
    if home and os.path.isdir(home):
        stdlib = os.path.dirname(os.__file__)     # the base Python's, even in .venv
        for p in (os.path.realpath(home), os.path.realpath(paths.venv_python()), stdlib):
            ok(p, 'python')
        for p in (home, stdlib):
            for d in _ancestors(p):
                ok(d, 'python', ancestor=True)
    return found


def root_fix_lines(found, root):
    """How to fix what root_service_unsafe() found, as text lines (pure:
    unit-tested). Only advice: nothing here changes a file."""
    where = set(w for _, _, w in found)
    lines = ['Either run the agent as an ordinary user: give the folder to that user, then '
             'from that account run `sudo python3 main.py install` (the service then runs '
             'as that user), or keep root and let only root change them:']
    if 'folder' in where:
        lines.append('  sudo chown -R root "%s" && sudo chmod -R go-w "%s"' % (root, root))
    if 'above' in where:
        lines.append('  move the install folder to one only root can change (e.g. /opt/uptime-sync), '
                     'or fix the folders above it: sudo chown root DIR && sudo chmod go-w DIR')
    if 'python' in where:
        lines.append('  rebuild .venv on a Python only root can change (e.g. /usr/bin/python3): '
                     'sudo /usr/bin/python3 main.py install --recreate')
    return lines


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

