"""Self-update: download -> verify -> stage (engine), swap -> verify -> keep
or roll back (supervisor).

Where the zip may come from. The server decides WHAT to install (version +
SHA-256, in a signed heartbeat reply); the bytes come from either
  * GitHub: https://github.com/<update.github_repo>/releases/download/
    v<ver>/uptime-sync-v<ver>.zip -- the repo is public, so no token on
    any box. Redirect hops may go to https *.githubusercontent.com only.
  * the reporting server itself (uptime-monitor's dist/download.php, the
    3.x path) -- OFF unless update.allow_server_download is true in
    data/settings.json (edited by hand; the web UI cannot set it). Whoever
    can change remote.url in the web UI could otherwise point the agent at
    a server of their own that offers its own zip with its own SHA-256:
    code execution as the agent's service account. With it on: same host
    as remote.url, an https server cannot hand out http, and the api_key +
    time + signature are appended only after the URL passed that check.
Any other URL is refused. The SHA-256 is never optional: no hash, no install.

Staging: the zip is extracted into update_staging/ (outside everything the
swap renames) and must contain VERSION == the offered version plus
uptime_sync/__init__.py. The engine then exits with EXIT_UPDATE and the
supervisor -- which is not running the code being replaced -- swaps.
"""

import datetime
import logging
import os
import shutil
import sys
import time
import zipfile
from urllib.parse import urljoin, urlparse

from . import __version__, paths, procs
from .signing import sign
from .util import (MIN_FREE_BYTES, BodyTooLarge, atomic_write_json, http_session, is_newer, is_version,
                   iso_now, iter_body, read_json, redact, remove_quietly, server_tls_verify, sha256_file,
                   active_server_url)

log = logging.getLogger('update')

EXIT_UPDATE = 3       # engine -> supervisor: a verified update is staged
EXIT_RESTART = 4      # engine -> supervisor: restart requested by the server
EXIT_STUCK = 5        # engine -> supervisor: a check hung for 3 cycles; restart me

MAX_ZIP_BYTES = 200 * 1024 * 1024
MAX_REDIRECTS = 5
KEEP_BACKUPS = 3
ZIP_NAME = 'uptime-sync-v%s.zip'


class UpdateRefused(Exception):
    """Policy refusal -- never retried."""


# -- URL policy -------------------------------------------------------------

def github_url(repo, version):
    return 'https://github.com/%s/releases/download/v%s/%s' % (repo, version, ZIP_NAME % version)


def _bad_chars(url):
    return any(c == '\\' or c.isspace() or ord(c) < 32 for c in url)


def resolve(url, remote_url, repo, version):
    """(absolute_url, 'github' | 'server') or raise UpdateRefused."""
    if not isinstance(url, str) or not url.strip():
        raise UpdateRefused('the server sent no update_url')
    url = url.strip()
    if _bad_chars(url):
        raise UpdateRefused('update_url contains backslashes, whitespace or control characters')
    server = urlparse((remote_url or '').strip())
    target = urlparse(urljoin(remote_url or '', url))
    if target.username is not None or target.password is not None or '@' in target.netloc:
        raise UpdateRefused('credentials in the URL are not allowed')
    if target.scheme == 'https' and (target.hostname or '').lower() == 'github.com':
        if not repo or target.geturl() != github_url(repo, version):
            raise UpdateRefused('GitHub URL is not the v%s release asset of %s' % (version, repo))
        return target.geturl(), 'github'
    if server.scheme not in ('http', 'https') or not server.hostname:
        raise UpdateRefused('remote.url is not an http(s) URL')
    if target.scheme not in ('http', 'https'):
        raise UpdateRefused('scheme "%s" is not allowed' % target.scheme)
    if (target.hostname or '').lower() != server.hostname.lower():
        raise UpdateRefused('host "%s" is neither GitHub nor the reporting server "%s"'
                            % (target.hostname, server.hostname))
    if server.scheme == 'https' and target.scheme != 'https':
        raise UpdateRefused('plain-http download offered by an https reporting server')
    return target.geturl(), 'server'


def check_redirect(location, current, kind, remote_url):
    nxt = urljoin(current, location or '')
    if _bad_chars(nxt):
        raise UpdateRefused('redirect target contains illegal characters')
    u = urlparse(nxt)
    host = (u.hostname or '').lower()
    if u.username is not None or u.password is not None:
        raise UpdateRefused('credentials in redirect URL')
    if kind == 'github':
        if u.scheme == 'https' and (host == 'github.com' or host.endswith('.githubusercontent.com')):
            return nxt
        raise UpdateRefused('GitHub redirected to "%s"' % host)
    server = urlparse(remote_url)
    if host != (server.hostname or '').lower():
        raise UpdateRefused('redirect to another host "%s"' % host)
    if (urlparse(current).scheme == 'https' or server.scheme == 'https') and u.scheme != 'https':
        raise UpdateRefused('redirect downgrades to http')
    return nxt


def signed_server_url(url, api_key, secret_key):
    t = str(int(time.time()))
    sig = sign(secret_key, ('%s|%s' % (api_key, t)).encode('utf-8'))
    sep = '&' if '?' in url else '?'
    return '%s%sapi_key=%s&t=%s&signature=%s' % (url, sep, api_key, t, sig)


# -- download + stage (runs in the engine) ----------------------------------

def _open(url, kind, remote_url, verify=True):
    hop = url
    for _ in range(MAX_REDIRECTS + 1):
        # verify=False only for a Local reporting server (server_tls_verify);
        # GitHub is always checked.
        # http_session(): requests.get() would read a redirect's body
        r = http_session().get(hop, timeout=60, stream=True, allow_redirects=False,
                               headers={'Accept-Encoding': 'identity'},
                               verify=verify if kind == 'server' else True)
        if not r.is_redirect:
            r.raise_for_status()
            return r
        location = r.headers.get('Location', '')
        r.close()
        hop = check_redirect(location, hop, kind, remote_url)
    raise UpdateRefused('more than %d redirects' % MAX_REDIRECTS)


def _safe_extract(zip_path, dest):
    if os.path.isdir(dest):
        shutil.rmtree(dest)
    os.makedirs(dest)
    root = os.path.realpath(dest)
    total = 0
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            name = info.filename.replace('\\', '/')
            target = os.path.realpath(os.path.join(dest, name))
            if not (target == root or target.startswith(root + os.sep)):
                raise UpdateRefused('zip entry escapes the staging folder: %s' % name)
            total += info.file_size
            if total > MAX_ZIP_BYTES * 3:
                raise UpdateRefused('zip expands to more than %d MB' % (MAX_ZIP_BYTES * 3 // 2 ** 20))
        z.extractall(dest)


def validate_staging(version):
    """Raise UpdateRefused unless update_staging/ holds a v<version> build."""
    vfile = os.path.join(paths.STAGING_DIR, 'VERSION')
    try:
        with open(vfile, 'r', encoding='utf-8') as f:
            staged = f.readline().strip()
    except OSError:
        raise UpdateRefused('staged build has no VERSION file')
    except ValueError:
        raise UpdateRefused('staged build has an unreadable VERSION file')
    if staged != version:
        raise UpdateRefused('staged build is v%s, expected v%s' % (staged, version))
    for required in (os.path.join('uptime_sync', '__init__.py'), 'main.py',
                     os.path.join('config', 'defaults.json')):
        if not os.path.isfile(os.path.join(paths.STAGING_DIR, required)):
            raise UpdateRefused('staged build is missing %s' % required)


def download_and_stage(url, version, sha256, settings):
    """Fetch, verify and extract v<version>. Returns True when staged.
    Raises UpdateRefused on a policy refusal; other errors propagate."""
    sha256 = (sha256 or '').strip().lower()
    if len(sha256) != 64 or any(c not in '0123456789abcdef' for c in sha256):
        raise UpdateRefused('the server sent no valid update_sha256 -- refusing to install '
                            'a zip without integrity proof')
    if not is_newer(version, __version__):
        raise UpdateRefused('v%s is not newer than v%s' % (version, __version__))
    remote = settings.get('remote', {})
    server_url = active_server_url(remote)
    repo = settings.get('update', {}).get('github_repo', '')
    url, kind = resolve(url, server_url, repo, version)
    if kind == 'server' and settings.get('update', {}).get('allow_server_download') is not True:
        raise UpdateRefused('the server offered its own download, but only the GitHub release '
                            'asset is accepted (set update.allow_server_download in '
                            'data/settings.json to allow the reporting server)')
    if kind == 'server':
        if not (remote.get('api_key') and remote.get('secret_key')):
            raise UpdateRefused('downloading from the server needs api_key and secret_key')
        url = signed_server_url(url, remote['api_key'], remote['secret_key'])

    os.makedirs(paths.DOWNLOAD_DIR, exist_ok=True)
    if shutil.disk_usage(paths.DOWNLOAD_DIR).free < MIN_FREE_BYTES:
        raise RuntimeError('less than %d MB free disk space' % (MIN_FREE_BYTES // 2 ** 20))
    zip_path = os.path.join(paths.DOWNLOAD_DIR, ZIP_NAME % version)
    part = zip_path + '.part'
    log.info('[UPDATE] Downloading v%s from %s', version, redact(url))
    last_error = None
    for attempt in range(3):
        try:
            r = _open(url, kind, server_url, server_tls_verify(remote))
            size = 0
            with open(part, 'wb') as f:
                try:
                    for chunk in iter_body(r, MAX_ZIP_BYTES):
                        size += len(chunk)
                        f.write(chunk)
                except BodyTooLarge:
                    raise UpdateRefused('download is larger than %d MB' % (MAX_ZIP_BYTES // 2 ** 20))
                f.flush()
                os.fsync(f.fileno())
            os.replace(part, zip_path)
            break
        except UpdateRefused:
            remove_quietly(part)
            raise
        except Exception as e:
            remove_quietly(part)
            last_error = e
            log.warning('[UPDATE] Download attempt %d/3 failed: %s', attempt + 1, redact(e))
            time.sleep(5)
    else:
        raise RuntimeError('download failed: %s' % redact(last_error))

    import hmac
    actual = sha256_file(zip_path)
    if not hmac.compare_digest(actual, sha256):
        remove_quietly(zip_path)
        raise UpdateRefused('SHA-256 mismatch: expected %s, got %s' % (sha256, actual))
    log.info('[UPDATE] SHA-256 verified (%s...)', actual[:12])
    try:
        _safe_extract(zip_path, paths.STAGING_DIR)
        validate_staging(version)
    except zipfile.BadZipFile as e:
        raise UpdateRefused('not a zip file: %s' % e)
    finally:
        remove_quietly(zip_path)
    atomic_write_json(paths.UPDATE_READY, {'version': version, 'sha256': actual,
                                           'staged_at': iso_now()})
    remove_quietly(paths.UPDATE_PENDING)
    return True


# -- swap / rollback (runs in the supervisor) --------------------------------

def state():
    return read_json(paths.UPDATE_STATE_FILE, {}) or {}


def set_state(**fields):
    s = state()
    s.update(fields)
    atomic_write_json(paths.UPDATE_STATE_FILE, s)
    return s


# Top-level names an update never moves, whatever the zip holds: site data,
# runtime state, the venv and the staging area itself.
_NEVER_SWAP = frozenset(os.path.basename(d) for d in (
    paths.DATA_DIR, paths.LOG_DIR, paths.RUN_DIR, paths.BACKUP_DIR, paths.STAGING_DIR,
    paths.VENV_DIR)) | {'.git'}


def _swap_names(staged_root):
    """What the staged build installs: its top-level entries (a newer release
    may ship a name this one does not know), never a protected one."""
    try:
        listed = os.listdir(staged_root)
    except OSError:
        listed = []
    return sorted(n for n in listed if n not in _NEVER_SWAP and not n.startswith('.'))


def _remove(path):
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path)
    elif os.path.lexists(path):
        os.remove(path)


def _move(names, src_root, dst_root, done):
    """Move each name present in src_root to dst_root, appending to `done`
    AS IT GOES, so a failure half-way still tells the undo what moved."""
    os.makedirs(dst_root, exist_ok=True)
    for name in names:
        src = os.path.join(src_root, name)
        if os.path.lexists(src):
            dst = os.path.join(dst_root, name)
            if os.path.lexists(dst):
                _remove(dst)
            os.replace(src, dst)
            done.append(name)


def _undo(moved_out, out_dir, moved_in, in_dir):
    """Reverse a swap: put what came in back into in_dir, then what went out
    back into ROOT. Never raises -- every step is tried; returns the failures,
    each already logged CRITICAL (the install may be half old, half new)."""
    problems = []
    for name in reversed(moved_in):
        try:
            _move([name], paths.ROOT, in_dir, [])
        except OSError as e:
            problems.append('%s: %s' % (name, e))
    for name in reversed(moved_out):
        try:
            _move([name], out_dir, paths.ROOT, [])
        except OSError as e:
            problems.append('%s: %s' % (name, e))
    for p in problems:
        log.critical('[UPDATE] Could not restore %s -- copy it back from %s by hand', p, out_dir)
    return problems


# What the OS autostart needs to reach recover_interrupted(): main.py, and
# the package it imports. A kill while either is out of ROOT leaves an
# install nothing can start, so they leave last and come back first (4.0.11).
# Launcher.bat goes with them: it is what tells the user, in that state,
# where the old code is.
_BOOT = ('uptime_sync', 'main.py', 'Launcher.bat')


def _boot_last(names):
    """names with _BOOT at the end (Launcher.bat the very last): the order
    for moving OUT of ROOT. reversed() of it is the order for moving back."""
    return [n for n in names if n not in _BOOT] + [n for n in _BOOT if n in names]


def _boot_first(names):
    """names with Launcher.bat, main.py, then uptime_sync first: the order
    for moving IN."""
    return list(reversed([n for n in _BOOT if n in names])) + [n for n in names if n not in _BOOT]


def _swap(names_out, out_dir, in_dir, names_in):
    """ROOT/names_out -> out_dir, then in_dir/names_in -> ROOT. All or
    nothing: on any error the moves are undone and the error re-raised.
    Every move out still precedes every move in (recovery relies on it);
    within each, the _BOOT names are out for as few moves as possible."""
    moved_out, moved_in = [], []
    try:
        _move(_boot_last(names_out), paths.ROOT, out_dir, moved_out)
        _move(_boot_first(names_in), in_dir, paths.ROOT, moved_in)
    except Exception:
        if not _undo(moved_out, out_dir, moved_in, in_dir):
            _drop_failed_attempt(out_dir)
        raise
    return moved_out, moved_in


def _drop_failed_attempt(backup):
    """After a clean undo: the backup folder is empty again and the staged
    build is known bad. An empty v<ver>-<ts> folder would count towards
    KEEP_BACKUPS and, after a few failed updates, push real backups out.
    Only called when the undo restored everything -- otherwise both stay
    for a by-hand recovery."""
    try:
        os.rmdir(backup)
    except OSError:
        pass
    shutil.rmtree(paths.STAGING_DIR, ignore_errors=True)


_SMOKE = ('import sys; sys.path.insert(0, sys.argv[1]); '
          'import uptime_sync, uptime_sync.cli, uptime_sync.supervisor, uptime_sync.engine, '
          'uptime_sync.web; print(uptime_sync.__version__)')


def _smoke_test(version):
    """Import the swapped-in code with the venv interpreter, in a fresh
    process, before it is trusted. A release that cannot even import (a
    missing package, a syntax error under Python 3.8) is caught here and
    put back at once, instead of crash-looping until the rollback counter
    trips. (ok, detail)."""
    py = paths.venv_python()
    if not os.path.isfile(py):
        py = sys.executable
    code, raw, error = procs.run([py, '-I', '-c', _SMOKE, paths.ROOT], 120, cwd=paths.ROOT)
    if code is None:
        return False, 'could not run %s: %s' % (py, error)
    out = raw.decode('utf-8', 'replace').strip()
    if code != 0:
        return False, out.splitlines()[-1] if out else 'exit %d' % code
    if out.splitlines()[-1:] != [version]:
        return False, 'the new code reports version %r' % out[-40:]
    return True, ''


def _pip_install(root):
    # .venv's console python (not pythonw: pip wants a real stdout), so
    # packages land in .venv and never in the system Python.
    cmd = [paths.venv_python(), '-m', 'pip', 'install', '--disable-pip-version-check',
           '-r', os.path.join(root, 'requirements.txt')]
    code, raw, error = procs.run(cmd, 900)
    return code == 0, (raw.decode('utf-8', 'replace') + error)[-2000:]


def apply():
    """Swap the staged build in. Returns the new version, or None if there
    was nothing (valid) to apply. Leaves the old code in backups/."""
    ready = read_json(paths.UPDATE_READY, None)
    remove_quietly(paths.UPDATE_READY)
    if not isinstance(ready, dict) or not is_version(ready.get('version')):
        return None
    version = ready['version']
    try:
        validate_staging(version)
    except UpdateRefused as e:
        log.error('[UPDATE] Not applying v%s: %s', version, e)
        set_state(status='Failed', version=version, time=iso_now(), detail=str(e))
        return None

    old_req = _read(os.path.join(paths.ROOT, 'requirements.txt'))
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    backup = os.path.join(paths.BACKUP_DIR, 'v%s-%s' % (__version__, stamp))
    names_in = _swap_names(paths.STAGING_DIR)
    names_out = sorted(set(paths.SHIPPED) | set(names_in))
    log.info('[UPDATE] Applying v%s (backup of v%s in %s)', version, __version__, backup)
    # Written BEFORE anything moves: a power cut from here until 'Applied'
    # leaves this record, and recover_interrupted() puts the old code back
    # on the next start instead of running a half-swapped install.
    try:
        set_state(status='Applying', version=version, previous=__version__, backup=backup,
                  installed=names_in, time=iso_now(), crashes=0, detail='',
                  rolling_back=None, pip_pending=False, leftovers=[],
                  requirements_changed=_read(os.path.join(paths.STAGING_DIR, 'requirements.txt')) != old_req)
    except OSError as e:
        log.error('[UPDATE] Cannot record the update state, v%s kept: %s', __version__, e)
        return None
    try:
        moved_out, moved_in = _swap(names_out, backup, paths.STAGING_DIR, names_in)
    except Exception as e:
        log.error('[UPDATE] Swap to v%s failed, v%s kept: %s', version, __version__, e)
        set_state(status='Failed', version=version, time=iso_now(), detail='swap failed: %s' % e)
        return None
    pip_ran = False
    try:
        if _read(os.path.join(paths.ROOT, 'requirements.txt')) != old_req:
            log.info('[UPDATE] requirements.txt changed - running pip install')
            pip_ran = True
            ok, out = _pip_install(paths.ROOT)
            if not ok:
                last = out.strip().splitlines()[-1] if out.strip() else ''
                raise RuntimeError('pip install failed: ' + last)
        ok, detail = _smoke_test(version)
        if not ok:
            raise RuntimeError('the new code does not start: ' + detail)
    except Exception as e:
        log.error('[UPDATE] v%s failed after the swap, restoring v%s: %s', version, __version__, e)
        if not _undo(moved_out, backup, moved_in, paths.STAGING_DIR):
            _drop_failed_attempt(backup)
        if pip_ran:
            # pip may have upgraded part of the venv before it failed.
            ok, _ = _pip_install(paths.ROOT)
            log.log(logging.INFO if ok else logging.ERROR,
                    '[UPDATE] Reinstalled the v%s requirements: %s', __version__, 'ok' if ok else 'FAILED')
        set_state(status='Failed', version=version, time=iso_now(), detail=str(e))
        return None
    set_state(status='Applied', version=version, previous=__version__, backup=backup,
              installed=moved_in, time=iso_now(), applied_at=time.time(), crashes=0, detail='',
              supervisor_starts=0)
    shutil.rmtree(paths.STAGING_DIR, ignore_errors=True)
    _prune_backups()
    return version


def recover_interrupted():
    """Finish an apply() that died half-way (power cut, killed supervisor):
    the state still says 'Applying'. Put the previous version back exactly
    as it was. Returns True when files were moved (the caller re-executes
    itself: the code it is running may have just been replaced).

    Also finishes a restore that was cut off after its swap: the pip
    install (`pip_pending`) and the clean-up (`leftovers`) it recorded. A
    restore writes its final state right after the swap, BEFORE pip, so a
    power cut during pip no longer makes the next start restore again from
    a backup that is already empty (4.0.11)."""
    s = state()
    if s.get('status') != 'Applying':
        if s.get('pip_pending') or s.get('leftovers'):
            _finish_restore(s.get('rolled_back_to') or __version__, bool(s.get('pip_pending')),
                            s.get('leftovers') or [])
        return False
    version, previous, backup = s.get('version'), s.get('previous'), s.get('backup') or ''
    log.critical('[UPDATE] The install of v%s was interrupted - restoring v%s', version, previous)
    names_in = [n for n in (s.get('installed') or []) if n not in _NEVER_SWAP]
    if not os.path.isdir(backup):
        # apply() creates the backup folder with its first move: nothing moved.
        set_state(status='Failed', time=iso_now(), detail='interrupted before the swap started')
        shutil.rmtree(paths.STAGING_DIR, ignore_errors=True)
        return False
    went_out = _swap_names(backup)
    rb = _resume_record(s, backup)
    if rb:
        # This restore was itself cut off. Its moves out all precede its
        # moves in: once a backup name has come back, every new name is in
        # rb['trash'] already and ROOT holds old code -- only the rest of
        # the backup still moves.
        trash = rb['trash']
        names_out = [] if set(rb['back']) - set(went_out) else list(rb['out'])
    else:
        # Every move out of apply() precedes every move in, so a name that
        # has left the staging folder is new code in ROOT; everything in the
        # backup is old code.
        staged = set(_swap_names(paths.STAGING_DIR)) if os.path.isdir(paths.STAGING_DIR) else set()
        came_in = [n for n in names_in if n not in staged]
        if came_in and not went_out:
            # Nothing left to put back, yet new names are in ROOT: a restore
            # finished its swap but could not record it. Swapping now would
            # move the restored old code out and leave ROOT empty. Trust the
            # files only if VERSION says they are the old ones.
            if _installed_version() != previous:
                log.critical('[UPDATE] Cannot restore v%s: %s is empty -- the files are left as they are',
                             previous, backup)
                set_state(status='RollbackFailed', time=iso_now(),
                          detail='interrupted install; the backup folder is empty')
                return True
            came_in = []
        trash = os.path.join(paths.BACKUP_DIR, 'interrupted-v%s-%s' % (version, int(time.time())))
        names_out = sorted(set(came_in) | set(went_out))
        _save_record(backup, trash, went_out, names_out)
    try:
        _swap(names_out, trash, backup, went_out)
    except Exception as e:
        log.critical('[UPDATE] Could not restore v%s: %s -- copy it back from %s by hand',
                     previous, e, backup)
        set_state(status='RollbackFailed', time=iso_now(),
                  detail='interrupted install; restore failed: %s' % e)
        return True
    _restored(version, previous, 'install was interrupted; v%s restored' % previous,
              bool(s.get('requirements_changed')), [trash, backup, paths.STAGING_DIR])
    log.error('[UPDATE] v%s restored after the interrupted install of v%s', previous, version)
    return True


def _installed_version():
    """First line of ROOT/VERSION as it is on disk now ('' if unreadable)."""
    try:
        with open(os.path.join(paths.ROOT, 'VERSION'), 'r', encoding='utf-8') as f:
            return f.readline().strip()
    except (OSError, ValueError):
        return ''


def _resume_record(s, backup):
    """The `rolling_back` record of a restore from THIS backup that was cut
    off, or None. A record for another backup is stale and never used."""
    rb = s.get('rolling_back')
    if (isinstance(rb, dict) and rb.get('backup') == backup and isinstance(rb.get('trash'), str)
            and rb['trash'] and isinstance(rb.get('back'), list) and isinstance(rb.get('out'), list)):
        return rb
    return None


def _save_record(backup, trash, back, out):
    """Written before a restore's swap, so a run cut off half-way can be
    finished by the next one without moving restored code out again."""
    try:
        set_state(rolling_back={'backup': backup, 'trash': trash, 'back': back, 'out': out})
    except OSError as e:
        log.critical('[UPDATE] Could not record the restore before it starts (%s); going on', e)


def _restored(version, previous, detail, pip, leftovers):
    """After a restore's swap: record the final state FIRST, then pip and
    clean-up. If the state cannot be written, the backup and trash stay
    where they are, so the next start finds the record (or an empty backup
    plus VERSION) and finishes without moving files."""
    try:
        set_state(status='Failed', version=version, time=iso_now(), detail=detail, backup='',
                  installed=[], rolled_back_to=previous, rolling_back=None, pip_pending=pip,
                  leftovers=[p for p in leftovers if p])
    except OSError as e:
        log.critical('[UPDATE] v%s is back, but the update state could not be written: %s',
                     previous, e)
        if pip:
            _pip_logged(previous)
        return
    _finish_restore(previous, pip, leftovers)


def _pip_logged(version):
    ok, _ = _pip_install(paths.ROOT)
    log.log(logging.INFO if ok else logging.ERROR,
            '[UPDATE] Reinstalled the v%s requirements: %s', version, 'ok' if ok else 'FAILED')


def _finish_restore(version, pip, leftovers):
    """pip (tried once per record, whatever the result: a box without a
    network must not spend 15 minutes in pip on every start), then the
    folders the restore left: its trash, the emptied backup, staging."""
    if pip:
        _pip_logged(version)
        try:
            set_state(pip_pending=False)
        except OSError:
            pass
    for path in leftovers:
        if path:
            shutil.rmtree(path, ignore_errors=True)
    try:
        set_state(leftovers=[])
    except OSError:
        pass


def rollback(reason):
    """Put the backup of the previous version back. True on success. Never
    raises: on failure the state becomes RollbackFailed, which stops the
    supervisor from trying again on every child start. Safe to run again
    after being cut off at any point (4.0.11): see _resume_record."""
    s = state()
    failed = s.get('version')
    backup = s.get('backup')
    previous = s.get('previous')
    installed = s.get('installed') or paths.SHIPPED
    req_changed = s.get('requirements_changed')
    if req_changed is None and backup:   # an older state does not say
        req_changed = _read(os.path.join(paths.ROOT, 'requirements.txt')) != \
            _read(os.path.join(backup, 'requirements.txt'))
    try:
        if not backup or not os.path.isdir(backup):
            raise RuntimeError('no backup recorded')
        names_back = _swap_names(backup)
        rb = _resume_record(s, backup)
        if rb:
            trash = rb['trash']
            names_out = [] if set(rb['back']) - set(names_back) else list(rb['out'])
            log.warning('[UPDATE] Finishing an interrupted rollback from v%s', failed)
        elif not names_back:
            # Nothing to put back. Moving the installed names out would leave
            # ROOT empty (before 4.0.11 a rollback killed during pip did
            # exactly that on the next start). Done already if VERSION says so.
            if not previous or _installed_version() != previous:
                raise RuntimeError('the backup folder is empty')
            trash, names_out = '', []
        else:
            trash = os.path.join(paths.BACKUP_DIR, 'failed-v%s-%s' % (failed, int(time.time())))
            names_out = sorted(set(installed) | set(names_back))
            _save_record(backup, trash, names_back, names_out)
        if names_out or names_back:
            _swap(names_out, trash, backup, names_back)
    except Exception as e:
        log.critical('[UPDATE] Cannot roll back from v%s: %s -- the agent stays on it', failed, e)
        try:
            set_state(status='RollbackFailed', time=iso_now(), detail='%s; rollback failed: %s' % (reason, e))
        except OSError:
            pass
        return False
    _restored(failed, previous, reason, bool(req_changed), [trash, backup])
    log.error('[UPDATE] Rolled back from v%s to v%s: %s', failed, previous, reason)
    return True


def _prune_backups():
    try:
        dirs = sorted((d for d in os.listdir(paths.BACKUP_DIR) if d.startswith('v')),
                      key=lambda d: os.path.getmtime(os.path.join(paths.BACKUP_DIR, d)))
    except OSError:
        return
    for d in dirs[:-KEEP_BACKUPS]:
        shutil.rmtree(os.path.join(paths.BACKUP_DIR, d), ignore_errors=True)


def _read(path):
    try:
        with open(path, 'rb') as f:
            return f.read()
    except OSError:
        return b''


def heartbeat_fields():
    """(last_update_status, last_update_time, last_update_version) as the
    server expects them ('Success' / 'Failed' free its update slot)."""
    s = state()
    status = s.get('status')
    if status in ('Applied', 'Applying'):
        status = 'Installing'
    elif status == 'RollbackFailed':
        status = 'Failed'   # the server only knows Success / Failed / Installing
    return (status or 'No update history', s.get('time', ''), s.get('version', ''))


def write_pending(version, url, sha256, mode):
    """Record an offered update; no write when it is the same offer again
    (the heartbeat repeats it every minute). True when it wrote, so the
    caller logs a new offer once instead of on every beat."""
    old = read_json(paths.UPDATE_PENDING, None)
    if isinstance(old, dict) and [old.get(k) for k in ('version', 'url', 'sha256', 'mode')] == \
            [version, url, sha256, mode]:
        return False
    atomic_write_json(paths.UPDATE_PENDING, {
        'version': version, 'url': url, 'sha256': sha256, 'mode': mode, 'detected_at': iso_now()})
    return True


def pending():
    p = read_json(paths.UPDATE_PENDING, None)
    if isinstance(p, dict) and is_newer(p.get('version'), __version__):
        return p
    return None


def in_window(start, end, now=None):
    """Is local time inside [start, end) ('HH:MM'); handles overnight windows."""
    now = now or datetime.datetime.now()

    def minutes(text, fallback):
        try:
            h, m = str(text).split(':')
            return int(h) * 60 + int(m)
        except (ValueError, AttributeError):
            return fallback
    s, e = minutes(start, 120), minutes(end, 240)
    n = now.hour * 60 + now.minute
    return s <= n < e if s <= e else (n >= s or n < e)
