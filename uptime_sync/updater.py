"""Self-update: download -> verify -> stage (engine), swap -> verify -> keep
or roll back (supervisor).

Where the zip may come from. The server decides WHAT to install (version +
SHA-256, in a signed heartbeat reply); the bytes come from either
  * GitHub: https://github.com/<update.github_repo>/releases/download/
    v<ver>/uptime-sync-v<ver>.zip -- the repo is public, so no token on
    any box. Redirect hops may go to https *.githubusercontent.com only.
  * the reporting server itself (uptime-monitor's dist/download.php, the
    3.x path): same host as remote.url, an https server cannot hand out
    http, and the api_key + time + signature are appended only after the
    URL passed that check.
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
import subprocess
import time
import zipfile
from urllib.parse import urljoin, urlparse

import requests

from . import __version__, paths
from .signing import sign
from .util import atomic_write_json, is_newer, read_json, redact, remove_quietly, sha256_file

log = logging.getLogger('update')

EXIT_UPDATE = 3       # engine -> supervisor: a verified update is staged
EXIT_RESTART = 4      # engine -> supervisor: restart requested by the server

MIN_FREE_BYTES = 100 * 1024 * 1024
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

def _open(url, kind, remote_url):
    hop = url
    for _ in range(MAX_REDIRECTS + 1):
        r = requests.get(hop, timeout=60, stream=True, allow_redirects=False,
                         headers={'User-Agent': 'UptimeSync/%s' % __version__})
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
    repo = settings.get('update', {}).get('github_repo', '')
    url, kind = resolve(url, remote.get('url', ''), repo, version)
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
            r = _open(url, kind, remote.get('url', ''))
            size = 0
            with open(part, 'wb') as f:
                for chunk in r.iter_content(65536):
                    size += len(chunk)
                    if size > MAX_ZIP_BYTES:
                        raise UpdateRefused('download is larger than %d MB' % (MAX_ZIP_BYTES // 2 ** 20))
                    f.write(chunk)
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
                                           'staged_at': _now()})
    remove_quietly(paths.UPDATE_PENDING)
    return True


# -- swap / rollback (runs in the supervisor) --------------------------------

def _now():
    return datetime.datetime.now().astimezone().isoformat(timespec='seconds')


def state():
    return read_json(paths.UPDATE_STATE_FILE, {}) or {}


def set_state(**fields):
    s = state()
    s.update(fields)
    atomic_write_json(paths.UPDATE_STATE_FILE, s)
    return s


def _move_shipped(src_root, dst_root):
    """Move every SHIPPED item present in src_root into dst_root.
    Returns the names moved (for undo)."""
    moved = []
    os.makedirs(dst_root, exist_ok=True)
    for name in paths.SHIPPED:
        src = os.path.join(src_root, name)
        if os.path.lexists(src):
            os.replace(src, os.path.join(dst_root, name))
            moved.append(name)
    return moved


def _pip_install(root):
    # .venv's console python (not pythonw: pip wants a real stdout), so
    # packages land in .venv and never in the system Python.
    cmd = [paths.venv_python(), '-m', 'pip', 'install', '--disable-pip-version-check',
           '-r', os.path.join(root, 'requirements.txt')]
    flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          stdin=subprocess.DEVNULL, timeout=900, creationflags=flags)
    return proc.returncode == 0, proc.stdout.decode('utf-8', 'replace')[-2000:]


def apply():
    """Swap the staged build in. Returns the new version, or None if there
    was nothing (valid) to apply. Leaves the old code in backups/."""
    ready = read_json(paths.UPDATE_READY, None)
    remove_quietly(paths.UPDATE_READY)
    if not isinstance(ready, dict) or not ready.get('version'):
        return None
    version = ready['version']
    try:
        validate_staging(version)
    except UpdateRefused as e:
        log.error('[UPDATE] Not applying v%s: %s', version, e)
        set_state(status='Failed', version=version, time=_now(), detail=str(e))
        return None

    old_req = _read(os.path.join(paths.ROOT, 'requirements.txt'))
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    backup = os.path.join(paths.BACKUP_DIR, 'v%s-%s' % (__version__, stamp))
    log.info('[UPDATE] Applying v%s (backup of v%s in %s)', version, __version__, backup)
    moved_in = []
    pip_ran = False
    try:
        _move_shipped(paths.ROOT, backup)
        moved_in = _move_shipped(paths.STAGING_DIR, paths.ROOT)
        if _read(os.path.join(paths.ROOT, 'requirements.txt')) != old_req:
            log.info('[UPDATE] requirements.txt changed - running pip install')
            pip_ran = True
            ok, out = _pip_install(paths.ROOT)
            if not ok:
                last = out.strip().splitlines()[-1] if out.strip() else ''
                raise RuntimeError('pip install failed: ' + last)
    except Exception as e:
        log.error('[UPDATE] Swap to v%s failed, restoring v%s: %s', version, __version__, e)
        for name in moved_in:
            try:
                p = os.path.join(paths.ROOT, name)
                shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
            except OSError:
                pass
        _move_shipped(backup, paths.ROOT)
        if pip_ran:
            # pip may have upgraded part of the venv before it failed.
            ok, _ = _pip_install(paths.ROOT)
            log.log(logging.INFO if ok else logging.ERROR,
                    '[UPDATE] Reinstalled the v%s requirements: %s', __version__, 'ok' if ok else 'FAILED')
        set_state(status='Failed', version=version, time=_now(), detail=str(e))
        return None
    shutil.rmtree(paths.STAGING_DIR, ignore_errors=True)
    set_state(status='Applied', version=version, previous=__version__, backup=backup,
              time=_now(), applied_at=time.time(), crashes=0, detail='')
    _prune_backups()
    return version


def rollback(reason):
    """Put the backup of the previous version back. True on success."""
    s = state()
    backup = s.get('backup')
    if not backup or not os.path.isdir(backup):
        log.error('[UPDATE] Cannot roll back: no backup recorded')
        return False
    failed = s.get('version')
    trash = os.path.join(paths.BACKUP_DIR, 'failed-v%s-%s' % (failed, int(time.time())))
    _move_shipped(paths.ROOT, trash)
    _move_shipped(backup, paths.ROOT)
    if _read(os.path.join(trash, 'requirements.txt')) != _read(os.path.join(paths.ROOT, 'requirements.txt')):
        ok, _ = _pip_install(paths.ROOT)
        log.log(logging.INFO if ok else logging.ERROR,
                '[UPDATE] Reinstalled the v%s requirements: %s', s.get('previous'), 'ok' if ok else 'FAILED')
    shutil.rmtree(backup, ignore_errors=True)
    shutil.rmtree(trash, ignore_errors=True)
    set_state(status='Failed', version=failed, time=_now(), detail=reason, backup='',
              rolled_back_to=s.get('previous'))
    log.error('[UPDATE] Rolled back from v%s to v%s: %s', failed, s.get('previous'), reason)
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
    if status == 'Applied':
        status = 'Installing'
    return (status or 'No update history', s.get('time', ''), s.get('version', ''))


def write_pending(version, url, sha256, mode):
    atomic_write_json(paths.UPDATE_PENDING, {
        'version': version, 'url': url, 'sha256': sha256, 'mode': mode, 'detected_at': _now()})


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
