"""Small helpers shared by every part of the agent."""

import copy
import datetime
import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import tempfile
import time
from urllib.parse import urlparse

from . import __version__

USER_AGENT = 'UptimeSync/%s' % __version__
# Below this much free space the box reports itself unhealthy, logs.db keeps
# only LOW_DISK_RETENTION_DAYS, and no update is downloaded.
MIN_FREE_BYTES = 200 * 1024 * 1024
CORRUPT_KEEP = 3        # .corrupt-<ts> copies kept per JSON file

log = logging.getLogger('heal')


def atomic_write_text(path, text, private=False):
    """Write a file so a reader sees the old file or the new one, never half.

    temp file in the same directory + fsync + os.replace. Never delete
    first: a crash between delete and rename would leave no file at all,
    and a lost users.json is an admin lockout. private=True makes the file
    owner-only on POSIX (Windows ACLs come from the install directory).
    """
    directory = os.path.dirname(path) or '.'
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.' + os.path.basename(path) + '.', suffix='.tmp', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        if private and os.name != 'nt':
            os.chmod(tmp, 0o600)
        _replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def _replace(src, dst, attempts=5):
    """os.replace, retried on Windows: it fails with a sharing violation
    while another process has `dst` open for a moment (the web reading
    status.json or update_state.json; an antivirus scan)."""
    for i in range(attempts):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if os.name != 'nt' or i == attempts - 1:
                raise
            time.sleep(0.05 * (i + 1))


def atomic_write_json(path, data, private=False, backup=False, compact=False):
    """backup=True first copies the current file to <path>.bak -- only when
    it parses, so a corrupt file never replaces the last good backup.
    compact=True: no indentation (history.json: written often, read by code)."""
    if backup:
        _keep_backup(path)
    if compact:
        text = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
    else:
        text = json.dumps(data, indent=2, ensure_ascii=False)
    atomic_write_text(path, text + '\n', private)


def _keep_backup(path):
    try:
        with open(path, 'r', encoding='utf-8-sig') as f:
            text = f.read()
        json.loads(text)
    except (OSError, ValueError):
        return
    try:
        atomic_write_text(path + '.bak', text, private=True)
    except OSError as e:
        log.warning('Could not back up %s: %s', os.path.basename(path), e)


def read_json(path, default=None, heal=True):
    """Parsed JSON from path; `default` (deep-copied) if it is missing.

    A file that exists but does not parse is not silently treated as
    missing (heal=True): it is moved to <path>.corrupt-<ts>, a CRITICAL line
    is logged, and <path>.bak is restored when it parses. heal=False only
    for files this agent must not move (3.x files being imported, the
    shipped defaults)."""
    try:
        with open(path, 'r', encoding='utf-8-sig') as f:
            text = f.read()
    except OSError:
        return copy.deepcopy(default)
    try:
        return json.loads(text)
    except ValueError as e:
        if not heal:
            return copy.deepcopy(default)
        return _heal(path, default, e)


def corrupt_copies(path):
    """Quarantined <path>.corrupt-<ts> files, oldest first."""
    directory, base = os.path.split(path)
    try:
        names = os.listdir(directory or '.')
    except OSError:
        return []
    return sorted(os.path.join(directory, n) for n in names if n.startswith(base + '.corrupt-'))


def _heal(path, default, err):
    name = os.path.basename(path)
    bad = '%s.corrupt-%s' % (path, time.strftime('%Y%m%d-%H%M%S'))
    try:
        os.replace(path, bad)
    except FileNotFoundError:
        bad = None      # another process healed it a moment ago
    except OSError as e:
        log.critical('[HEAL] %s is corrupt (%s) and could not be moved aside: %s', name, err, e)
        return copy.deepcopy(default)
    for old in corrupt_copies(path)[:-CORRUPT_KEEP]:
        remove_quietly(old)
    if bad is None:
        return read_json(path, default, heal=False)
    try:
        with open(path + '.bak', 'r', encoding='utf-8-sig') as f:
            text = f.read()
        data = json.loads(text)
        atomic_write_text(path, text, private=True)
    except (OSError, ValueError):
        log.critical('[HEAL] %s was corrupt (%s): moved to %s; no usable backup, starting '
                     'from defaults', name, err, os.path.basename(bad))
        return copy.deepcopy(default)
    log.critical('[HEAL] %s was corrupt (%s): moved to %s and restored from %s.bak',
                 name, err, os.path.basename(bad), name)
    return data


def deep_merge(base, override):
    """New dict: base with override's keys applied recursively."""
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def diff_from(base, data):
    """The part of `data` that differs from `base` (recursively).

    Site files store only this, so a default changed by a later release
    reaches every box that never overrode it.
    """
    out = {}
    for key, value in data.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            sub = diff_from(base[key], value)
            if sub:
                out[key] = sub
        elif key not in base or base[key] != value:
            out[key] = copy.deepcopy(value)
    return out


def now_local():
    """Aware datetime in the OS timezone (stdlib only -- no zoneinfo on 3.8)."""
    return datetime.datetime.now().astimezone()


def iso_now():
    """ISO-8601 with an explicit offset, e.g. 2026-11-04T19:05:00+07:00."""
    return now_local().isoformat(timespec='seconds')


_PUSH_TOKEN_RE = re.compile(r'(/api/push/)[^/?#\s]+')
_QUERY_SECRET_RE = re.compile(r'((?:api_key|signature|token)=)[^&\s]*', re.I)


def url_host(url):
    """'scheme://host' of a URL, for log lines: no path, no query, no token."""
    try:
        u = urlparse(str(url))
        return '%s://%s' % (u.scheme, u.hostname) if u.hostname else '(invalid URL)'
    except ValueError:
        return '(invalid URL)'


_CGNAT = ipaddress.ip_network('100.64.0.0/10')   # carrier-grade NAT, Tailscale


def _is_local_ip(ip):
    if getattr(ip, 'ipv4_mapped', None):
        ip = ip.ipv4_mapped
    return ip.is_loopback or ip.is_link_local or ip.is_private or \
        (ip.version == 4 and ip in _CGNAT)


def is_local_host(host):
    """True for localhost / a private, link-local or CGNAT address, or a
    name that resolves ONLY to such addresses (checked on every call, so a
    name that later points to the internet stops counting as local)."""
    host = (host or '').strip().strip('[]')
    if not host:
        return False
    try:
        return _is_local_ip(ipaddress.ip_address(host.split('%')[0]))
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
        ips = {ipaddress.ip_address(i[4][0].split('%')[0]) for i in infos}
    except (OSError, ValueError, UnicodeError):
        return False
    return bool(ips) and all(_is_local_ip(ip) for ip in ips)


def is_local_server(remote):
    return str((remote or {}).get('server_type') or 'public').lower() == 'local'


def active_server_url(remote):
    """The URL the agent reports to: remote.local_url when Local network is
    chosen, remote.url (the Public one) otherwise. Each type keeps its own
    URL, so switching back and forth loses neither."""
    remote = remote or {}
    key = 'local_url' if is_local_server(remote) else 'url'
    return str(remote.get(key) or '').strip()


def server_tls_verify(remote):
    """Check the reporting server's certificate? Always, unless the admin
    chose server_type 'local' AND the host really is on the local network:
    a LAN server often has a self-signed certificate. Reply signing (HMAC)
    still protects what the agent acts on."""
    if not is_local_server(remote):
        return True
    try:
        host = urlparse(active_server_url(remote)).hostname
    except ValueError:
        return True
    return not is_local_host(host)


def free_bytes(path):
    try:
        return shutil.disk_usage(path).free
    except OSError:
        return None


def redact(text):
    """Hide push tokens and signed query parameters before logging a URL."""
    text = _PUSH_TOKEN_RE.sub(r'\1***', str(text))
    return _QUERY_SECRET_RE.sub(r'\1***', text)


_VERSION_RE = re.compile(r'^\s*v?(\d+)\.(\d+)\.(\d+)')


def version_tuple(version):
    """(major, minor, patch) or None for a string that is not x.y.z."""
    m = _VERSION_RE.match(str(version or ''))
    return tuple(int(x) for x in m.groups()) if m else None


_STRICT_VERSION_RE = re.compile(r'^\d{1,4}\.\d{1,5}\.\d{1,6}$')


def is_version(text):
    """Exactly x.y.z. The version goes into the GitHub URL and file paths, so
    a suffix such as '9.9.9/../../evil' must never get that far."""
    return isinstance(text, str) and bool(_STRICT_VERSION_RE.match(text))


def is_newer(candidate, current):
    """candidate must be a strict x.y.z (see is_version); current may be loose."""
    if not is_version(candidate):
        return False
    a, b = version_tuple(candidate), version_tuple(current)
    return bool(a and b and a > b)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def touch(path, text=''):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)


def remove_quietly(path):
    try:
        os.remove(path)
        return True
    except OSError:
        return False
