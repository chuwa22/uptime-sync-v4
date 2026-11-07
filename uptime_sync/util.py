"""Small helpers shared by every part of the agent."""

import codecs
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
import zlib
from urllib.parse import urljoin, urlparse

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
    backup='mirror': <path>.bak gets what was just written instead. For
    users.json, where the previous version is the old password hash, a
    deleted user, an old role, or the epoch that revoked sessions: healing
    from it brought those back.
    compact=True: no indentation (history.json: written often, read by code)."""
    if backup is True:
        _keep_backup(path)
    if compact:
        text = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
    else:
        text = json.dumps(data, indent=2, ensure_ascii=False)
    atomic_write_text(path, text + '\n', private)
    if backup == 'mirror':
        try:
            atomic_write_text(path + '.bak', text + '\n', private=True)
        except OSError as e:
            log.warning('Could not back up %s: %s', os.path.basename(path), e)


def decode_text(data, errors='strict'):
    """bytes -> str for a file a person may have saved by hand: UTF-8
    (with or without a BOM), or UTF-16 with a BOM (what Notepad on Windows 7
    calls "Unicode"). Anything else raises UnicodeDecodeError, which is a
    ValueError, so callers treat it like a file that does not parse;
    errors='replace' never raises (and still drops the BOM)."""
    if data[:2] in (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE):
        return data.decode('utf-16', errors)
    return data.decode('utf-8-sig', errors)


def _read_text(path):
    with open(path, 'rb') as f:
        return decode_text(f.read())


def _keep_backup(path):
    try:
        text = _read_text(path)
        json.loads(text)
    except (OSError, ValueError):
        return
    try:
        atomic_write_text(path + '.bak', text, private=True)
    except OSError as e:
        log.warning('Could not back up %s: %s', os.path.basename(path), e)


def read_json(path, default=None, heal=True, strict=False):
    """Parsed JSON from path; `default` (deep-copied) if it is missing.

    A file that exists but does not parse is not silently treated as
    missing (heal=True): it is moved to <path>.corrupt-<ts>, a CRITICAL line
    is logged, and <path>.bak is restored when it parses. heal=False only
    for files this agent must not move (3.x files being imported, the
    shipped defaults). strict=True: only a MISSING file gives `default`; any
    other read error (a file an antivirus or backup tool holds for a moment)
    raises OSError, so the caller can keep what it had instead of "empty".
    Bytes that are not UTF-8 (or UTF-16 with a BOM) count as corrupt and
    are healed the same way: before 4.0.11 the UnicodeDecodeError escaped
    and stopped the supervisor on every start."""
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        return copy.deepcopy(default)
    except OSError:
        if strict:
            raise
        return copy.deepcopy(default)
    try:
        return json.loads(decode_text(data))
    except ValueError as e:   # UnicodeDecodeError is a ValueError too
        if not heal:
            return copy.deepcopy(default)
        return _heal(path, default, e)


READ_RETRY_DELAYS = (0.05, 0.1, 0.2, 0.4)


def read_json_for_update(path, default=None):
    """read_json for a read-modify-write (4.0.11): a file that exists but
    cannot be opened right now (an antivirus or backup tool holds it) is
    tried again a few times, then raises OSError. The non-strict read gave
    `default` instead, and the caller then wrote "default + its change"
    over the real file: the update state lost the backup path a rollback
    needs, settings went back to defaults. A missing file is `default`; a
    corrupt one heals as in read_json."""
    for delay in READ_RETRY_DELAYS + (None,):
        try:
            return read_json(path, default, strict=True)
        except OSError:
            if delay is None:
                raise
            time.sleep(delay)


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
        text = _read_text(path + '.bak')
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


# What counts as "this network" for a Local server (whose certificate is not
# checked). An explicit list, not ipaddress.is_private: that also covers
# ranges routed on the internet or never used on a LAN (Teredo 2001::/32,
# 198.18/15 benchmarking, 240/4, 0/8), depending on the Python version.
LOCAL_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',   # RFC 1918
    '127.0.0.0/8', '169.254.0.0/16',                    # loopback, link-local
    '100.64.0.0/10',                                    # carrier-grade NAT, Tailscale
    '::1/128', 'fc00::/7', 'fe80::/10'))               # IPv6 loopback, ULA, link-local


def _is_local_ip(ip):
    if getattr(ip, 'ipv4_mapped', None):
        ip = ip.ipv4_mapped
    return any(ip.version == n.version and ip in n for n in LOCAL_NETWORKS)


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


UPTIME_BARS = 30   # history bars on the dashboard; Uptime % counts these checks only


def recent_checks(history):
    """The last UPTIME_BARS [time, ok, ms] entries of a monitor's history:
    what the dashboard draws as bars and the only checks Uptime % counts,
    so the number always matches the bars beside it."""
    return list(history or [])[-UPTIME_BARS:]


def uptime_pct(history):
    """Percent of the last UPTIME_BARS [time, ok, ms] entries that were up,
    one decimal; None when there are none."""
    h = recent_checks(history)
    if not h:
        return None
    return round(100.0 * sum(1 for e in h if e[1]) / len(h), 1)


_session_class = None


def http_session():
    """The requests.Session every outbound request uses. requests reads,
    and decompresses, the whole body of a redirect reply even with
    allow_redirects=False (Session.send() fills Response.next through
    resolve_redirects()), so a hostile server answering 302 with a gzip bomb
    took 128 MB from one small reply. This Session never resolves redirects:
    callers that follow them use get_following()."""
    global _session_class
    import requests
    if _session_class is None:
        class Session(requests.Session):
            def resolve_redirects(self, resp, req, **kwargs):
                return iter(())
        _session_class = Session
    s = _session_class()
    s.headers['User-Agent'] = USER_AGENT
    return s


def get_following(session, url, max_redirects=5, headers=None, params=None, **kw):
    """GET through http_session(), following up to max_redirects redirects
    here without reading any hop's body. Like requests, Authorization is
    dropped when a redirect changes host or leaves https. `params` go on the
    first request only (a Location URL is used as given). Returns the
    final response, unread (stream=True): close it."""
    import requests
    headers = dict(headers or {})
    for _ in range(max_redirects + 1):
        r = session.get(url, headers=headers, params=params, allow_redirects=False, stream=True, **kw)
        params = None
        location = session.get_redirect_target(r)
        if not location:
            return r
        r.close()
        nxt = urljoin(r.url or url, location)
        if session.should_strip_auth(r.url or url, nxt):
            headers = {k: v for k, v in headers.items() if k.lower() != 'authorization'}
        url = nxt
    raise requests.TooManyRedirects('more than %d redirects' % max_redirects)


class BodyTooLarge(ValueError):
    """A response body (after decompression) over the caller's limit."""


def iter_body(r, limit, chunk_size=65536):
    """The body of a `stream=True` requests response, decoded, in chunks,
    never more than `limit` bytes in all (BodyTooLarge). Every response body
    the agent reads goes through here.

    It reads r.raw with decode_content=False, so urllib3 neither decompresses
    nor parses chunked framing: Python's http.client does the framing (with
    its 64 KB line limit) and zlib here inflates at most `limit` bytes. The
    urllib3 releases that still install on Python 3.8 (Windows 7) have no
    fix for the 2025-2026 decompression-bomb and chunk-size-line bugs
    (CVE-2025-66471, CVE-2025-66418, CVE-2026-21441, CVE-2026-44432,
    CVE-2026-97689), and a hostile server could otherwise run a 32-bit box
    out of memory with a few KB. Network errors come out as
    requests.ConnectionError, as from iter_content()."""
    import http.client
    import requests
    import urllib3
    enc = (r.headers.get('Content-Encoding') or '').strip().lower()
    if enc in ('', 'identity'):
        inflate = None
    elif enc in ('gzip', 'x-gzip'):
        inflate = zlib.decompressobj(16 + zlib.MAX_WBITS)
    elif enc == 'deflate':
        inflate = zlib.decompressobj()
    else:
        raise requests.exceptions.ContentDecodingError('unsupported Content-Encoding %r' % enc[:40])
    total = 0
    try:
        while True:
            try:
                data = r.raw.read(chunk_size, decode_content=False)
            except (urllib3.exceptions.HTTPError, http.client.HTTPException, OSError) as e:
                raise requests.ConnectionError(e)
            if not data:
                break
            if inflate is not None:
                try:
                    # max_length > 0 always: total <= limit here
                    data = inflate.decompress(data, limit + 1 - total)
                except zlib.error as e:
                    raise requests.exceptions.ContentDecodingError(e)
                if inflate.unconsumed_tail:
                    raise BodyTooLarge('over %d bytes' % limit)
            total += len(data)
            if total > limit:
                raise BodyTooLarge('over %d bytes' % limit)
            if data:
                yield data
        if inflate is not None:
            data = inflate.flush()
            if total + len(data) > limit:
                raise BodyTooLarge('over %d bytes' % limit)
            if data:
                yield data
    finally:
        r.close()

