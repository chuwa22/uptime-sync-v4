"""data/monitors.json: {"monitors": [ {...}, ... ]}.

A monitor:
    id, name, type (DNS | PING | TCP PORT | HTTP | HTTPS), target,
    port, monitor_url, push_url, enabled, timeout, retry_count,
    headers {}, ssl_verify, dns_method (auto|query|ping), dns_query_name
"""

import copy
import hashlib
import re
import threading
import uuid
from urllib.parse import parse_qsl, urlencode, urlparse, urlsplit, urlunsplit

from . import paths, settings
from .checks import DNS_METHODS, is_valid_dns_query_name
from .util import atomic_write_json, read_json

TYPES = ('DNS', 'PING', 'TCP PORT', 'HTTP', 'HTTPS')

DEFAULTS = {
    'id': '',
    'name': '',
    'type': 'PING',
    'target': '',
    'port': None,
    'monitor_url': '',
    'push_url': '',
    'enabled': True,
    'timeout': 10,
    'retry_count': 3,
    'headers': {},
    'ssl_verify': True,
    'dns_method': 'auto',
    'dns_query_name': '',
}

_HOST_RE = re.compile(r'^[A-Za-z0-9_.:\-\[\]]{1,253}$')
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,100}$")
_lock = threading.Lock()


PUSH_PARAMS = ('status', 'msg', 'ping', 'dns_ping')


def push_base_url(url):
    """The push URL without the parameters the agent sends itself.

    Uptime Kuma shows a push URL as .../api/push/<token>?status=up&msg=OK&ping=
    and that is what people paste. Sent as-is plus the agent's own params,
    every name appears twice; Kuma then reads status as a list, which is not
    "up", and marks the monitor DOWN on every beat. Other query parameters
    are kept."""
    parts = urlsplit(url)
    if not parts.query:
        return url
    kept = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
            if k.lower() not in PUSH_PARAMS]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(kept), parts.fragment))


# field -> (lo, hi, default). normalize() clamps hand-edited values to these;
# the monitor form rejects anything outside them.
LIMITS = {'timeout': (1, 120, 10), 'retry_count': (1, 10, 3), 'port': (1, 65535, None)}

def normalize(raw):
    """A monitor dict with every field present and sane types."""
    m = copy.deepcopy(DEFAULTS)
    for key in DEFAULTS:
        if key in raw and raw[key] is not None:
            m[key] = raw[key]
    m['type'] = str(m['type'] or 'PING').strip().upper()
    m['name'] = str(m['name']).strip()
    m['target'] = str(m['target']).strip()
    m['push_url'] = str(m['push_url'] or '').strip()
    m['monitor_url'] = str(m['monitor_url'] or '').strip()
    m['enabled'] = bool(m['enabled'])
    m['ssl_verify'] = bool(m['ssl_verify'])
    try:
        m['port'] = int(m['port']) if m['port'] not in (None, '') else None
    except (TypeError, ValueError):
        m['port'] = None
    if m['type'] in ('HTTP', 'HTTPS') and not m['target'] and m['monitor_url']:
        # Target is ignored when a monitor URL is set; keep its host for display.
        m['target'] = urlparse(m['monitor_url']).hostname or ''
    if m['type'] in ('DNS', 'PING'):
        # Not used by these checks; a value left over from another type (the
        # form only hides the field) would otherwise be saved and shown.
        m['port'] = None
    for key in ('timeout', 'retry_count'):
        lo, hi, fallback = LIMITS[key]
        try:
            m[key] = min(hi, max(lo, int(m[key])))
        except (TypeError, ValueError):
            m[key] = fallback
    if not isinstance(m['headers'], dict):
        m['headers'] = {}
    m['headers'] = {str(k): str(v) for k, v in m['headers'].items()}
    m['dns_method'] = str(m['dns_method'] or 'auto').lower()
    if m['dns_method'] not in DNS_METHODS:
        m['dns_method'] = 'auto'
    m['dns_query_name'] = str(m['dns_query_name'] or '').strip()
    if not m['id']:
        m['id'] = uuid.uuid4().hex[:12]
    return m


def validate(m):
    """List of problems (empty = valid). Expects a normalize()d monitor."""
    errors = []
    if not m['name']:
        errors.append('Name is required.')
    if m['type'] not in TYPES:
        errors.append('Type must be one of: ' + ', '.join(TYPES) + '.')
    if not m['target'] or not _HOST_RE.match(m['target']):
        errors.append('Target must be a host name or IP address (no scheme, no path).')
    if m['type'] == 'TCP PORT' and not (m['port'] and 0 < m['port'] < 65536):
        errors.append('TCP PORT monitors need a port between 1 and 65535.')
    if m['port'] is not None and not (0 < m['port'] < 65536):
        errors.append('Port must be between 1 and 65535.')
    if m['monitor_url']:
        u = urlparse(settings.expand_refs(m['monitor_url']))
        if u.scheme not in ('http', 'https') or not u.hostname:
            errors.append('Monitor URL must be an http(s) URL.')
    for name, value in m['headers'].items():
        if not _HEADER_NAME_RE.match(name):
            errors.append('Header name %r is not valid (letters, digits and - only, no spaces).' % name[:40])
        try:
            value.encode('latin-1')
        except UnicodeEncodeError:
            errors.append('Header %s: HTTP header values can only use Latin characters.' % name[:40])
        if '\r' in value or '\n' in value:
            errors.append('Header %s: the value cannot contain a line break.' % name[:40])
    if m['type'] == 'DNS' and m['dns_query_name'] and not is_valid_dns_query_name(m['dns_query_name']):
        errors.append('DNS query name is not a valid host name.')
    for field, text in [('Push URL', m['push_url']), ('Monitor URL', m['monitor_url'])] + \
            [('Header ' + k[:40], v) for k, v in m['headers'].items()]:
        reserved = settings.reserved_refs(text)
        if reserved:
            errors.append('%s uses ${%s}: that is one of this agent\'s own credentials and is '
                          'never put into a monitor.' % (field, reserved[0]))
    if m['push_url']:
        missing = settings.undefined_refs(m['push_url'])
        if missing:
            errors.append('Push URL uses ${%s}, which data/.env does not define.' % missing[0])
        u = urlparse(settings.expand_refs(m['push_url']))
        if u.scheme != 'https' or not u.hostname:
            errors.append('Push URL must be an https:// URL (the token in it would travel in clear text).')
    else:
        errors.append('Push URL is required.')
    return errors


def _fix_ids(items):
    """Every row gets an id that is unique and the same on every load.

    3.x numbered monitors monitor_<count+1>, so add / delete / add left two
    rows with one id, and the import copies them; a row without an id would
    get a new random one per load. Either way the web UI's Edit / Delete
    links hit the wrong row (or none). The ids made here are deterministic,
    so the engine and the web process agree without writing the file; the
    next save stores them."""
    seen = set()
    for i, m in enumerate(items):
        mid = str(m.get('id') or '').strip()
        if not mid:
            src = '%s|%s|%s|%d' % (m.get('name'), m.get('type'), m.get('target'), i)
            mid = 'm' + hashlib.sha1(src.encode('utf-8')).hexdigest()[:11]
        while mid in seen:
            mid = '%s-%d' % (mid, i)
        seen.add(mid)
        m['id'] = mid
    return items


def load(strict=False):
    """strict=True raises OSError when the file exists but cannot be read
    (see util.read_json); otherwise that reads as no monitors."""
    data = read_json(paths.MONITORS_FILE, {'monitors': []}, strict=strict)
    if isinstance(data, list):
        data = {'monitors': data}
    items = data.get('monitors') if isinstance(data, dict) else None
    rows = [dict(m) for m in (items or []) if isinstance(m, dict)]
    return [normalize(m) for m in _fix_ids(rows)]


def save(monitors):
    with _lock:
        atomic_write_json(paths.MONITORS_FILE, {'monitors': [normalize(m) for m in monitors]},
                          private=True, backup=True)


def runtime_view(m, env=None):
    """The monitor as the checker uses it: ${NAME} references expanded.
    Never send this to the web UI -- it carries the real push token."""
    env = settings.env_values() if env is None else env
    r = copy.deepcopy(m)
    r['push_url'] = settings.expand_refs(r['push_url'], env)
    r['monitor_url'] = settings.expand_refs(r['monitor_url'], env)
    r['headers'] = {k: settings.expand_refs(v, env) for k, v in r['headers'].items()}
    return r
