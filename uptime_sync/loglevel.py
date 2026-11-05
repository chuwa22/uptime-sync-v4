"""Log levels: the one place that knows them. Every process (supervisor,
engine, web, CLI) applies them through here, and settings.py, the Settings
page, the heartbeat and the importer validate through here.

Settings:

    "log_level": "INFO"                      every part, unless overridden
    "log_levels": {"checks": "DEBUG"}        per part; absent = log_level

A part is a logger name (logging.getLogger('checks')), so a part keeps its
level in every process it runs in. "libraries" (urllib3, waitress,
werkzeug) is the exception: it stays at WARNING unless set, because their
INFO lines are one per request, and it never goes below INFO: urllib3's
DEBUG line is the full request URL, i.e. every Kuma push token (also the
ones kept in data/.env) and the signed update URL, written into logs.db.

Long-running processes call refresh() from a loop they already have: it
stats data/settings.json and re-applies only when the file changed, so a
level saved in the web UI (or pushed by the server) reaches every process
within seconds, without a restart.
"""

import logging
import os
import threading
import time

LEVELS = ('DEBUG', 'INFO', 'WARNING', 'ERROR')         # what a setting may say
VALUES = {'DEBUG': logging.DEBUG, 'INFO': logging.INFO, 'WARNING': logging.WARNING,
          'ERROR': logging.ERROR, 'CRITICAL': logging.CRITICAL}   # for filtering logs.db
DEFAULT = 'INFO'
ALIASES = {'WARN': 'WARNING', 'FATAL': 'CRITICAL'}

# (part, what it logs). The Settings page lists them in this order.
COMPONENTS = (
    ('engine', 'Check cycles, pushes, monitor reloads'),
    ('checks', 'DNS / PING / TCP / HTTP probes'),
    ('heartbeat', 'Heartbeats to uptime-monitor'),
    ('update', 'Update downloads, installs and rollbacks'),
    ('supervisor', 'Starting and restarting the engine and web'),
    ('web', 'Web UI: sign-ins, saves'),
    ('heal', 'Self-healing of data files'),
    ('settings', 'Loading settings'),
    ('log', 'logs.db itself'),
    ('libraries', 'urllib3, waitress, werkzeug'),
)
NAMES = tuple(name for name, _ in COMPONENTS)
LIBRARIES = ('urllib3', 'waitress', 'werkzeug')
LIBRARY_DEFAULT = 'WARNING'
LIBRARY_FLOOR = 'INFO'     # see the module docstring: DEBUG would log push tokens


def choices(part):
    """Levels a part may be set to (the Settings page offers these)."""
    if part == 'libraries':
        return tuple(l for l in LEVELS if VALUES[l] >= VALUES[LIBRARY_FLOOR])
    return LEVELS

log = logging.getLogger('log')

_lock = threading.Lock()
_applied = None        # signature of the levels in force in this process
_stamp = None          # settings files' (mtime, size) when last applied
_next_check = 0.0


def normalize(value):
    """'debug' -> 'DEBUG', 'warn' -> 'WARNING'; None if not a level a
    setting may hold."""
    if not isinstance(value, str):
        return None
    name = value.strip().upper()
    name = ALIASES.get(name, name)
    return name if name in LEVELS else None


def filter_value(name, default='INFO'):
    """Number for a "this level and up" filter (Logs page, `main.py logs
    --level`). Unlike a setting, CRITICAL is allowed here."""
    key = str(name or '').strip().upper()
    key = ALIASES.get(key, key)
    return VALUES.get(key, VALUES[default])


def coerce(merged, warn):
    """Make merged['log_level'] / ['log_levels'] valid in place (used by
    settings.load(), so every reader sees clean values). warn(name, raw,
    used) reports a value that was replaced or dropped."""
    raw = merged.get('log_level')
    level = normalize(raw)
    if level is None:
        warn('log_level', raw, DEFAULT)
        level = DEFAULT
    merged['log_level'] = level
    raw = merged.get('log_levels')
    out = {}
    if isinstance(raw, dict):
        for part, value in raw.items():
            if value in (None, ''):
                continue
            name = normalize(value)
            if part not in NAMES or name is None:
                warn('log_levels.%s' % part, value, 'ignored')
                continue
            if name not in choices(part):
                warn('log_levels.%s' % part, value, LIBRARY_FLOOR)
                name = LIBRARY_FLOOR
            out[part] = name
    elif raw not in (None, {}):
        warn('log_levels', raw, 'ignored')
    merged['log_levels'] = out
    return merged


def effective(s, part):
    """The level `part` logs at under settings `s` (a name)."""
    own = normalize((s.get('log_levels') or {}).get(part))
    if own:
        return own if own in choices(part) else LIBRARY_FLOOR
    if part == 'libraries':
        return LIBRARY_DEFAULT
    return normalize(s.get('log_level')) or DEFAULT


def describe(s):
    """'INFO' or 'INFO (checks=DEBUG, web=WARNING)' for log lines and pages."""
    base = normalize(s.get('log_level')) or DEFAULT
    own = s.get('log_levels') or {}
    extra = ['%s=%s' % (p, normalize(own[p])) for p in NAMES if normalize(own.get(p))]
    return base + (' (%s)' % ', '.join(extra) if extra else '')


def apply(s):
    """Set the root logger and every part's logger from settings `s`.
    Idempotent; logs one line when the levels in force change."""
    global _applied
    base = normalize(s.get('log_level')) or DEFAULT
    own = s.get('log_levels') or {}
    sig = (base, tuple((p, normalize(own.get(p))) for p in NAMES))
    with _lock:
        if sig == _applied:
            return False
        first = _applied is None
        _applied = sig
        logging.getLogger().setLevel(VALUES[base])
        for part, level in sig[1]:
            if part == 'libraries':
                value = max(VALUES[level or LIBRARY_DEFAULT], VALUES[LIBRARY_FLOOR])
                for lib in LIBRARIES:
                    logging.getLogger(lib).setLevel(value)
            else:
                # NOTSET: follow the root logger (the global level)
                logging.getLogger(part).setLevel(VALUES[level] if level else logging.NOTSET)
    if not first:
        log.info('Log levels now %s', describe(s))
    return True


def _files_stamp():
    from . import paths
    out = []
    for p in (paths.SETTINGS_FILE, paths.DEFAULTS_FILE):
        try:
            st = os.stat(p)
            out.append((st.st_mtime, st.st_size))
        except OSError:
            out.append(None)
    return tuple(out)


def refresh(every=2.0):
    """Re-apply when data/settings.json (or the defaults) changed. Cheap:
    at most one stat pair per `every` seconds. Never raises."""
    global _stamp, _next_check
    now = time.monotonic()
    if now < _next_check:
        return False
    _next_check = now + every
    try:
        stamp = _files_stamp()
        if stamp == _stamp:
            return False
        from . import settings
        s = settings.load()
        _stamp = stamp
        return apply(s)
    except Exception as e:   # a bad settings file must not stop the loop calling this
        log.debug('Log level refresh failed: %s', e)
        return False


def reset():
    """Forget what was applied (tests, and log.setup() starting afresh)."""
    global _applied, _stamp, _next_check
    with _lock:
        _applied = None
        _stamp = None
        _next_check = 0.0
