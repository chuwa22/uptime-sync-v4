"""Settings = config/defaults.json, overlaid by data/settings.json, overlaid
by credentials from data/.env (and the OS environment).

Precedence: OS environment > data/.env > data/settings.json > defaults.

data/settings.json holds only what differs from the defaults (save() strips
the rest), so a default changed by a later release reaches every box that
never overrode it. Values that come from .env are never written back to
settings.json and are never rendered into HTML (see ENV_MANAGED).
"""

import copy
import logging
import math
import os
import re
import threading

from . import loglevel, paths
from .util import atomic_write_json, deep_merge, diff_from, read_json

# setting path -> environment variable that overrides it
ENV_SETTINGS = (
    (('remote', 'api_key'), 'UPTIME_API_KEY'),
    (('remote', 'secret_key'), 'UPTIME_SECRET_KEY'),
    (('remote', 'url'), 'UPTIME_REMOTE_URL'),
)

# ${NAME} never expands these. They are this agent's own credentials: if a
# monitor URL could say ${UPTIME_SECRET_KEY}, anyone allowed to edit
# monitors could have the agent send its HMAC key to a host of their choice.
RESERVED_REFS = frozenset(name for _, name in ENV_SETTINGS) | {'UPTIME_SYNC_SECRET_KEY'}

# (path, type, min, max): load() coerces and clamps these, so a hand-edited
# "check_interval": "abc" or 0 is a warning, not a crash loop of the engine.
NUMERIC = (
    (('check_interval',), int, 10, 86400),
    (('max_workers',), int, 1, 64),
    (('retry_delay',), float, 0, 60),
    (('log_retention_days',), int, 1, 3650),
    (('web', 'port'), int, 1, 65535),
    (('remote', 'heartbeat_interval'), int, 30, 86400),
)

# 'check_interval' / 'web.port' -> (lo, hi): what the Settings form offers
# and checks. One table, so the form can never refuse a value load() keeps.
BOUNDS = {'.'.join(p): (lo, hi) for p, _kind, lo, hi in NUMERIC}

log = logging.getLogger('settings')
_warned = set()

_NAME_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
_REF_RE = re.compile(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}')

_lock = threading.Lock()


def parse_env_file(path):
    """KEY=VALUE lines -> dict. '#' comments, optional `export `, optional
    matching quotes. Malformed lines are skipped, never fatal."""
    values = {}
    try:
        with open(path, 'r', encoding='utf-8-sig') as f:
            lines = f.read().splitlines()
    except OSError:
        return values
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        if line.startswith('export '):
            line = line[7:].lstrip()
        key, value = line.split('=', 1)
        key, value = key.strip(), value.strip()
        if not _NAME_RE.match(key):
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
            value = value[1:-1]
        values[key] = value
    return values


def env_values():
    """data/.env with the OS environment on top (only names .env or
    ENV_SETTINGS mention, so the whole OS environment is not exposed)."""
    values = parse_env_file(paths.ENV_FILE)
    wanted = set(values) | {name for _, name in ENV_SETTINGS}
    for name in wanted:
        if os.environ.get(name):
            values[name] = os.environ[name]
    return values


def env_managed():
    """{'remote.api_key': 'UPTIME_API_KEY', ...} for settings set by .env."""
    env = env_values()
    return {'.'.join(p): name for p, name in ENV_SETTINGS if env.get(name)}


def expand_refs(text, env=None):
    """Replace ${NAME} with its .env value. Unknown and RESERVED_REFS names
    stay as written."""
    if not isinstance(text, str) or '${' not in text:
        return text
    env = env_values() if env is None else env

    def value(m):
        if m.group(1) in RESERVED_REFS:
            return m.group(0)
        return env.get(m.group(1), m.group(0))
    return _REF_RE.sub(value, text)


def undefined_refs(text, env=None):
    env = env_values() if env is None else env
    return [n for n in _REF_RE.findall(text or '') if n not in env and n not in RESERVED_REFS]


def reserved_refs(text):
    """${NAME}s in text that may never be expanded (see RESERVED_REFS)."""
    return [n for n in _REF_RE.findall(text or '') if n in RESERVED_REFS]


def defaults():
    # heal=False: config/ ships with the code; a broken copy is a bad
    # release, not site data to quarantine.
    return read_json(paths.DEFAULTS_FILE, {}, heal=False) or {}


def _coerce(merged, base):
    for path, kind, lo, hi in NUMERIC:
        node, dflt = merged, base
        for key in path[:-1]:
            node = node.get(key) if isinstance(node.get(key), dict) else node.setdefault(key, {})
            dflt = dflt.get(key) if isinstance(dflt, dict) else {}
            if not isinstance(node, dict):
                break
        if not isinstance(node, dict):
            continue
        raw = node.get(path[-1])
        fallback = dflt.get(path[-1], lo) if isinstance(dflt, dict) else lo
        try:
            value = kind(raw)
            if isinstance(value, float) and math.isnan(value):
                raise ValueError('nan')
        except (TypeError, ValueError, OverflowError):
            value = kind(fallback)
        value = min(max(value, kind(lo)), kind(hi))
        if value != raw or type(raw) is bool:
            name = '.'.join(path)
            if (name, repr(raw)) not in _warned:
                _warned.add((name, repr(raw)))
                log.warning('Setting %s = %r is not valid (%s to %s) - using %s',
                            name, raw, lo, hi, value)
        node[path[-1]] = value


# Defaults whose type is mixed on purpose (auto / true / false).
_ANY_TYPE = frozenset({'remote.require_signed_response'})


def _fix_types(merged, base, prefix=''):
    """A value whose type differs from its default is replaced by the
    default, with one warning: `"web": null` in a hand-edited file made the
    supervisor raise on every start (so no engine ran at all), and
    `"remote": null` killed the heartbeat thread. NUMERIC values are left to
    _coerce(), which converts "60" instead of discarding it."""
    numeric = {'.'.join(p) for p, _k, _lo, _hi in NUMERIC}
    for key, dflt in base.items():
        name = prefix + key
        if key not in merged or name in _ANY_TYPE or name in numeric:
            continue
        value = merged[key]
        if isinstance(dflt, dict):
            if isinstance(value, dict):
                _fix_types(value, dflt, name + '.')
                continue
        elif isinstance(dflt, bool):
            if isinstance(value, bool):
                continue
        elif isinstance(dflt, str):
            if isinstance(value, str):
                continue
        else:
            continue
        if (name, repr(value)) not in _warned:
            _warned.add((name, repr(value)))
            log.warning('Setting %s = %r has the wrong type (%s expected) - using the default %r',
                        name, value, type(dflt).__name__, dflt)
        merged[key] = copy.deepcopy(dflt)


def _warn_once(name, raw, used):
    if (name, repr(raw)) not in _warned:
        _warned.add((name, repr(raw)))
        log.warning('Setting %s = %r is not valid (%s) - using %s',
                    name, raw, '/'.join(loglevel.LEVELS), used)


def load_site():
    """data/settings.json only (what this site changed)."""
    data = read_json(paths.SETTINGS_FILE, {})
    return data if isinstance(data, dict) else {}


def load():
    """Merged settings with .env credentials applied. A fresh copy."""
    base = defaults()
    merged = deep_merge(base, load_site())
    _fix_types(merged, base)
    _coerce(merged, base)
    loglevel.coerce(merged, _warn_once)
    env = env_values()
    for path, name in ENV_SETTINGS:
        if env.get(name):
            node = merged
            for key in path[:-1]:
                node = node.setdefault(key, {})
            node[path[-1]] = env[name]
    return merged


def save(merged):
    """Persist a full settings dict: only the non-default, non-.env part."""
    with _lock:
        data = copy.deepcopy(merged)
        for dotted in env_managed():
            node = data
            keys = dotted.split('.')
            for key in keys[:-1]:
                node = node.get(key, {})
            node.pop(keys[-1], None)
        site = diff_from(defaults(), data)
        atomic_write_json(paths.SETTINGS_FILE, site, private=True, backup=True)
        return site


def update(changes):
    """Apply a nested dict of changes on top of the current settings."""
    return save(deep_merge(load(), changes))
