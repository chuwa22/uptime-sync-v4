"""Settings = config/defaults.json, overlaid by data/settings.json, overlaid
by credentials from data/.env (and the OS environment).

Precedence: OS environment > data/.env > data/settings.json > defaults.

data/settings.json holds only what differs from the defaults (save() strips
the rest), so a default changed by a later release reaches every box that
never overrode it. Values that come from .env are never written back to
settings.json and are never rendered into HTML (see ENV_MANAGED).
"""

import copy
import os
import re
import threading

from . import paths
from .util import atomic_write_json, deep_merge, diff_from, read_json

# setting path -> environment variable that overrides it
ENV_SETTINGS = (
    (('remote', 'api_key'), 'UPTIME_API_KEY'),
    (('remote', 'secret_key'), 'UPTIME_SECRET_KEY'),
    (('remote', 'url'), 'UPTIME_REMOTE_URL'),
)

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
    """Replace ${NAME} with its .env value. Unknown names stay as written."""
    if not isinstance(text, str) or '${' not in text:
        return text
    env = env_values() if env is None else env
    return _REF_RE.sub(lambda m: env.get(m.group(1), m.group(0)), text)


def undefined_refs(text, env=None):
    env = env_values() if env is None else env
    return [n for n in _REF_RE.findall(text or '') if n not in env]


def defaults():
    return read_json(paths.DEFAULTS_FILE, {}) or {}


def load_site():
    """data/settings.json only (what this site changed)."""
    data = read_json(paths.SETTINGS_FILE, {})
    return data if isinstance(data, dict) else {}


def load():
    """Merged settings with .env credentials applied. A fresh copy."""
    merged = deep_merge(defaults(), load_site())
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
        atomic_write_json(paths.SETTINGS_FILE, site, private=True)
        return site


def update(changes):
    """Apply a nested dict of changes on top of the current settings."""
    return save(deep_merge(load(), changes))
