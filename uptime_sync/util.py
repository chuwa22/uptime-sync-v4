"""Small helpers shared by every part of the agent."""

import copy
import datetime
import hashlib
import json
import os
import re
import tempfile


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
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def atomic_write_json(path, data, private=False):
    atomic_write_text(path, json.dumps(data, indent=2, ensure_ascii=False) + '\n', private)


def read_json(path, default=None):
    """Parsed JSON from path, or `default` (deep-copied) if missing/corrupt."""
    try:
        with open(path, 'r', encoding='utf-8-sig') as f:
            return json.load(f)
    except (OSError, ValueError):
        return copy.deepcopy(default)


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


def redact(text):
    """Hide push tokens and signed query parameters before logging a URL."""
    text = _PUSH_TOKEN_RE.sub(r'\1***', str(text))
    return _QUERY_SECRET_RE.sub(r'\1***', text)


_VERSION_RE = re.compile(r'^\s*v?(\d+)\.(\d+)\.(\d+)')


def version_tuple(version):
    """(major, minor, patch) or None for a string that is not x.y.z."""
    m = _VERSION_RE.match(str(version or ''))
    return tuple(int(x) for x in m.groups()) if m else None


def is_newer(candidate, current):
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
