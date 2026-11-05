"""`main.py import <folder>`: bring a site over from an Uptime Sync 3.x
(or 2.8.x) install, so a reinstall does not mean retyping everything.

Read (never modified):
    data/local.json over config/defaults.json   (2.8.x: config/settings.json)
    data/monitors.json                          (2.8.x: config/monitors.json)
    data/users.json                             (2.8.x: config/users.json)
    data/.env                                   copied as-is: push URLs may use ${NAME}
    data/response_signing.json                  the 3.6.22 latch; same fingerprint format

Written here: data/.env FIRST (so settings.save() leaves .env-managed
secrets out of settings.json), then settings.json, monitors.json,
users.json, response_signing.json. A file that already exists here is
skipped unless --force; with --force the old copy is kept as
<file>.before-import-<ts>.

Secrets are reported by name only, never by value.
"""

import os
import shutil
import time

from . import monitors, paths, settings
from .util import atomic_write_json, deep_merge, read_json

# (3.x dotted path, v4 dotted path)
SETTING_MAP = (
    ('web.site_name', 'site_name'),
    ('service.check_interval', 'check_interval'),
    ('service.retry_delay', 'retry_delay'),
    ('service.max_concurrent_checks', 'max_workers'),
    ('logging.level', 'log_level'),
    ('logging.retention_days', 'log_retention_days'),
    ('web.enabled', 'web.enabled'),
    ('web.host', 'web.host'),
    ('web.port', 'web.port'),
    ('remote_reporting.enabled', 'remote.enabled'),
    ('remote_reporting.remote_url', 'remote.url'),
    ('remote_reporting.api_key', 'remote.api_key'),
    ('remote_reporting.secret_key', 'remote.secret_key'),
    ('remote_reporting.heartbeat_interval', 'remote.heartbeat_interval'),
    ('remote_reporting.require_signed_response', 'remote.require_signed_response'),
)
SECRET_KEYS = ('remote.api_key', 'remote.secret_key')


def _get(d, dotted):
    node = d
    for key in dotted.split('.'):
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node


def _set(d, dotted, value):
    keys = dotted.split('.')
    for key in keys[:-1]:
        d = d.setdefault(key, {})
    d[keys[-1]] = value


def _first(root, *rels):
    for rel in rels:
        p = os.path.join(root, *rel.split('/'))
        if os.path.isfile(p):
            return p
    return None


def find_sources(root):
    return {
        'defaults': _first(root, 'config/defaults.json'),
        'settings': _first(root, 'data/local.json', 'config/settings.json'),
        'monitors': _first(root, 'data/monitors.json', 'config/monitors.json'),
        'users': _first(root, 'data/users.json', 'config/users.json'),
        'env': _first(root, 'data/.env'),
        'latch': _first(root, 'data/response_signing.json'),
    }


def map_settings(old_defaults, old_local):
    old = deep_merge(old_defaults or {}, old_local or {})
    new = {}
    for src, dst in SETTING_MAP:
        value = _get(old, src)
        if value is None or value == '':
            continue
        if dst in ('check_interval', 'retry_delay', 'max_workers', 'log_retention_days',
                   'web.port', 'remote.heartbeat_interval'):
            try:
                value = int(value)
            except (TypeError, ValueError):
                continue
        if dst == 'log_level':
            value = str(value).upper()
        _set(new, dst, value)
    return new


def map_users(old):
    out = {}
    for name, u in (old or {}).items():
        if not isinstance(u, dict) or name.startswith('_') or not u.get('password'):
            continue
        role = u.get('role')
        role = 'admin' if role in (None, '') else ('admin' if role == 'admin' else 'viewer')
        out[name] = {'password': u['password'], 'role': role,
                     'created_at': u.get('created_at'), 'last_login': u.get('last_login'),
                     'is_active': bool(u.get('is_active', True)), 'epoch': 1}
    return out


def _exists(path):
    try:
        return os.path.getsize(path) > 2
    except OSError:
        return False


def run(root, dry_run=False, force=False, out=print):
    root = os.path.abspath(root)
    if os.path.normcase(root) == os.path.normcase(paths.ROOT):
        out('[ERROR] That is this install. Point at the old 3.x folder.')
        return 1
    src = find_sources(root)
    if not any(src.values()):
        out('[ERROR] No Uptime Sync data found under %s' % root)
        return 1
    try:
        with open(os.path.join(root, 'VERSION')) as f:
            out('[INFO] Importing from %s (version %s)' % (root, f.readline().strip() or '?'))
    except OSError:
        out('[INFO] Importing from %s' % root)
    stamp = time.strftime('%Y%m%d-%H%M%S')
    plan = []   # (label, target path, writer)

    def keep_or_skip(target, label):
        if _exists(target) and not force:
            out('[SKIP] %s: %s already exists here (use --force to replace it)' % (label, target))
            return False
        return True

    # .env first: settings.save() strips what .env manages.
    if src['env'] and keep_or_skip(paths.ENV_FILE, '.env'):
        names = sorted(settings.parse_env_file(src['env']))
        out('[OK] .env: %d name(s): %s' % (len(names), ', '.join(names) or '-'))
        plan.append(('.env', paths.ENV_FILE, lambda: shutil.copyfile(src['env'], paths.ENV_FILE)))

    new_settings = {}
    if src['settings']:
        new_settings = map_settings(read_json(src['defaults'], {}, heal=False) if src['defaults'] else {},
                                    read_json(src['settings'], {}, heal=False))
        if keep_or_skip(paths.SETTINGS_FILE, 'settings'):
            for _, dst in SETTING_MAP:
                value = _get(new_settings, dst)
                if value is None:
                    continue
                shown = '(set)' if dst in SECRET_KEYS else repr(value)
                out('[OK] setting %s = %s' % (dst, shown))
            url = str(_get(new_settings, 'remote.url') or '')
            if url.lower().startswith('http://'):
                out('[WARN] remote.url is plain http: heartbeats and replies can be read and '
                    'altered on the way. Move it to https when the server supports it.')
            plan.append(('settings', paths.SETTINGS_FILE,
                         lambda: settings.save(deep_merge(settings.defaults(), new_settings))))

    if src['monitors'] and keep_or_skip(paths.MONITORS_FILE, 'monitors'):
        raw = read_json(src['monitors'], {}, heal=False) or {}
        items = raw.get('monitors', []) if isinstance(raw, dict) else raw
        mons = [monitors.normalize(m) for m in items if isinstance(m, dict)]
        env = settings.parse_env_file(src['env']) if src['env'] else {}
        for m in mons:
            notes = []
            if not m['push_url']:
                notes.append('no push URL')
            elif m['push_url'].lower().startswith('http://'):
                notes.append('push URL is plain http - token travels in clear text, change it to https')
            missing = [n for n in settings.undefined_refs(m['push_url'] + m['monitor_url'], env)]
            if missing:
                notes.append('uses ${%s}, not defined in .env' % missing[0])
            reserved = settings.reserved_refs(m['push_url'] + m['monitor_url'])
            if reserved:
                notes.append('uses ${%s}, an agent credential that is never expanded '
                             'in a monitor - edit it after the import' % reserved[0])
            out('[%s] monitor %s (%s %s)%s' % ('WARN' if notes else 'OK', m['name'], m['type'],
                                              m['target'], ': ' + '; '.join(notes) if notes else ''))
        plan.append(('monitors', paths.MONITORS_FILE, lambda: monitors.save(mons)))

    if src['users'] and keep_or_skip(paths.USERS_FILE, 'users'):
        users = map_users(read_json(src['users'], {}, heal=False))
        for name, u in sorted(users.items()):
            out('[OK] user %s (%s)' % (name, u['role']))
        if users:
            plan.append(('users', paths.USERS_FILE,
                         lambda: atomic_write_json(paths.USERS_FILE, users, private=True)))

    if src['latch'] and keep_or_skip(paths.LATCH_FILE, 'response-signing latch'):
        out('[OK] response-signing latch (this server already signs its replies)')
        plan.append(('latch', paths.LATCH_FILE, lambda: shutil.copyfile(src['latch'], paths.LATCH_FILE)))

    if dry_run:
        out('[INFO] Dry run: nothing written.')
        return 0
    paths.ensure_dirs()
    for label, target, write in plan:
        if os.path.exists(target):
            shutil.copyfile(target, '%s.before-import-%s' % (target, stamp))
        write()
        if os.name != 'nt':
            os.chmod(target, 0o600)
    out('[OK] Imported: %s' % (', '.join(p[0] for p in plan) or 'nothing'))
    out('')
    out('Before starting this install, stop the old one for good -- both would push the same')
    out('monitors and both want web port %s:' % (_get(new_settings, 'web.port') or 5000))
    out('  Windows: run the old scripts\\service-manager.ps1 -StopService, then delete its')
    out('           scheduled tasks (Task Scheduler: UptimeSync_Watchdog and the service task).')
    out('Then: python main.py install')
    return 0
