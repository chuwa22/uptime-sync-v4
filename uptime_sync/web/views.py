"""Routes. Every state-changing route is POST (CSRF-checked in
__init__.csrf_guard) and admin-only."""

import ipaddress
import logging
import re
import secrets
import time
from urllib.parse import urlparse

from flask import abort, flash, jsonify, redirect, render_template, request, session, url_for

from .. import __version__, log as logsetup, loglevel, logstore, monitors, paths, procs, settings, signing, updater
from ..util import active_server_url, deep_merge, is_local_host, is_local_server, read_json, touch, uptime_pct
from . import auth

log = logging.getLogger('web')
LOG_LEVELS = loglevel.VALUES
LOG_PAGE_SIZES = (50, 100, 200, 500)   # rows per Logs page, offered on the page
LOG_PAGE = 50                           # the default
LOG_CLAMP_LINES = 3                     # longer messages fold (app.js)


def _engine_state():
    status = read_json(paths.STATUS_FILE, {}) or {}
    pid = procs.read_pid(paths.child_pid_file('engine'))
    alive = procs.pid_alive(pid)
    return status, alive


def mask_push_url(url):
    """https://kuma.example/api/push/*** -- for lists and the status API."""
    try:
        u = urlparse(url)
    except ValueError:
        return ''
    if not u.scheme:
        return ''
    path = u.path
    if '/api/push/' in path:
        path = path.split('/api/push/')[0] + '/api/push/***'
    try:
        port = u.port
    except ValueError:
        port = None
    host = u.hostname or ''     # never u.netloc: it may carry user:password@
    if ':' in host:
        host = '[%s]' % host
    return '%s://%s%s%s' % (u.scheme, host, ':%d' % port if port else '', path)


def tones(p):
    """Colour of each dashboard tile: ok | warn | bad | off. The template and
    app.js both use this, so the rule lives in one place."""
    enabled = [m for m in p['monitors'] if m['enabled']]
    states = [m['state'] for m in enabled]
    hb = p['heartbeat']
    return {
        'engine': 'ok' if p['engine']['running'] else 'bad',
        'monitors': ('off' if not enabled else 'bad' if 'down' in states
                     else 'warn' if 'unknown' in states else 'ok'),
        'heartbeat': ('off' if not hb['enabled'] else 'bad' if hb['failures'] or hb.get('error')
                      else 'ok' if hb['last_ok'] else 'warn'),
        'signing': ('off' if not hb['enabled'] else
                    'ok' if p['signing']['state'] in ('enforced', 'required') else 'warn'),
    }


def _ago(epoch, now):
    if not epoch:
        return 'never'
    s = max(0, int(round(now - epoch)))
    return '%d s ago' % s if s < 90 else '%d min ago' % int(round(s / 60.0))


def tile_text(p):
    """Every dashboard tile's words, for the first paint and for app.js's
    15 s refresh alike (they used to word it differently)."""
    hb = p['heartbeat']
    updated = p['engine']['updated_at']
    since = p['signing']['since']
    if not hb['enabled']:
        hb_value, hb_sub = 'Off', 'reporting disabled'
    else:
        hb_value = ('Failing' if hb['failures'] else 'Error' if hb.get('error') else
                    'OK' if hb['last_ok'] else 'Waiting')
        hb_sub = (hb['error'] + ' - ' if hb.get('error') else '') + 'last OK ' + _ago(hb['last_ok'], p['now'])
    return {
        'engine': 'Running' if p['engine']['running'] else 'Stopped',
        'engine_sub': 'last cycle ' + (updated[11:19] if updated else '-'),
        'counts': '%d / %d' % (p['counts']['up'], p['counts']['enabled']),
        'heartbeat': hb_value, 'heartbeat_sub': hb_sub,
        'signing': p['signing']['state'],
        'signing_sub': 'since ' + since[:10] if since else '',
    }


# Dashboard table order: a click on a column title sorts by it, the next
# click flips the direction. The choice rides in ?sort=&dir= (works without
# JS, IE8 included) and is remembered in the session, so the 15 s refresh
# (/api/status) and the next visit keep it. No choice = monitors.json order.
STATE_RANK = {'down': 0, 'unknown': 1, 'up': 2, 'paused': 3}   # problems first


def _natural(text):
    """'4.2.2.10' after '4.2.2.2', 'dns10' after 'dns2'."""
    parts = re.split(r'([0-9]+)', text or '')
    return [int(t) if i % 2 else t.lower() for i, t in enumerate(parts)]   # odd = the digit runs


DASH_SORTS = {
    'status': lambda r: STATE_RANK.get(r['state'], 9),
    'name': lambda r: _natural(r['name']),
    'type': lambda r: (r['type'] or '').lower(),
    'target': lambda r: _natural(r['target']),
    'response': lambda r: r['ms'],
    'uptime': lambda r: r['uptime'],
    'checked': lambda r: r['checked_at'] or None,
}


def dash_sort():
    """{'key', 'dir'} for the dashboard; key '' = monitors.json order."""
    if 'sort' in request.args:
        key, d = request.args.get('sort', ''), request.args.get('dir', 'asc')
        if key in DASH_SORTS and d in ('asc', 'desc'):
            session['dash_sort'] = [key, d]
        elif key == '':
            session.pop('dash_sort', None)
    saved = session.get('dash_sort')
    if isinstance(saved, list) and len(saved) == 2 and saved[0] in DASH_SORTS and saved[1] in ('asc', 'desc'):
        return {'key': saved[0], 'dir': saved[1]}
    return {'key': '', 'dir': ''}


def sort_rows(rows, key, direction):
    """Sorted copy. Rows without a value (never checked, no uptime yet) stay
    at the bottom both ways; ties keep name order."""
    fn = DASH_SORTS.get(key)
    if not fn:
        return rows
    have = [r for r in rows if fn(r) is not None]
    have.sort(key=lambda r: _natural(r['name']))
    have.sort(key=fn, reverse=(direction == 'desc'))
    return have + [r for r in rows if fn(r) is None]


def _status_payload():
    status, alive = _engine_state()
    results = status.get('monitors', {})
    history = None     # history.json only for an engine that predates status 'uptime'
    rows = []
    for m in monitors.load():
        r = results.get(m['id'], {})
        if 'uptime' in r:
            uptime = r['uptime']
        else:
            if history is None:
                history = read_json(paths.HISTORY_FILE, {}) or {}
            uptime = uptime_pct(history.get(m['id'], []))
        rows.append({
            'id': m['id'], 'name': m['name'], 'type': m['type'], 'target': m['target'],
            'enabled': m['enabled'],
            'state': ('paused' if not m['enabled'] else
                      'unknown' if 'ok' not in r else 'up' if r['ok'] else 'down'),
            'ms': r.get('ms'), 'checked_at': r.get('checked_at', ''),
            'uptime': uptime,
        })
    s = settings.load()
    hb = status.get('heartbeat', {})
    sign_state, sign_since = signing.status(s.get('remote', {}))
    pending = updater.pending()
    enabled = [r for r in rows if r['enabled']]
    p = {
        'version': __version__,
        'engine': {'running': alive, 'updated_at': status.get('updated_at', '')},
        'counts': {'up': len([r for r in enabled if r['state'] == 'up']), 'enabled': len(enabled)},
        'heartbeat': {
            'enabled': bool(s.get('remote', {}).get('enabled')),
            'last_ok': hb.get('last_ok'), 'failures': hb.get('failures', 0), 'error': hb.get('error', ''),
        },
        'signing': {'state': sign_state, 'since': sign_since},
        'update': {'pending': pending['version'] if pending else '',
                   'last': updater.state()},
        'monitors': rows,
        'now': int(time.time()),
    }
    p['tones'] = tones(p)
    p['text'] = tile_text(p)
    return p


LOOPBACK = ('127.0.0.1', '::1', '::ffff:127.0.0.1')
LOOPBACK_HOSTS = ('127.0.0.1', 'localhost', '::1')


def _local_request():
    """The request comes from this box AND names it as localhost. The Host
    check stops DNS rebinding: a web page on evil.example whose name
    resolves to 127.0.0.1 reaches us from a loopback address, but its
    requests still carry Host: evil.example."""
    try:
        host = (urlparse('//' + (request.host or '')).hostname or '').lower()
    except ValueError:
        return False
    return request.remote_addr in LOOPBACK and host in LOOPBACK_HOSTS


def _url_host(url):
    """Host of an http(s) URL, or '' when it is not one."""
    try:
        u = urlparse(url)
        return u.hostname or '' if u.scheme in ('http', 'https') else ''
    except ValueError:
        return ''


def safe_next(nxt):
    """A same-site path to go to after login, else ''. Browsers drop tabs and
    newlines inside URLs, so /\t/evil.example becomes //evil.example."""
    if not nxt or any(ord(c) < 0x20 or c == '\\' for c in nxt):
        return ''
    u = urlparse(nxt)
    if not nxt.startswith('/') or nxt.startswith('//') or u.scheme or u.netloc:
        return ''
    return nxt


def register(app):  # noqa: C901 -- one place for the whole route table

    # -- first run / login ----------------------------------------------------

    @app.route('/setup', methods=['GET', 'POST'])
    def setup():
        if auth.has_users():
            return redirect(url_for('login'))
        if not _local_request():
            # Until the admin exists, whoever opens /setup first becomes admin.
            # Only someone on the box itself may do that.
            return render_template('setup.html', remote=True, error='', min_len=auth.MIN_PASSWORD), 403
        error = ''
        if request.method == 'POST':
            pw, confirm = request.form.get('password', ''), request.form.get('confirm', '')
            error = auth.password_problem(pw, confirm)
            if not error:
                auth.create_user('admin', pw, 'admin')
                user = auth.load_users()['admin']
                auth.login('admin', user)
                flash('Admin account created.', 'ok')
                return redirect(url_for('dashboard'))
        return render_template('setup.html', error=error, min_len=auth.MIN_PASSWORD)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if not auth.has_users():
            return redirect(url_for('setup'))
        error = ''
        if auth.accounts_lost():
            error = ('No user account can be read (data/users.json is missing or damaged). '
                     'On the agent computer run: main.py reset-password')
        elif request.method == 'POST':
            ip = auth.client_ip()
            if not auth.begin_attempt(ip):
                error = 'Too many failed attempts. Wait a few minutes and try again.'
            else:
                name = auth.canonical_name(request.form.get('username', '').strip())
                user = auth.authenticate(name, request.form.get('password', ''))
                if user:
                    auth.clear_failures(ip)
                    auth.login(name, user)
                    return redirect(safe_next(request.args.get('next', '')) or url_for('dashboard'))
                log.warning('Failed login for %r from %s', name[:40], ip)
                error = 'Wrong username or password.'
        # After a failed attempt, keep the user name typed (escaped by Jinja).
        username = request.form.get('username', '').strip()[:100] if request.method == 'POST' else ''
        return render_template('login.html', error=error, username=username)

    @app.route('/logout', methods=['POST'])
    def logout():
        from flask import session
        name, _ = auth.current_user()
        if name:
            auth.revoke_sessions(name)
        session.clear()
        return redirect(url_for('login'))

    @app.route('/health')
    def health():
        status, alive = _engine_state()
        return jsonify({'ok': alive, 'version': __version__}), (200 if alive else 503)

    # -- dashboard -------------------------------------------------------------

    def _sorted_status():
        st, order = _status_payload(), dash_sort()
        st['monitors'] = sort_rows(st['monitors'], order['key'], order['dir'])
        st['sort'] = order
        return st

    @app.route('/')
    @auth.login_required
    def dashboard():
        return render_template('dashboard.html', st=_sorted_status())

    @app.route('/api/status')
    @auth.login_required
    def api_status():
        return jsonify(_sorted_status())

    @app.route('/update/install', methods=['POST'])
    @auth.admin_required
    def update_install():
        if updater.pending():
            touch(paths.INSTALL_TRIGGER)
            flash('Install started. The agent restarts on the new version in a minute or two.', 'ok')
        else:
            flash('No pending update.', 'warn')
        return redirect(url_for('dashboard'))

    @app.route('/service/restart', methods=['POST'])
    @auth.admin_required
    def service_restart():
        touch(paths.RESTART_FLAG)
        flash('Restart requested. The web UI may be unavailable for a few seconds.', 'ok')
        return redirect(url_for('dashboard'))

    # -- monitors --------------------------------------------------------------

    def _find(mid):
        items = monitors.load()
        for i, m in enumerate(items):
            if m['id'] == mid:
                return items, i
        abort(404)

    @app.route('/monitors')
    @auth.admin_required
    def monitors_list():
        items = monitors.load()
        for m in items:
            m['push_display'] = mask_push_url(m['push_url']) if '${' not in m['push_url'] else m['push_url']
        return render_template('monitors.html', items=items)

    @app.route('/monitors/new')
    @auth.admin_required
    def monitor_new():
        return render_template('monitor_form.html', m=monitors.normalize({}), errors=[], is_new=True,
                               types=monitors.TYPES, limits=monitors.LIMITS)

    @app.route('/monitors/<mid>/edit')
    @auth.admin_required
    def monitor_edit(mid):
        items, i = _find(mid)
        return render_template('monitor_form.html', m=items[i], errors=[], is_new=False,
                               types=monitors.TYPES, limits=monitors.LIMITS)

    @app.route('/monitors/save', methods=['POST'])
    @auth.admin_required
    def monitor_save():
        f = request.form
        headers = {}
        for line in f.get('headers', '').splitlines():
            if ':' in line:
                k, v = line.split(':', 1)
                if k.strip():
                    headers[k.strip()] = v.strip()
        raw = {
            'id': f.get('id', ''), 'name': f.get('name', ''), 'type': f.get('type', ''),
            'target': f.get('target', ''), 'port': f.get('port', ''),
            'monitor_url': f.get('monitor_url', ''), 'push_url': f.get('push_url', ''),
            'enabled': f.get('enabled') == 'on', 'timeout': f.get('timeout', 10),
            'retry_count': f.get('retry_count', 3), 'headers': headers,
            'ssl_verify': f.get('ssl_verify') == 'on', 'dns_method': f.get('dns_method', 'auto'),
            'dns_query_name': f.get('dns_query_name', ''),
        }
        m = monitors.normalize(raw)
        errors = monitors.validate(m)
        # normalize() is lenient (it also reads hand-edited files); a typo in
        # the form must be an error, not a silent default.
        for key, label in (('port', 'Port'), ('timeout', 'Timeout'), ('retry_count', 'Attempts')):
            lo, hi, _default = monitors.LIMITS[key]
            value = str(f.get(key, '')).strip()
            if key == 'port' and (not value or m['type'] in ('DNS', 'PING')):
                continue
            if not value.isdigit() or not lo <= int(value) <= hi:
                errors.append('%s must be a whole number from %d to %d.' % (label, lo, hi))
        items = monitors.load()
        if any(o['name'].lower() == m['name'].lower() and o['id'] != m['id'] for o in items):
            errors.append('Another monitor already has that name.')
        if errors:
            return render_template('monitor_form.html', m=m, errors=errors,
                                   is_new=not raw['id'], types=monitors.TYPES, limits=monitors.LIMITS), 400
        for i, o in enumerate(items):
            if o['id'] == m['id']:
                items[i] = m
                break
        else:
            items.append(m)
        monitors.save(items)
        flash('Saved "%s". The engine checks it within a few seconds.' % m['name'], 'ok')
        return redirect(url_for('monitors_list'))

    @app.route('/monitors/<mid>/toggle', methods=['POST'])
    @auth.admin_required
    def monitor_toggle(mid):
        items, i = _find(mid)
        items[i]['enabled'] = not items[i]['enabled']
        monitors.save(items)
        return redirect(url_for('monitors_list'))

    @app.route('/monitors/<mid>/clone', methods=['POST'])
    @auth.admin_required
    def monitor_clone(mid):
        items, i = _find(mid)
        copy_ = dict(items[i], id='', name='Clone ' + items[i]['name'], enabled=False)
        items.append(monitors.normalize(copy_))
        monitors.save(items)
        flash('Cloned as a paused monitor - check its target and push URL, then enable it.', 'ok')
        return redirect(url_for('monitors_list'))

    @app.route('/monitors/<mid>/delete', methods=['POST'])
    @auth.admin_required
    def monitor_delete(mid):
        items, i = _find(mid)
        name = items[i]['name']
        del items[i]
        monitors.save(items)
        flash('Deleted "%s".' % name, 'ok')
        return redirect(url_for('monitors_list'))

    @app.route('/monitors/<mid>/test', methods=['POST'])
    @auth.admin_required
    def monitor_test(mid):
        items, i = _find(mid)
        from ..checks import Checker
        m = monitors.runtime_view(items[i])
        ok, ms, _ = Checker().check(m)
        flash('Test %s: %s (%s ms) - nothing was pushed.' % (m['name'], 'UP' if ok else 'DOWN', ms),
              'ok' if ok else 'warn')
        return redirect(url_for('monitors_list'))

    # -- settings --------------------------------------------------------------

    @app.route('/settings', methods=['GET', 'POST'])
    @auth.admin_required
    def settings_page():
        managed = settings.env_managed()
        s = settings.load()
        errors = []
        if request.method == 'POST':
            f = request.form
            new = {
                'site_name': f.get('site_name', '').strip()[:100],
                'log_level': f.get('log_level', 'INFO'),
                'web': {'port': f.get('web_port', ''), 'host': f.get('web_host', '').strip()},
                'remote': {'enabled': f.get('remote_enabled') == 'on',
                           'require_signed_response': f.get('require_signed', 'auto'),
                           'server_type': f.get('server_type', 'public')},
                'update': {'enabled': f.get('update_enabled') == 'on'},
            }
            # Bounds from settings.BOUNDS, the table load() enforces: an
            # out-of-range value is an error, never silently clamped.
            for field, name, label in (('check_interval', 'check_interval', 'Check every'),
                                       ('max_workers', 'max_workers', 'Parallel checks'),
                                       ('log_retention_days', 'log_retention_days', 'Keep logs'),
                                       ('heartbeat_interval', 'remote.heartbeat_interval', 'Heartbeat every'),
                                       ('web_port', 'web.port', 'Web port')):
                lo, hi = settings.BOUNDS[name]
                value = str(f.get(field, '')).strip()
                if not value.isdigit() or not lo <= int(value) <= hi:
                    errors.append('%s must be a whole number from %d to %d.' % (label, lo, hi))
                    value = s
                    for key in name.split('.'):
                        value = value.get(key, {}) if isinstance(value, dict) else value
                node = new
                for key in name.split('.')[:-1]:
                    node = node.setdefault(key, {})
                node[name.split('.')[-1]] = int(value)
            host = new['web']['host']
            if host and host != 'localhost':
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    errors.append('Web listens on must be an IP address: 0.0.0.0 (every network), '
                                  '127.0.0.1 (this PC only) or one of this PC\'s addresses.')
            new['log_level'] = loglevel.normalize(new['log_level']) or loglevel.DEFAULT
            # '' = same as log_level; anything else must be a level
            levels = {}
            for part in loglevel.NAMES:
                value = loglevel.normalize(f.get('level_' + part, ''))
                if value in loglevel.choices(part):
                    levels[part] = value
            if new['remote']['require_signed_response'] not in ('auto', 'true', 'false'):
                new['remote']['require_signed_response'] = 'auto'
            rs = new['remote']['require_signed_response']
            new['remote']['require_signed_response'] = {'true': True, 'false': False}.get(rs, 'auto')
            if new['remote']['server_type'] not in ('public', 'local'):
                new['remote']['server_type'] = 'public'
            if 'remote.url' not in managed:
                url = f.get('remote_url', '').strip()
                if url and not _url_host(url):
                    errors.append('Public server URL must be an http(s) URL to api/heartbeat.php.')
                new['remote']['url'] = url
            local_url = f.get('local_url', '').strip()
            local_host = _url_host(local_url)
            if local_url and not local_host:
                errors.append('Local server URL must be an http(s) URL to api/heartbeat.php.')
            elif local_host and not is_local_host(local_host):
                # A Local server's certificate is not checked; never accept
                # that for a server out on the internet.
                errors.append('Local server URL must point to this network: localhost, a '
                              '192.168.x.x / 10.x.x.x / 172.16-31.x.x address, or a name that '
                              'resolves to one. %s is not - put it under Public.' % local_host)
            new['remote']['local_url'] = local_url
            if 'remote.api_key' not in managed:
                new['remote']['api_key'] = f.get('api_key', '').strip()
            if 'remote.secret_key' not in managed and f.get('secret_key', '').strip():
                new['remote']['secret_key'] = f.get('secret_key', '').strip()
            if new['remote']['enabled'] and not errors:
                merged = settings.load()
                merged_remote = dict(merged.get('remote', {}), **new['remote'])
                if not active_server_url(merged_remote) or not merged_remote.get('api_key'):
                    errors.append('Reporting needs an API key and a URL for the chosen server '
                                  '(%s).' % ('Local network' if is_local_server(merged_remote)
                                             else 'Public'))
            if not errors:
                restart_web = (new['web']['port'] != s['web'].get('port') or
                               (new['web']['host'] or s['web'].get('host')) != s['web'].get('host'))
                if not new['web']['host']:
                    del new['web']['host']
                merged = deep_merge(settings.load(), new)
                merged['log_levels'] = levels   # replaced, not merged: '' removes an override
                settings.save(merged)
                flash('Settings saved.' + (' Restart the service for the new web address to take '
                                           'effect.' if restart_web else ''), 'ok')
                return redirect(url_for('settings_page'))
            s = deep_merge(s, new)
            s['log_levels'] = levels
        sign_state, sign_since = signing.status(s.get('remote', {}))
        return render_template('settings.html', s=s, managed=managed, errors=errors,
                               has_secret=bool(s.get('remote', {}).get('secret_key')),
                               sign_state=sign_state, sign_since=sign_since,
                               log_levels=loglevel.LEVELS, log_parts=loglevel.COMPONENTS,
                               level_choices=loglevel.choices, bounds=settings.BOUNDS,
                               library_default=loglevel.LIBRARY_DEFAULT)

    @app.route('/settings/new-secret', methods=['POST'])
    @auth.admin_required
    def new_secret():
        if 'remote.secret_key' in settings.env_managed():
            flash('The secret is managed by data/.env - change it there.', 'warn')
            return redirect(url_for('settings_page'))
        secret = secrets.token_urlsafe(32)
        settings.update({'remote': {'secret_key': secret}})
        return render_template('secret.html', secret=secret)

    # -- account / logs --------------------------------------------------------

    @app.route('/account', methods=['GET', 'POST'])
    @auth.login_required
    def account():
        name, user = auth.current_user()
        error = ''
        if request.method == 'POST':
            # Same limit as sign-in, per account: a stolen session cookie
            # must not become an unlimited password oracle.
            key = 'account:' + name
            if not auth.begin_attempt(key):
                error = 'Too many wrong passwords. Wait a few minutes and try again.'
            elif not auth.check_password(request.form.get('current', ''), user.get('password')):
                error = 'Current password is wrong.'
            else:
                auth.clear_failures(key)
                error = auth.password_problem(request.form.get('password', ''),
                                              request.form.get('confirm', ''))
            if not error:
                auth.set_password(name, request.form['password'])
                auth.login(name, auth.load_users()[name])
                flash('Password changed. Other sessions were signed out.', 'ok')
                return redirect(url_for('account'))
        return render_template('account.html', error=error, user=user, name=name,
                               min_len=auth.MIN_PASSWORD)

    @app.route('/logs')
    @auth.admin_required
    def logs():
        level = request.args.get('level', 'INFO')
        if level not in LOG_LEVELS:
            level = 'INFO'
        proc = request.args.get('proc', '')
        if proc not in logsetup.PROCS:
            proc = ''
        text = (request.args.get('q') or '')[:200]
        before = request.args.get('before', type=int)
        if before is not None and not 0 < before < 2 ** 63:
            before = None    # sqlite integers are 64-bit; bigger raises OverflowError
        n = request.args.get('n', type=int)
        if n not in LOG_PAGE_SIZES:
            n = LOG_PAGE
        min_level = LOG_LEVELS[level]
        rows, older_id, window = logstore.page(min_level=min_level, proc=proc, text=text,
                                               before_id=before, limit=n)

        def link(before_id):
            return url_for('logs', level=level, proc=proc or None, q=text or None,
                           n=n if n != LOG_PAGE else None, before=before_id)
        newer = None
        if before:
            # rows[0] is this page's newest line; an empty page sits just below `before`
            top = rows[0]['id'] if rows else before - 1
            newer = link(logstore.newer(min_level, proc, text, top, n))
        for r in rows:
            extra = r['msg'].count('\n') + 1 - LOG_CLAMP_LINES
            r['more'] = extra if extra > 0 else 0
        return render_template('logs.html', rows=rows, level=level, proc=proc, q=text, n=n,
                               sizes=LOG_PAGE_SIZES, levels=list(LOG_LEVELS), procs=logsetup.PROCS,
                               newest=link(None) if before else None, newer=newer,
                               older=link(older_id) if older_id else None,
                               window=window, span=logstore.SEARCH_SPAN,
                               recording=loglevel.describe(settings.load()),
                               stats=logstore.stats(), files=logsetup.text_files())

    @app.route('/logs/file/<name>')
    @auth.admin_required
    def log_file(name):
        lines = logsetup.tail(name, 400)
        if lines is None:
            abort(404)
        return render_template('log_file.html', name=name, lines=list(reversed(lines)))
