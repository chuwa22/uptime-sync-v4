"""Routes. Every state-changing route is POST (CSRF-checked in
__init__.csrf_guard) and admin-only."""

import logging
import secrets
import time
from urllib.parse import urlparse

from flask import abort, flash, jsonify, redirect, render_template, request, url_for

from .. import __version__, log as logsetup, logstore, monitors, paths, procs, settings, signing, updater
from ..util import deep_merge, read_json, touch
from . import auth

log = logging.getLogger('web')
LOG_LEVELS = logstore.LEVELS
LOG_PAGE = 300


def _engine_state():
    status = read_json(paths.STATUS_FILE, {}) or {}
    pid = procs.read_pid(paths.child_pid_file('engine'))
    alive = procs.pid_alive(pid)
    return status, alive


def _uptime(history):
    if not history:
        return None
    return round(100.0 * sum(1 for h in history if h[1]) / len(history), 1)


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
    return '%s://%s%s' % (u.scheme, u.netloc, path)


def _status_payload():
    status, alive = _engine_state()
    history = read_json(paths.HISTORY_FILE, {}) or {}
    results = status.get('monitors', {})
    rows = []
    for m in monitors.load():
        r = results.get(m['id'], {})
        rows.append({
            'id': m['id'], 'name': m['name'], 'type': m['type'], 'target': m['target'],
            'enabled': m['enabled'],
            'state': ('paused' if not m['enabled'] else
                      'unknown' if 'ok' not in r else 'up' if r['ok'] else 'down'),
            'ms': r.get('ms'), 'checked_at': r.get('checked_at', ''),
            'uptime': _uptime(history.get(m['id'], [])),
        })
    s = settings.load()
    hb = status.get('heartbeat', {})
    sign_state, sign_since = signing.status(s.get('remote', {}))
    pending = updater.pending()
    return {
        'version': __version__,
        'engine': {'running': alive, 'updated_at': status.get('updated_at', '')},
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


def register(app):  # noqa: C901 -- one place for the whole route table

    # -- first run / login ----------------------------------------------------

    @app.route('/setup', methods=['GET', 'POST'])
    def setup():
        if auth.has_users():
            return redirect(url_for('login'))
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
        if request.method == 'POST':
            ip = auth.client_ip()
            if auth.rate_limited(ip):
                error = 'Too many failed attempts. Wait a few minutes and try again.'
            else:
                name = request.form.get('username', '').strip()
                user = auth.authenticate(name, request.form.get('password', ''))
                if user:
                    auth.clear_failures(ip)
                    auth.login(name, user)
                    nxt = request.args.get('next', '')
                    return redirect(nxt if nxt.startswith('/') and not nxt.startswith('//')
                                    else url_for('dashboard'))
                auth.note_failure(ip)
                log.warning('Failed login for %r from %s', name[:40], ip)
                error = 'Wrong username or password.'
        return render_template('login.html', error=error)

    @app.route('/logout', methods=['POST'])
    def logout():
        from flask import session
        session.clear()
        return redirect(url_for('login'))

    @app.route('/health')
    def health():
        status, alive = _engine_state()
        return jsonify({'ok': alive, 'version': __version__}), (200 if alive else 503)

    # -- dashboard -------------------------------------------------------------

    @app.route('/')
    @auth.login_required
    def dashboard():
        return render_template('dashboard.html', st=_status_payload())

    @app.route('/api/status')
    @auth.login_required
    def api_status():
        return jsonify(_status_payload())

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
                               types=monitors.TYPES)

    @app.route('/monitors/<mid>/edit')
    @auth.admin_required
    def monitor_edit(mid):
        items, i = _find(mid)
        return render_template('monitor_form.html', m=items[i], errors=[], is_new=False,
                               types=monitors.TYPES)

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
        items = monitors.load()
        if any(o['name'].lower() == m['name'].lower() and o['id'] != m['id'] for o in items):
            errors.append('Another monitor already has that name.')
        if errors:
            return render_template('monitor_form.html', m=m, errors=errors,
                                   is_new=not raw['id'], types=monitors.TYPES), 400
        for i, o in enumerate(items):
            if o['id'] == m['id']:
                items[i] = m
                break
        else:
            items.append(m)
        monitors.save(items)
        flash('Saved "%s". The engine picks it up on its next cycle.' % m['name'], 'ok')
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
                           'require_signed_response': f.get('require_signed', 'auto')},
                'update': {'enabled': f.get('update_enabled') == 'on'},
            }
            for key, lo, hi in (('check_interval', 10, 3600), ('max_workers', 1, 50),
                                ('log_retention_days', 1, 365)):
                try:
                    new[key] = min(hi, max(lo, int(f.get(key, ''))))
                except ValueError:
                    errors.append('%s must be a number.' % key.replace('_', ' ').capitalize())
            try:
                new['remote']['heartbeat_interval'] = min(3600, max(30, int(f.get('heartbeat_interval', 60))))
            except ValueError:
                errors.append('Heartbeat interval must be a number.')
            try:
                port = int(new['web']['port'])
                if not 0 < port < 65536:
                    raise ValueError
                new['web']['port'] = port
            except ValueError:
                errors.append('Web port must be between 1 and 65535.')
            if new['log_level'] not in ('DEBUG', 'INFO', 'WARNING', 'ERROR'):
                new['log_level'] = 'INFO'
            if new['remote']['require_signed_response'] not in ('auto', 'true', 'false'):
                new['remote']['require_signed_response'] = 'auto'
            rs = new['remote']['require_signed_response']
            new['remote']['require_signed_response'] = {'true': True, 'false': False}.get(rs, 'auto')
            if 'remote.url' not in managed:
                url = f.get('remote_url', '').strip()
                u = urlparse(url)
                if url and (u.scheme not in ('http', 'https') or not u.hostname):
                    errors.append('Server URL must be an http(s) URL to api/heartbeat.php.')
                new['remote']['url'] = url
            if 'remote.api_key' not in managed:
                new['remote']['api_key'] = f.get('api_key', '').strip()
            if 'remote.secret_key' not in managed and f.get('secret_key', '').strip():
                new['remote']['secret_key'] = f.get('secret_key', '').strip()
            if new['remote']['enabled'] and not errors:
                merged = settings.load()
                merged_remote = dict(merged.get('remote', {}), **new['remote'])
                if not merged_remote.get('url') or not merged_remote.get('api_key'):
                    errors.append('Reporting needs a server URL and an API key.')
            if not errors:
                restart_web = (new['web']['port'] != s['web'].get('port') or
                               (new['web']['host'] or s['web'].get('host')) != s['web'].get('host'))
                if not new['web']['host']:
                    del new['web']['host']
                settings.update(new)
                flash('Settings saved.' + (' Restart the service for the new web address to take '
                                           'effect.' if restart_web else ''), 'ok')
                return redirect(url_for('settings_page'))
            s = deep_merge(s, new)
        sign_state, sign_since = signing.status(s.get('remote', {}))
        return render_template('settings.html', s=s, managed=managed, errors=errors,
                               has_secret=bool(s.get('remote', {}).get('secret_key')),
                               sign_state=sign_state, sign_since=sign_since)

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
            if not auth.check_password(request.form.get('current', ''), user.get('password')):
                error = 'Current password is wrong.'
            else:
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
        rows = logstore.query(min_level=LOG_LEVELS[level], proc=proc, text=text,
                              before_id=before, limit=LOG_PAGE + 1)
        more = len(rows) > LOG_PAGE
        rows = rows[:LOG_PAGE]
        older = url_for('logs', level=level, proc=proc or None, q=text or None,
                        before=rows[-1]['id']) if more else None
        return render_template('logs.html', rows=rows, level=level, proc=proc, q=text,
                               levels=list(LOG_LEVELS), procs=logsetup.PROCS, older=older,
                               paged=bool(before), stats=logstore.stats(),
                               files=logsetup.text_files())

    @app.route('/logs/file/<name>')
    @auth.admin_required
    def log_file(name):
        lines = logsetup.tail(name, 400)
        if lines is None:
            abort(404)
        return render_template('log_file.html', name=name, lines=list(reversed(lines)))
