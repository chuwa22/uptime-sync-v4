"""The web UI (Flask, served by waitress). Runs as the supervisor's `web`
child; reads the files the engine writes and edits data/*.json. It never
runs checks or talks to the server itself.

Templates carry markup only: no inline style, no inline script, no on*=
handlers -- behaviour lives in static/app.js (data-* attributes), looks in
static/app.css. That keeps the CSP at script-src 'self'.
"""

import datetime
import logging
import os
import threading
import time

from flask import Flask, abort, request

from .. import __version__, log as logsetup, loglevel, paths, procs, settings
from ..util import remove_quietly
from . import auth, hardening, icons

log = logging.getLogger('web')


def create_app():
    app = Flask(__name__, static_folder='static', template_folder='templates')
    app.config.update(
        SECRET_KEY=auth.app_secret_key(),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=datetime.timedelta(hours=12),
        MAX_CONTENT_LENGTH=1024 * 1024,
        JSON_SORT_KEYS=False,
    )
    app.jinja_env.globals['icon'] = icons.icon
    boot = str(int(time.time()))

    @app.context_processor
    def globals_():
        name, user = auth.current_user()
        s = settings.load()
        return {
            'version': __version__,
            'asset_v': __version__ + '-' + boot,
            'site_name': s.get('site_name') or 'Uptime Sync',
            'current_user': name,
            'is_admin': bool(user) and user.get('role', 'admin') == 'admin',
            'current_role': (user.get('role') or 'admin') if user else '',
            'csrf_token': auth.csrf_token,
        }

    @app.before_request
    def csrf_guard():
        if hardening.names_a_device(request.path):
            abort(404)
        if request.method == 'POST':
            auth.check_csrf()

    @app.after_request
    def headers(resp):
        resp.headers['Content-Security-Policy'] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
        resp.headers['X-Frame-Options'] = 'DENY'
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['Referrer-Policy'] = 'same-origin'
        # IE puts localhost and LAN addresses in the intranet zone and renders
        # them as IE7 unless told otherwise (Windows 7 ships IE8-IE11).
        resp.headers['X-UA-Compatible'] = 'IE=edge'
        if request.path.startswith('/static/') and request.args.get('v'):
            resp.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
        elif not request.path.startswith('/static/'):
            resp.headers['Cache-Control'] = 'no-store'
            # Flask 3.1.3 (CVE-2026-27205) adds this when the session is
            # read; Flask 2.3 (Python 3.8) does not. Every page depends on it.
            resp.vary.add('Cookie')
        return resp

    from . import views
    views.register(app)
    return app


def _watch(parent_pid):
    flag = paths.child_stop_flag('web')
    while True:
        time.sleep(1)
        loglevel.refresh()
        if os.path.exists(flag) or (parent_pid and not procs.pid_alive(parent_pid)):
            log.info('Web UI stopping')
            remove_quietly(paths.child_pid_file('web'))
            logging.shutdown()
            os._exit(0)


def main(parent_pid=0):
    paths.ensure_dirs()
    s = settings.load()
    logsetup.setup('web', s)
    host = s.get('web', {}).get('host', '0.0.0.0')
    port = int(s.get('web', {}).get('port', 5000))
    procs.write_pid(paths.child_pid_file('web'))
    remove_quietly(paths.child_stop_flag('web'))
    threading.Thread(target=_watch, args=(parent_pid,), daemon=True).start()
    app = create_app()
    log.info('Web UI %s listening on http://%s:%d', __version__, host, port)
    from waitress import serve
    hardening.patch_waitress()
    serve(app, host=host, port=port, **hardening.SERVE_OPTIONS)
    return 0
