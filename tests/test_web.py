from tests import _env  # noqa: F401  (must be first)

import json
import os
import re
import unittest

from uptime_sync import monitors, paths, settings, util
from uptime_sync.web import auth, create_app

PW = 'correct horse battery'


class WebTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        auth._attempts.clear()
        self.app = create_app()
        self.app.testing = True
        self.c = self.app.test_client()

    def csrf(self, path='/'):
        html = self.c.get(path).get_data(as_text=True)
        return re.search(r'name="csrf" value="([^"]+)"', html).group(1)

    def setup_admin(self):
        r = self.c.get('/setup')
        token = re.search(r'name="csrf" value="([^"]+)"', r.get_data(as_text=True)).group(1)
        r = self.c.post('/setup', data={'csrf': token, 'password': PW, 'confirm': PW})
        self.assertEqual(r.status_code, 302)

    def test_first_run_goes_to_setup(self):
        r = self.c.get('/')
        self.assertIn('/login', r.headers['Location'])
        self.assertIn('/setup', self.c.get('/login').headers['Location'])

    def test_short_password_refused(self):
        token = re.search(r'name="csrf" value="([^"]+)"',
                          self.c.get('/setup').get_data(as_text=True)).group(1)
        r = self.c.post('/setup', data={'csrf': token, 'password': 'short', 'confirm': 'short'})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(auth.has_users())

    def test_csrf_required(self):
        self.setup_admin()
        r = self.c.post('/monitors/save', data={'name': 'x'})
        self.assertEqual(r.status_code, 400)

    def test_pages_and_headers(self):
        self.setup_admin()
        for path in ('/', '/monitors', '/monitors/new', '/settings', '/logs', '/account',
                     '/api/status', '/logs?level=ERROR&proc=engine&q=x'):
            r = self.c.get(path)
            self.assertEqual(r.status_code, 200, path)
            self.assertIn("script-src 'self'", r.headers['Content-Security-Policy'])
            self.assertEqual(r.headers['Cache-Control'], 'no-store')
            self.assertEqual(r.headers['X-UA-Compatible'], 'IE=edge')
        html = self.c.get('/settings').get_data(as_text=True)
        self.assertNotIn(' style=', html)
        self.assertNotIn('<script>', html)

    def test_save_monitor(self):
        self.setup_admin()
        token = self.csrf('/monitors/new')
        data = {'csrf': token, 'name': 'Gateway', 'type': 'PING', 'target': '10.0.0.1',
                'push_url': 'https://kuma.example.com/api/push/abc', 'enabled': 'on',
                'timeout': '5', 'retry_count': '2'}
        r = self.c.post('/monitors/save', data=data)
        self.assertEqual(r.status_code, 302)
        self.assertEqual([m['name'] for m in monitors.load()], ['Gateway'])
        r = self.c.post('/monitors/save', data=dict(data, push_url='http://kuma/api/push/abc'))
        self.assertEqual(r.status_code, 400)

    def test_env_secret_never_rendered(self):
        with open(paths.ENV_FILE, 'w') as f:
            f.write('UPTIME_API_KEY=ENVAPIKEYVALUE\nUPTIME_SECRET_KEY=ENVSECRETVALUE\n')
        settings.update({'remote': {'url': 'https://mon.example.com/api/heartbeat.php'}})
        self.setup_admin()
        html = self.c.get('/settings').get_data(as_text=True)
        self.assertNotIn('ENVAPIKEYVALUE', html)
        self.assertNotIn('ENVSECRETVALUE', html)
        self.assertIn('Managed by data/.env', html)

    def test_viewer_is_read_only(self):
        self.setup_admin()
        auth.create_user('viewer1', PW, role='viewer')
        self.c = self.app.test_client()
        token = self.csrf('/login')
        r = self.c.post('/login', data={'csrf': token, 'username': 'viewer1', 'password': PW})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.c.get('/').status_code, 200)
        for path in ('/settings', '/monitors', '/logs'):
            self.assertIn(self.c.get(path).status_code, (302, 403), path)

    def test_password_change_signs_out_other_sessions(self):
        self.setup_admin()
        other = self.app.test_client()
        token = re.search(r'name="csrf" value="([^"]+)"',
                          other.get('/login').get_data(as_text=True)).group(1)
        other.post('/login', data={'csrf': token, 'username': 'admin', 'password': PW})
        self.assertEqual(other.get('/').status_code, 200)
        auth.set_password('admin', PW + '2')
        self.assertEqual(other.get('/').status_code, 302)

    def test_login_rate_limit(self):
        self.setup_admin()
        self.c = self.app.test_client()
        for _ in range(auth.MAX_ATTEMPTS):
            token = self.csrf('/login')
            self.c.post('/login', data={'csrf': token, 'username': 'admin', 'password': 'wrong'})
        token = self.csrf('/login')
        r = self.c.post('/login', data={'csrf': token, 'username': 'admin', 'password': PW})
        self.assertIn('Too many', r.get_data(as_text=True))

    def test_status_api_masks_push_tokens(self):
        self.setup_admin()
        with open(paths.STATUS_FILE, 'w') as f:
            json.dump({'monitors': {}, 'updated_at': 'x'}, f)
        monitors.save([monitors.normalize({'name': 'g', 'type': 'PING', 'target': '1.1.1.1',
                                           'push_url': 'https://k/api/push/' + 'SECRETTOKEN1'})])
        for path in ('/api/status', '/monitors'):
            self.assertNotIn('SECRETTOKEN1', self.c.get(path).get_data(as_text=True), path)

    def test_port_only_for_types_that_use_it(self):
        html = _read('templates', 'monitor_form.html')
        self.assertIn('<label data-for-types="TCP HTTP HTTPS">Port', html)
        for t in ('DNS', 'PING'):
            self.assertIsNone(monitors.normalize({'type': t, 'port': 8080})['port'], t)
        self.assertEqual(monitors.normalize({'type': 'TCP PORT', 'port': '8080'})['port'], 8080)
        self.assertEqual(monitors.normalize({'type': 'HTTPS', 'port': 8443})['port'], 8443)

    def test_push_url_drops_params_the_agent_sends(self):
        base = 'https://kuma.example/api/push/' + 'abc'
        self.assertEqual(monitors.push_base_url(base + '?status=up&msg=OK&ping='), base)
        self.assertEqual(monitors.push_base_url(base), base)
        self.assertEqual(monitors.push_base_url(base + '?Status=up&x=1&dns_ping=3'), base + '?x=1')

    def test_monitor_form_examples_and_placeholders(self):
        self.setup_admin()
        html = self.c.get('/monitors/new').get_data(as_text=True)
        self.assertIn('class="card flush examples"', html)
        for name in ('name', 'target', 'port', 'monitor_url', 'push_url', 'dns_query_name'):
            self.assertRegex(html, r'name="%s"[^>]*placeholder="[^"]+"' % name, name)
        ph = re.search(r'name="target"[^>]*data-ph="([^"]+)"', html).group(1)
        keys = set(p.split('=')[0] for p in ph.split('|'))
        self.assertEqual(keys, set(t.split(' ')[0] for t in monitors.TYPES))

    def test_setup_only_from_the_box_itself(self):
        lan = {'REMOTE_ADDR': '192.168.10.50'}
        r = self.c.get('/setup', environ_base=lan)
        self.assertEqual(r.status_code, 403)
        self.assertIn('only be created on this PC', r.get_data(as_text=True))
        r = self.c.post('/setup', data={'password': PW, 'confirm': PW}, environ_base=lan)
        self.assertIn(r.status_code, (400, 403))
        self.assertFalse(auth.has_users())

    def test_login_next_cannot_leave_the_site(self):
        from uptime_sync.web.views import safe_next
        for bad in ('//evil.example', '/\t/evil.example', '/\\evil', 'https://evil.example/', '/\n/x', ''):
            self.assertEqual(safe_next(bad), '', repr(bad))
        self.assertEqual(safe_next('/monitors?x=1'), '/monitors?x=1')

    def test_logout_revokes_a_copied_cookie(self):
        self.setup_admin()
        token = self.csrf('/settings')
        cookie = self.c.get_cookie('session')
        stolen = self.app.test_client()
        stolen.set_cookie('session', cookie.value)
        self.assertEqual(stolen.get('/settings').status_code, 200)
        self.c.post('/logout', data={'csrf': token})
        self.assertEqual(stolen.get('/settings').status_code, 302)

    def test_bad_csrf_value_is_400_not_500(self):
        self.setup_admin()
        self.assertEqual(self.c.post('/monitors/save', data={'csrf': '\u00e9'}).status_code, 400)

    def test_monitor_ids_made_unique_on_load(self):
        with open(paths.MONITORS_FILE, 'w') as f:
            json.dump({'monitors': [{'id': 'monitor_3', 'name': 'A', 'type': 'PING', 'target': 'a'},
                                    {'id': 'monitor_3', 'name': 'B', 'type': 'PING', 'target': 'b'},
                                    {'name': 'C', 'type': 'PING', 'target': 'c'}]}, f)
        first = [m['id'] for m in monitors.load()]
        self.assertEqual(len(set(first)), 3)
        self.assertEqual(first, [m['id'] for m in monitors.load()])   # stable without a save
        self.assertEqual(first[0], 'monitor_3')

    def test_monitor_form_refuses_bad_numbers_and_headers(self):
        self.setup_admin()
        token = self.csrf('/monitors/new')
        base = {'csrf': token, 'name': 'w', 'type': 'HTTP', 'target': 'example.com',
                'push_url': 'https://k.example/api/push/x', 'timeout': '10', 'retry_count': '3'}
        cases = (({'port': '8o8o'}, 'Port must be'), ({'timeout': 'abc'}, 'Timeout must be'),
                 ({'headers': 'X Bad: 1'}, 'not valid'),
                 ({'headers': 'X-Site: \u0e17\u0e14\u0e2a\u0e2d\u0e1a'}, 'Latin'))
        for extra, msg in cases:
            r = self.c.post('/monitors/save', data=dict(base, **extra))
            self.assertEqual(r.status_code, 400, extra)
            self.assertIn(msg, r.get_data(as_text=True), extra)
        self.assertEqual(monitors.load(), [])

    def test_http_target_optional_with_monitor_url(self):
        m = monitors.normalize({'name': 'h', 'type': 'HTTPS', 'target': '', 'monitor_url': 'https://site.example/health',
                                'push_url': 'https://k.example/api/push/x'})
        self.assertEqual(m['target'], 'site.example')
        self.assertEqual(monitors.validate(m), [])

    def test_web_host_must_be_an_ip(self):
        self.setup_admin()
        token = self.csrf('/settings')
        r = self.c.post('/settings', data={'csrf': token, 'web_host': 'not a host!', 'web_port': '5000',
                                           'check_interval': '60', 'max_workers': '10',
                                           'log_retention_days': '14', 'heartbeat_interval': '60'})
        self.assertEqual(r.status_code, 200)
        self.assertIn('must be an IP address', r.get_data(as_text=True))
        self.assertNotEqual(settings.load()['web'].get('host'), 'not a host!')

    def test_logs_huge_before_is_not_a_500(self):
        self.setup_admin()
        self.assertEqual(self.c.get('/logs?before=999999999999999999999999').status_code, 200)

    def test_heartbeat_error_is_red(self):
        from uptime_sync.web.views import tones
        p = {'engine': {'running': True}, 'monitors': [], 'signing': {'state': 'not-yet'},
             'heartbeat': {'enabled': True, 'failures': 0, 'last_ok': 1, 'error': 'HTTP 401'}}
        self.assertEqual(tones(p)['heartbeat'], 'bad')

    def test_tile_tones(self):
        from uptime_sync.web.views import tones

        def payload(running=True, states=(), hb_on=False, failures=0, last_ok=None, sign='not-yet'):
            return {'engine': {'running': running},
                    'monitors': [{'enabled': st != 'paused', 'state': st} for st in states],
                    'heartbeat': {'enabled': hb_on, 'failures': failures, 'last_ok': last_ok},
                    'signing': {'state': sign}}
        t = tones(payload())
        self.assertEqual(t, {'engine': 'ok', 'monitors': 'off', 'heartbeat': 'off', 'signing': 'off'})
        self.assertEqual(tones(payload(running=False))['engine'], 'bad')
        self.assertEqual(tones(payload(states=('up', 'paused')))['monitors'], 'ok')
        self.assertEqual(tones(payload(states=('up', 'unknown')))['monitors'], 'warn')
        self.assertEqual(tones(payload(states=('up', 'down')))['monitors'], 'bad')
        self.assertEqual(tones(payload(hb_on=True))['heartbeat'], 'warn')
        self.assertEqual(tones(payload(hb_on=True, last_ok=1))['heartbeat'], 'ok')
        self.assertEqual(tones(payload(hb_on=True, last_ok=1, failures=2))['heartbeat'], 'bad')
        self.assertEqual(tones(payload(hb_on=True, sign='enforced'))['signing'], 'ok')
        self.assertEqual(tones(payload(hb_on=True, sign='off'))['signing'], 'warn')

    def test_dashboard_tiles_carry_tones(self):
        self.setup_admin()
        html = self.c.get('/').get_data(as_text=True)
        for key in ('engine', 'monitors', 'heartbeat', 'signing'):
            self.assertRegex(html, r'class="tile tone-(ok|warn|bad|off)" data-tile="%s"' % key)
        st = json.loads(self.c.get('/api/status').get_data(as_text=True))
        self.assertEqual(set(st['tones']), {'engine', 'monitors', 'heartbeat', 'signing'})
        self.assertEqual(st['counts'], {'up': 0, 'enabled': 0})



WEB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'uptime_sync', 'web')


def _read(*rel):
    with open(os.path.join(WEB, *rel), encoding='utf-8') as f:
        return f.read()


def _supports_split(css):
    """(css outside @supports blocks, css inside them)."""
    outside, inside, i = [], [], 0
    while True:
        j = css.find('@supports', i)
        if j < 0:
            outside.append(css[i:])
            return ''.join(outside), ''.join(inside)
        outside.append(css[i:j])
        k, depth = css.index('{', j), 0
        for n in range(k, len(css)):
            depth += {'{': 1, '}': -1}.get(css[n], 0)
            if depth == 0:
                break
        inside.append(css[k:n + 1])
        i = n + 1


class OldBrowserTests(unittest.TestCase):
    """Windows 7 boxes open the UI in IE8-IE11 (see the header of app.css)."""

    def setUp(self):
        self.css = re.sub(r'/\*.*?\*/', '', _read('static', 'app.css'), flags=re.S)

    def test_one_password_eye(self):
        # IE10/11 and Edge draw their own reveal eye on top of app.js's one.
        self.assertIn('input::-ms-reveal { display: none; }', self.css)
        # A rule with a selector the browser does not know is dropped whole,
        # so each vendor pseudo-element sits alone in its rule.
        for sel in re.findall(r'([^{}]*::-(?:ms|webkit)-[^{}]*)\{', self.css):
            self.assertNotIn(',', sel, sel.strip())
        js = _read('static', 'app.js')
        self.assertIn('canSwitchType()', js)          # IE8 cannot switch type: no button
        self.assertIn("input.type = 'password'", js)  # reset before the form is sent

    def test_every_var_has_a_literal_fallback(self):
        for body in re.findall(r'\{([^{}]*)\}', self.css):
            decls = [d.strip() for d in body.split(';') if d.strip()]
            for prev, decl in zip([''] + decls, decls):
                if 'var(' not in decl or decl.startswith('--'):
                    continue
                prop = decl.split(':', 1)[0].strip()
                self.assertTrue(prev.split(':', 1)[0].strip() == prop and 'var(' not in prev,
                                'no IE fallback before: %s' % decl)

    def test_flex_grid_gap_only_inside_supports(self):
        outside, inside = _supports_split(self.css)
        self.assertIn('display: grid', inside)
        self.assertIsNone(re.search(r'\drem\b', self.css), 'IE8 has no rem: use px')
        for pattern in (r'display:\s*(flex|grid)', r'(^|[;{\s])gap:', r'grid-template'):
            self.assertIsNone(re.search(pattern, outside), pattern)

    def test_templates_use_no_html5_sectioning_tags(self):
        for name in os.listdir(os.path.join(WEB, 'templates')):
            html = _read('templates', name)
            for tag in ('main', 'header', 'nav', 'footer', 'section', 'article', 'aside'):
                self.assertNotIn('<%s' % tag, html, '%s uses <%s> (IE8 cannot style it)' % (name, tag))

    def test_base_template_asks_ie_for_its_best_mode(self):
        self.assertIn('<meta http-equiv="X-UA-Compatible" content="IE=edge">', _read('templates', 'base.html'))

    def test_app_js_is_es3(self):
        js = re.sub(r'/\*.*?\*/|//[^\n]*', '', _read('static', 'app.js'), flags=re.S)
        for token in ('=>', 'const ', 'let ', '`', 'fetch(', '.forEach(', 'classList', '.closest(',
                      '.matches(', '.filter(', '.map(', 'Object.assign', 'replaceChildren',
                      '.innerHTML'):
            self.assertNotIn(token, js, token)


if __name__ == '__main__':
    unittest.main()


class ServerTypeTests(unittest.TestCase):
    """Settings > Reporting: Public / Local network, each with its own URL (4.0.9)."""

    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        auth._attempts.clear()
        self.app = create_app()
        self.app.testing = True
        self.c = self.app.test_client()
        WebTests.setup_admin(self)

    def post(self, server_type, public='', local='', enabled=False):
        token = WebTests.csrf(self, '/settings')
        form = {'csrf': token, 'site_name': '', 'check_interval': '60', 'max_workers': '10',
                'log_retention_days': '14', 'log_level': 'INFO', 'web_port': '5000', 'web_host': '',
                'heartbeat_interval': '60', 'require_signed': 'auto', 'remote_url': public,
                'local_url': local, 'api_key': 'k', 'server_type': server_type}
        if enabled:
            form['remote_enabled'] = 'on'
        return self.c.post('/settings', data=form)

    def test_radios_and_two_url_fields(self):
        html = self.c.get('/settings').get_data(as_text=True)
        self.assertIn('name="server_type" value="public" id="server-public" checked', html)
        self.assertIn('name="remote_url"', html)
        self.assertIn('name="local_url"', html)
        self.assertIn('data-selects="server-local"', html)

    def test_each_type_keeps_its_own_url(self):
        pub = 'https://mon.example.com/api/heartbeat.php'
        loc = 'http://192.168.1.10/uptime-monitor/api/heartbeat.php'
        self.assertEqual(self.post('local', pub, loc, enabled=True).status_code, 302)
        r = settings.load()['remote']
        self.assertEqual((r['server_type'], r['url'], r['local_url']), ('local', pub, loc))
        self.assertEqual(util.active_server_url(r), loc)
        html = self.c.get('/settings').get_data(as_text=True)
        self.assertIn('value="local" id="server-local" checked', html)
        self.assertIn('value="%s"' % pub, html)
        self.assertEqual(self.post('public', pub, loc, enabled=True).status_code, 302)
        r = settings.load()['remote']
        self.assertEqual((util.active_server_url(r), r['local_url']), (pub, loc))

    def test_local_url_must_be_on_this_network(self):
        r = self.post('public', '', 'https://8.8.8.8/api/heartbeat.php')
        self.assertEqual(r.status_code, 200)
        self.assertIn('put it under Public', r.get_data(as_text=True))
        self.assertEqual(settings.load()['remote']['local_url'], '')

    def test_chosen_type_needs_its_url(self):
        r = self.post('local', 'https://mon.example.com/api/heartbeat.php', '', enabled=True)
        self.assertEqual(r.status_code, 200)
        self.assertIn('chosen server (Local network)', r.get_data(as_text=True))

    def test_public_accepts_any_http_url(self):
        self.assertEqual(self.post('public', 'http://10.0.0.5/api/heartbeat.php').status_code, 302)
        self.assertEqual(self.post('bogus', 'https://mon.example.com/api/heartbeat.php').status_code, 302)
        self.assertEqual(settings.load()['remote']['server_type'], 'public')


class DictMethodNameTests(unittest.TestCase):
    """Jinja looks up `x.update` as dict.update (the method) before the key:
    the Install updates box rendered unticked, so saving Settings turned
    updates off, and the dashboard never showed a pending update."""

    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        auth._attempts.clear()
        self.app = create_app()
        self.app.testing = True
        self.c = self.app.test_client()
        WebTests.setup_admin(self)

    def test_settings_shows_update_settings(self):
        html = self.c.get('/settings').get_data(as_text=True)
        self.assertIn('name="update_enabled" checked', html)
        self.assertIn('GitHub (chuwa22/uptime-sync-v4)', html)

    def test_dashboard_offers_a_pending_update(self):
        from uptime_sync import updater
        updater.write_pending('99.0.0', 'u', 'a' * 64, 'manual')
        self.assertIn('Version <b>99.0.0</b> is ready to install', self.c.get('/').get_data(as_text=True))

    def test_no_dict_method_names_in_templates(self):
        tdir = os.path.join(_env.REPO, 'uptime_sync', 'web', 'templates')
        bad = re.compile(r'\b\w+\.(update|items|keys|values|pop|copy|clear|setdefault)\b(?!\()')
        for name in os.listdir(tdir):
            with open(os.path.join(tdir, name), encoding='utf-8') as f:
                for i, line in enumerate(f, 1):
                    self.assertIsNone(bad.search(line), '%s:%d %s' % (name, i, line.strip()))


class PhoneLayoutTests(unittest.TestCase):
    """Below 640px each row of a table.stack is shown as a small card: the
    cell classes (title, lead, wide) and data-label carry that layout."""

    ROLE = re.compile(r'\b(title|lead|wide|empty|row-actions)\b')

    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        auth._attempts.clear()
        self.app = create_app()
        self.app.testing = True
        self.c = self.app.test_client()
        WebTests.setup_admin(self)
        monitors.save([monitors.normalize({'name': 'g', 'type': 'PING', 'target': '1.1.1.1',
                                           'push_url': 'https://kuma.example.com/api/push/abc'})])

    def test_every_stacked_cell_has_a_role_or_label(self):
        for path in ('/', '/monitors', '/monitors/new'):
            html = self.c.get(path).get_data(as_text=True)
            tables = re.findall(r'<table class="[^"]*\bstack\b[^"]*">(.*?)</table>', html, re.S)
            self.assertTrue(tables, path)
            for table in tables:
                for td in re.findall(r'<td\b[^>]*>', table.split('</thead>')[-1]):
                    self.assertTrue('data-label=' in td or self.ROLE.search(td), '%s %s' % (path, td))
        # Log rows read fine without labels; the message takes its own line.
        logs = _read('templates', 'logs.html')
        self.assertIn('<table class="logtable stack">', logs)
        self.assertIn('<td class="wide"><pre class="msg">', logs)

    def test_live_dashboard_rows_keep_the_labels(self):
        js = _read('static', 'app.js')
        for label in ('Type', 'Target', 'Response', 'Uptime', 'Checked'):
            self.assertIn("'%s')" % label, js)
        self.assertIn("cell(m.name, 'title')", js)
        self.assertIn("td.className = 'lead'", js)

    def test_phone_rules_are_hidden_from_ie(self):
        css = re.sub(r'/\*.*?\*/', '', _read('static', 'app.css'), flags=re.S)
        outside, inside = _supports_split(css)
        self.assertIn('@media (max-width: 640px)', inside)
        self.assertNotIn('max-width: 640px', outside)
