from tests import _env  # noqa: F401  (must be first)

import json
import os
import re
import unittest

from uptime_sync import monitors, paths, settings
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
