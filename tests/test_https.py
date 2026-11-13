"""HTTPS for the web UI (4.4.0): the stdlib self-signed certificate, the
TLS channel under waitress (a real handshake on a real socket), the plain
http redirect, and the Settings / sign-in page wording."""

from tests import _env  # must be first: it points UPTIME_SYNC_ROOT at a temp copy
_env  # imported for that alone; naming it keeps pyflakes quiet (it ignores noqa)

import contextlib
import datetime
import http.client
import io
import os
import shutil
import socket
import ssl
import threading
import unittest
from unittest import mock

from tests import test_web
from uptime_sync import cli, paths, settings
from uptime_sync.web import certgen, create_app, hardening, tls

_KEY = []


def cached_key(bits=certgen.KEY_BITS):
    """One real 2048-bit key for the whole module: making one takes seconds."""
    if not _KEY:
        _KEY.append(certgen.new_key(bits))
    return _KEY[0]


def make_cert(directory, name='c'):
    cn, dns, ips = certgen.local_names()
    key = cached_key()
    der = certgen.certificate_der(key, cn, dns, ips)
    cert, keyfile = os.path.join(directory, name + '.pem'), os.path.join(directory, name + '.key')
    with open(cert, 'w') as f:
        f.write(certgen.pem('CERTIFICATE', der))
    with open(keyfile, 'w') as f:
        f.write(certgen.pem('RSA PRIVATE KEY', certgen.private_key_der(key)))
    return cert, keyfile, der


class CertGenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = os.path.join(paths.ROOT, 'certgen-test')
        os.makedirs(cls.dir, exist_ok=True)
        cls.cert, cls.key, cls.der = make_cert(cls.dir)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def test_openssl_loads_the_pair(self):
        ctx = tls._context(self.cert, self.key)     # raises when cert and key do not match
        self.assertTrue(ctx.get_ciphers())

    def test_the_certificate_says_what_browsers_need(self):
        info = ssl._ssl._test_decode_cert(self.cert)
        self.assertEqual(info['version'], 3)
        names = info['subjectAltName']
        self.assertIn(('DNS', 'localhost'), names)
        self.assertIn(('IP Address', '127.0.0.1'), names)
        self.assertEqual(info['subject'], info['issuer'])

    def test_validity_is_825_days_from_yesterday(self):
        start, end = certgen.validity(self.der)
        self.assertEqual(end - start, datetime.timedelta(days=825))
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        self.assertLess(start, now - datetime.timedelta(hours=23))

    def test_a_date_from_2050_is_generalized_time(self):
        der = certgen.certificate_der(cached_key(), 'x', ['x'], ['127.0.0.1'],
                                      now=datetime.datetime(2049, 6, 1))
        start, end = certgen.validity(der)
        self.assertEqual((start.year, end.year), (2049, 2051))

    def test_der_integers(self):
        self.assertEqual(certgen._int(0), b'\x02\x01\x00')
        self.assertEqual(certgen._int(127), b'\x02\x01\x7f')
        self.assertEqual(certgen._int(128), b'\x02\x02\x00\x80')
        self.assertEqual(certgen._int(256), b'\x02\x02\x01\x00')
        self.assertEqual(certgen._oid('1.2.840.113549.1.1.11'), bytes.fromhex('06092a864886f70d01010b'))

    def test_the_signature_verifies(self):
        key = cached_key()
        sig = int.from_bytes(certgen._sign(key, b'hello'), 'big')
        self.assertEqual(pow(sig, key['e'], key['n']).to_bytes(256, 'big')[-32:],
                         __import__('hashlib').sha256(b'hello').digest())

    def test_junk_is_not_a_certificate(self):
        for junk in (b'', b'\x30\x03\x02\x01\x00', b'\xff' * 40):
            with self.assertRaises(ValueError):
                certgen.validity(junk)

    def test_fingerprint_looks_like_the_browsers(self):
        fp = certgen.fingerprint(self.der)
        self.assertEqual(len(fp), 32 * 3 - 1)
        self.assertRegex(fp, r'^([0-9A-F]{2}:){31}[0-9A-F]{2}$')

    def test_local_names_take_an_ip_host_and_skip_junk(self):
        cn, dns, ips = certgen.local_names('192.168.77.5')
        self.assertIn('localhost', dns)
        self.assertIn('192.168.77.5', ips)
        cn, dns, ips = certgen.local_names('0.0.0.0')
        self.assertNotIn('0.0.0.0', ips)


@mock.patch.object(certgen, 'new_key', lambda bits=2048: cached_key())
class CertificateChoiceTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        shutil.rmtree(tls.TLS_DIR, ignore_errors=True)

    def test_self_signed_is_made_once_and_renewed_near_the_end(self):
        self.assertTrue(tls.ensure_self_signed())
        self.assertFalse(tls.ensure_self_signed())
        if os.name != 'nt':
            self.assertEqual(os.stat(tls.SELF_KEY).st_mode & 0o777, 0o600)
        end = tls.describe(tls.SELF_CERT)['not_after']
        self.assertFalse(tls.ensure_self_signed(now=end - datetime.timedelta(days=31)))
        self.assertTrue(tls.ensure_self_signed(now=end - datetime.timedelta(days=29)))

    def test_a_broken_self_signed_file_is_made_again(self):
        os.makedirs(tls.TLS_DIR)
        with open(tls.SELF_CERT, 'w') as f:
            f.write('not a certificate')
        self.assertTrue(tls.ensure_self_signed())
        tls.describe(tls.SELF_CERT)

    def test_own_certificate_wins(self):
        os.makedirs(tls.TLS_DIR)
        cert, key, der = make_cert(tls.TLS_DIR, 'mine')
        os.rename(cert, tls.OWN_CERT)
        os.rename(key, tls.OWN_KEY)
        _ctx, info = tls.server_context()
        self.assertEqual((info['source'], info['error']), ('own', ''))
        self.assertEqual(info['fingerprint'], certgen.fingerprint(der))
        self.assertFalse(os.path.exists(tls.SELF_CERT))

    def test_a_broken_own_certificate_falls_back_to_self_signed_never_http(self):
        os.makedirs(tls.TLS_DIR)
        with open(tls.OWN_CERT, 'w') as f:
            f.write('-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n')
        with self.assertLogs('web', 'ERROR') as logs:
            ctx, info = tls.server_context()
        self.assertIsInstance(ctx, ssl.SSLContext)
        self.assertEqual(info['source'], 'self-signed')
        self.assertTrue(info['error'])
        self.assertIn('cannot be used', logs.output[0])

    def test_an_encrypted_own_key_does_not_prompt(self):
        os.makedirs(tls.TLS_DIR)
        cert, _key, _der = make_cert(tls.TLS_DIR, 'mine')
        os.rename(cert, tls.OWN_CERT)
        with open(tls.OWN_KEY, 'w') as f:
            f.write(certgen.pem('ENCRYPTED PRIVATE KEY', b'\x30\x03\x02\x01\x00'))   # a passphrase key
        with self.assertLogs('web', 'ERROR'):
            _ctx, info = tls.server_context()
        self.assertEqual(info['source'], 'self-signed')


def _app(environ, start_response):
    path = environ['PATH_INFO']
    if path == '/big':
        body = b'x' * (2 * 1024 * 1024 + 17)
    elif path == '/echo':
        body = str(len(environ['wsgi.input'].read(int(environ.get('CONTENT_LENGTH') or 0)))).encode()
    else:
        body = ('%s %s %s' % (environ['wsgi.url_scheme'], environ['REMOTE_ADDR'], path)).encode()
    start_response('200 OK', [('Content-Type', 'text/plain'), ('Content-Length', str(len(body)))])
    return [body]


class TLSServerTests(unittest.TestCase):
    """waitress + TLSChannel on 127.0.0.1, port chosen by the OS."""

    @classmethod
    def setUpClass(cls):
        cls.dir = os.path.join(paths.ROOT, 'tls-server-test')
        os.makedirs(cls.dir, exist_ok=True)
        cls.cert, key, _der = make_cert(cls.dir)
        hardening.patch_waitress()
        cls.server = tls.create_server(_app, tls._context(cls.cert, key), host='127.0.0.1', port=0,
                                       **hardening.SERVE_OPTIONS)
        cls.port = int(cls.server.effective_port)
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        from waitress import wasyncore
        cls.server.trigger.pull_trigger(lambda: wasyncore.close_all(cls.server._map))
        cls.thread.join(10)
        cls.server.task_dispatcher.shutdown()
        shutil.rmtree(cls.dir, ignore_errors=True)

    def client(self, **kw):
        ctx = ssl.create_default_context(cafile=self.cert)
        for k, v in kw.items():
            setattr(ctx, k, v)
        return http.client.HTTPSConnection('127.0.0.1', self.port, context=ctx, timeout=10)

    def test_get_post_and_keep_alive(self):
        c = self.client()
        for path in ('/a', '/b?x=1', '/c'):
            c.request('GET', path)
            r = c.getresponse()
            self.assertEqual(r.status, 200)
            self.assertEqual(r.read().decode(), 'https 127.0.0.1 %s' % path.split('?')[0])
        body = os.urandom(1024 * 1024 + 3)
        c.request('POST', '/echo', body=body)
        self.assertEqual(c.getresponse().read(), str(len(body)).encode())
        c.close()

    def test_a_large_response_arrives_whole(self):
        c = self.client()
        c.request('GET', '/big')
        self.assertEqual(len(c.getresponse().read()), 2 * 1024 * 1024 + 17)
        c.close()

    def test_plain_http_is_sent_to_https(self):
        c = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        c.request('GET', '/settings?x=1', headers={'Host': '127.0.0.1:%d' % self.port})
        r = c.getresponse()
        self.assertEqual(r.status, 302)
        self.assertEqual(r.getheader('Location'), 'https://127.0.0.1:%d/settings?x=1' % self.port)
        c.close()

    def test_not_http_at_all_gets_400(self):
        with socket.create_connection(('127.0.0.1', self.port), timeout=10) as s:
            s.sendall(b'hello there\r\n\r\n')
            self.assertIn(b'400 Bad Request', s.recv(4096))

    def test_tls_1_1_is_refused(self):
        c = self.client(minimum_version=ssl.TLSVersion.MINIMUM_SUPPORTED,
                        maximum_version=ssl.TLSVersion.TLSv1_1)
        with self.assertRaises((ssl.SSLError, OSError)):
            c.request('GET', '/')
            c.getresponse()
        c.close()

    def test_a_dropped_handshake_does_not_hurt_the_next_client(self):
        with socket.create_connection(('127.0.0.1', self.port), timeout=10) as s:
            s.sendall(b'\x16\x03\x01\x00\x05')     # the start of a record, then gone
        with socket.create_connection(('127.0.0.1', self.port), timeout=10) as s:
            s.sendall(b'\x16\x03\x01\x00\x04\x01\x00\x00\x00')   # an empty ClientHello
            s.recv(100)                                     # an alert, or closed
        c = self.client()
        c.request('GET', '/still')
        self.assertEqual(c.getresponse().status, 200)
        c.close()


class RedirectTests(unittest.TestCase):
    def test_host_header_and_path(self):
        out = tls.redirect_for(b'GET /logs?level=ERROR HTTP/1.1\r\nHost: box.lan:5000')
        self.assertIn(b'302 Found', out)
        self.assertIn(b'Location: https://box.lan:5000/logs?level=ERROR\r\n', out)

    def test_no_host_uses_the_local_address(self):
        out = tls.redirect_for(b'GET / HTTP/1.0', local=('192.168.1.20', 5000))
        self.assertIn(b'Location: https://192.168.1.20:5000/\r\n', out)
        out = tls.redirect_for(b'GET / HTTP/1.0', local=('::1', 5000, 0, 0))
        self.assertIn(b'Location: https://[::1]:5000/\r\n', out)

    def test_odd_input_is_never_echoed_raw(self):
        self.assertIn(b'400', tls.redirect_for(b'GET / HTTP/1.1\r\nHost: evil"\r\n<x>'))
        out = tls.redirect_for(b'GET /a"b<c HTTP/1.1\r\nHost: box:1')
        self.assertIn(b'Location: https://box:1/a"b<c\r\n', out)
        self.assertIn(b'href="https://box:1/a%22b<c"', out)
        out = tls.redirect_for(b'GET http://x/ HTTP/1.1\r\nHost: box:1')
        self.assertIn(b'Location: https://box:1/\r\n', out)
        self.assertIn(b'400', tls.redirect_for(b'\x00\x01\x02'))


class WebUrlTests(unittest.TestCase):
    def test_scheme_and_host(self):
        url = cli._web_url
        self.assertEqual(url({'web': {'host': '0.0.0.0', 'port': 5000}}), 'http://127.0.0.1:5000/')
        self.assertEqual(url({'web': {'host': '0.0.0.0', 'port': 5443, 'https': True}}),
                         'https://127.0.0.1:5443/')
        self.assertEqual(url({'web': {'host': '::1', 'port': 5000}}), 'http://[::1]:5000/')
        self.assertEqual(url({'web': {'host': '192.168.1.20', 'port': 5000, 'https': True}}),
                         'https://192.168.1.20:5000/')

    def test_help_prints_it_for_the_launchers(self):
        _env.reset()
        settings.update({'web': {'https': True}})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli.main(['help'])
        self.assertIn('\nWeb UI: https://127.0.0.1:5000/\n', out.getvalue())


FORM = {'web_port': '5000', 'check_interval': '60', 'max_workers': '10',
        'log_retention_days': '14', 'heartbeat_interval': '60'}
LAN = {'REMOTE_ADDR': '192.168.1.50'}


class _Web(unittest.TestCase):
    setUp = test_web.WebTests.setUp
    csrf = test_web.WebTests.csrf
    setup_admin = test_web.WebTests.setup_admin

    def tearDown(self):
        tls.ACTIVE = None

    def post(self, **fields):
        return self.c.post('/settings', data=dict(FORM, csrf=self.csrf('/settings'), **fields))


class SettingsTests(_Web):
    def test_who_can_open_it(self):
        self.setup_admin()
        for scope, host in (('local', '127.0.0.1'), ('all', '0.0.0.0')):
            self.post(web_scope=scope, web_host='10.9.9.9')
            self.assertEqual(settings.load()['web']['host'], host)
        self.post(web_scope='custom', web_host='192.168.1.20')
        self.assertEqual(settings.load()['web']['host'], '192.168.1.20')
        r = self.post(web_scope='custom', web_host='')
        self.assertIn('needs the address', r.get_data(as_text=True))
        r = self.post(web_scope='custom', web_host='bad host')
        self.assertIn('must be an IP address', r.get_data(as_text=True))
        self.assertEqual(settings.load()['web']['host'], '192.168.1.20')

    def test_https_is_saved_and_asks_for_a_restart(self):
        self.setup_admin()
        r = self.post(web_scope='all', web_https='on')
        self.assertTrue(settings.load()['web']['https'])
        html = self.c.get(r.headers['Location']).get_data(as_text=True)
        self.assertIn('when the service restarts', html)
        self.assertIn('HTTPS is saved, but this page still came over plain http', html)
        self.post(web_scope='all')
        self.assertFalse(settings.load()['web']['https'])
        self.assertNotIn('"https"', open(paths.SETTINGS_FILE).read())   # the default again

    def test_plain_http_on_the_network_is_said_plainly(self):
        self.setup_admin()
        warn = 'Open to the network over plain http'
        self.assertIn(warn, self.c.get('/settings').get_data(as_text=True))   # default 0.0.0.0
        settings.update({'web': {'host': '127.0.0.1'}})
        html = self.c.get('/settings').get_data(as_text=True)
        self.assertNotIn(warn, html)
        self.assertIn('value="local" id="web-local" checked', html)
        settings.update({'web': {'host': '0.0.0.0', 'https': True}})
        self.assertNotIn(warn, self.c.get('/settings').get_data(as_text=True))

    def test_the_certificate_in_use_is_shown(self):
        self.setup_admin()
        tls.ACTIVE = {'source': 'self-signed', 'cert': tls.SELF_CERT, 'fingerprint': 'AB:CD',
                      'not_after': datetime.datetime(2029, 2, 14), 'error': 'SSLError: bad key'}
        html = self.c.get('/settings').get_data(as_text=True)
        self.assertIn('self-signed by this agent, valid until 2029-02-14', html)
        self.assertIn('AB:CD', html)
        self.assertIn('could not be used (SSLError: bad key)', html)


class PlainHttpNoteTests(_Web):
    NOTE = 'Not encrypted: this page came over plain http'

    def test_sign_in_from_the_network_over_http_says_so(self):
        self.setup_admin()
        self.c = self.app.test_client()
        self.assertIn(self.NOTE, self.c.get('/login', environ_base=LAN).get_data(as_text=True))
        self.assertNotIn(self.NOTE, self.c.get('/login').get_data(as_text=True))   # this PC
        https = self.c.get('/login', environ_base=LAN, base_url='https://box.lan')
        self.assertNotIn(self.NOTE, https.get_data(as_text=True))


class CookieTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()

    def cookie(self, https):
        app = create_app(https=https)
        c = app.test_client()
        r = c.get('/setup', base_url='https://localhost' if https else 'http://localhost')
        return r.headers.get('Set-Cookie', '')

    def test_https_cookie_is_secure_and_host_only(self):
        self.assertTrue(self.cookie(True).startswith('__Host-uptime_sync_v4='))
        self.assertIn('Secure', self.cookie(True))
        self.assertIn('Path=/', self.cookie(True))
        self.assertNotIn('Domain=', self.cookie(True))
        self.assertTrue(self.cookie(False).startswith('uptime_sync_v4='))
        self.assertNotIn('Secure', self.cookie(False))

    def test_the_setting_picks_it(self):
        settings.update({'web': {'https': True}})
        self.assertTrue(create_app().config['SESSION_COOKIE_SECURE'])


if __name__ == '__main__':
    unittest.main()
