"""Response bodies from a hostile server (4.0.9): util.iter_body never lets
urllib3 decompress or parse chunk framing, so the urllib3 that still runs on
Python 3.8 cannot be made to eat the memory of a 32-bit Windows 7 box."""

from tests import _env  # noqa: F401  (must be first)

import gzip
import socket
import threading
import tracemalloc
import unittest
from unittest import mock

import requests

from uptime_sync import checks, engine, monitors, paths, util

BOMB = gzip.compress(b'\0' * (64 * 1024 * 1024), 9)     # 64 MB of zeros in ~64 KB


class RawServer:
    """Answers each connection with the canned bytes for its path."""

    def __init__(self, routes):
        self.routes = routes
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(8)
        self.base = 'http://127.0.0.1:%d' % self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                data = b''
                while b'\r\n\r\n' not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                path = data.split(b' ')[1].decode() if data.count(b' ') >= 2 else '/'
                try:
                    conn.sendall(self.routes.get(path, b'HTTP/1.1 404 x\r\nContent-Length: 0\r\n\r\n'))
                except OSError:
                    pass

    def close(self):
        self.sock.close()


def response(status, headers, body):
    head = 'HTTP/1.1 %s\r\n' % status + ''.join('%s: %s\r\n' % kv for kv in headers.items())
    return head.encode() + b'Connection: close\r\n\r\n' + body


def peak_mb(fn):
    tracemalloc.start()
    try:
        fn()
        return tracemalloc.get_traced_memory()[1] / 2 ** 20
    finally:
        tracemalloc.stop()


class IterBodyTests(unittest.TestCase):
    def setUp(self):
        self.srv = RawServer({
            '/plain': response('200 OK', {'Content-Length': '5'}, b'hello'),
            '/gzip': response('200 OK', {'Content-Encoding': 'gzip', 'Content-Length': len(gzip.compress(b'hi'))},
                              gzip.compress(b'hi')),
            '/bomb': response('200 OK', {'Content-Encoding': 'gzip', 'Content-Length': len(BOMB)}, BOMB),
            '/chunkline': response('200 OK', {'Transfer-Encoding': 'chunked'}, b'0' * (8 * 1024 * 1024)),
            '/br': response('200 OK', {'Content-Encoding': 'br', 'Content-Length': '2'}, b'xx'),
        })
        self.s = requests.Session()
        self.s.trust_env = False

    def tearDown(self):
        self.srv.close()

    def get(self, path):
        return self.s.get(self.srv.base + path, stream=True, timeout=10)

    def test_plain_and_gzip(self):
        self.assertEqual(b''.join(util.iter_body(self.get('/plain'), 100)), b'hello')
        self.assertEqual(b''.join(util.iter_body(self.get('/gzip'), 100)), b'hi')
        with self.assertRaises(util.BodyTooLarge):
            b''.join(util.iter_body(self.get('/plain'), 4))

    def test_gzip_bomb_stops_at_the_limit(self):
        def read():
            with self.assertRaises(util.BodyTooLarge):
                for _ in util.iter_body(self.get('/bomb'), 256 * 1024):
                    pass
        self.assertLess(peak_mb(read), 8)

    def test_endless_chunk_size_line_is_refused(self):
        def read():
            with self.assertRaises(requests.ConnectionError):
                for _ in util.iter_body(self.get('/chunkline'), 256 * 1024):
                    pass
        self.assertLess(peak_mb(read), 8)

    def test_unknown_encoding_is_refused(self):
        with self.assertRaises(requests.exceptions.ContentDecodingError):
            b''.join(util.iter_body(self.get('/br'), 100))


class RedirectBodyTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        self.srv = RawServer({
            '/ok': response('200 OK', {'Content-Length': '2'}, b'ok'),
            '/r': response('302 Found', {'Location': '/ok', 'Content-Encoding': 'gzip',
                                         'Content-Length': len(BOMB)}, BOMB),
            '/loop': response('302 Found', {'Location': '/loop', 'Content-Length': '0'}, b''),
        })
        self.c = checks.Checker()
        self.c.session.trust_env = False

    def tearDown(self):
        self.srv.close()

    def test_redirect_body_is_never_read(self):
        # requests' own redirect handling would inflate all 64 MB here
        result = []
        self.assertLess(peak_mb(lambda: result.append(self.c.check_http(self.srv.base + '/r', timeout=5))), 8)
        self.assertTrue(result[0][0])

    def test_redirect_loop_is_down(self):
        self.assertEqual(self.c.check_http(self.srv.base + '/loop', timeout=5), (False, 0))

    def test_authorization_dropped_on_another_host(self):
        sent = []

        def fake_get(url, **kw):
            sent.append((url, dict(kw['headers'])))
            r = requests.Response()
            r.status_code = 302 if len(sent) == 1 else 200
            r.headers['Location'] = 'https://other.example/x'
            r.url = url
            r.raw = mock.Mock()
            return r
        with mock.patch.object(self.c.session, 'get', side_effect=fake_get):
            self.assertTrue(self.c.check_http('https://site.example/', headers={'Authorization': 'Bearer t',
                                                                               'X-Site': 'a'})[0])
        self.assertEqual(sent[0][1], {'Authorization': 'Bearer t', 'X-Site': 'a'})
        self.assertEqual(sent[1], ('https://other.example/x', {'X-Site': 'a'}))

    def test_push_does_not_read_the_body(self):
        e = engine.Engine(supervised=True)
        m = monitors.normalize({'name': 'a', 'type': 'PING', 'target': '192.0.2.1',
                                'push_url': 'https://kuma.example/api/push/x'})
        r = mock.Mock(status_code=200, is_redirect=False)
        with mock.patch.object(e.session, 'get', return_value=r) as get:
            e._push(m, True, 1, 0)
        self.assertTrue(get.call_args[1].get('stream'))
        r.close.assert_called_once_with()


    def test_heartbeat_redirect_body_is_never_read(self):
        # allow_redirects=False alone is not enough: requests' Session.send
        # still reads a redirect's body to fill Response.next
        from uptime_sync import heartbeat, settings
        hb = heartbeat.Heartbeat(0)
        hb.session.trust_env = False
        s = util.deep_merge(settings.load(), {'remote': {
            'enabled': True, 'server_type': 'local', 'local_url': self.srv.base + '/r',
            'api_key': 'k', 'secret_key': 's'}})
        out = []
        self.assertLess(peak_mb(lambda: out.append(hb.send(s))), 8)
        self.assertIsNone(out[0])        # a 302 is not a success
        self.assertTrue(hb.last_error)

    def test_update_download_redirect_body_is_never_read(self):
        from uptime_sync import updater
        with mock.patch.dict('os.environ', {'NO_PROXY': '*'}):
            def run():
                try:
                    updater._open(self.srv.base + '/r', 'server', self.srv.base, verify=True).close()
                except Exception:
                    pass
            self.assertLess(peak_mb(run), 8)

if __name__ == '__main__':
    unittest.main()
