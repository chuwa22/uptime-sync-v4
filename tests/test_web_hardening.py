"""Web-stack fixes that Python 3.8 boxes cannot get by upgrading (4.0.9)."""

from tests import _env  # noqa: F401  (must be first)

import socket
import unittest

from uptime_sync import paths
from uptime_sync.web import auth, create_app, hardening


class DeviceNameTests(unittest.TestCase):
    def test_rule(self):
        for p in ('/static/NUL', '/static/con.txt', '/static/aux .css', '/static/a/Com1.js',
                  '/static/nul:', '/static/lpt3.txt.txt', '/static/COM\u00b9', '/conin$'):
            self.assertTrue(hardening.names_a_device(p), p)
        for p in ('/', '/static/app.css', '/static/console.js', '/logs/file/engine-2026-11-05.log',
                  '/static/icons-ie8.png', '/monitors/abc123/edit', '/static/COM10'):
            self.assertFalse(hardening.names_a_device(p), p)

    def test_web_answers_404(self):
        _env.reset()
        paths.ensure_dirs()
        auth._attempts.clear()
        app = create_app()
        app.testing = True
        c = app.test_client()
        for p in ('/static/NUL', '/static/con.txt', '/static/aux%20.css', '/static/nul:', '/static/COM%C2%B9'):
            self.assertEqual(c.get(p).status_code, 404, p)
        r = c.get('/static/app.css')
        r.close()
        self.assertEqual(r.status_code, 200)
        self.assertNotIn('Cookie', r.headers.get('Vary', ''))
        self.assertIn('Cookie', c.get('/setup').headers.get('Vary', ''))


class WaitressTests(unittest.TestCase):
    def test_no_request_lookahead(self):
        # CVE-2024-49768 needs it above 0 (waitress 3.0.0 on Python 3.8)
        self.assertEqual(hardening.SERVE_OPTIONS['channel_request_lookahead'], 0)

    def test_channel_on_a_socket_closed_before_getpeername(self):
        # CVE-2024-49769: an accept()ed socket whose peer already left. A
        # never-connected socket gives getpeername() the same ENOTCONN.
        from waitress.adjustments import Adjustments
        from waitress.channel import HTTPChannel
        applied = hardening.patch_waitress()
        self.assertEqual(applied, hardening._waitress_version() == '3.0.0')
        class Server:
            active_channels = {}
        sock = socket.socket()
        try:
            ch = HTTPChannel(Server(), sock, ('192.0.2.1', 1), Adjustments(), map={})
            self.assertTrue(ch.connected)     # 3.0.0 unpatched: False -> busy loop
            ch.will_close = True
            ch.handle_write()                 # closes instead of returning forever
            self.assertFalse(ch.connected)
        finally:
            sock.close()


if __name__ == '__main__':
    unittest.main()
