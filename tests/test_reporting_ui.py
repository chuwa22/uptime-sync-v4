"""Settings > Reporting: you can tell whether a secret is set and whether
the agent reaches uptime-monitor, and the server's own reason shows up."""

from tests import _env  # must be first: it points UPTIME_SYNC_ROOT at a temp copy
_env  # imported for that alone; naming it keeps pyflakes quiet (it ignores noqa)

import time
import unittest
from unittest import mock

from tests import test_web
from uptime_sync import heartbeat, settings, util

FORM = {'web_port': '5000', 'check_interval': '60', 'max_workers': '10',
        'log_retention_days': '14', 'heartbeat_interval': '60'}


class _Web(unittest.TestCase):
    # test_web's setup and helpers, without running its tests a second time
    setUp = test_web.WebTests.setUp
    csrf = test_web.WebTests.csrf
    setup_admin = test_web.WebTests.setup_admin


class SecretFieldTests(_Web):
    def post(self, path='/settings', **fields):
        data = dict(FORM, csrf=self.csrf(path), **fields)
        return self.c.post(path, data=data)

    def test_a_set_secret_shows_as_a_locked_mask_never_the_value(self):
        self.setup_admin()
        settings.update({'remote': {'secret_key': 'TOPSECRETVALUE'}})
        html = self.c.get('/settings').get_data(as_text=True)
        self.assertNotIn('TOPSECRETVALUE', html)
        self.assertIn('value="********" disabled aria-label="HMAC secret is set"', html)
        self.assertNotIn('name="secret_key"', html)            # nothing to post back by accident
        self.assertIn('href="/settings?secret=change#reporting"', html)
        change = self.c.get('/settings?secret=change').get_data(as_text=True)
        self.assertIn('name="secret_key" type="password"', change)
        self.assertNotIn('TOPSECRETVALUE', change)

    def test_not_set_is_said_plainly(self):
        self.setup_admin()
        html = self.c.get('/settings').get_data(as_text=True)
        self.assertIn('not set - heartbeats are not verified', html)
        self.assertIn('name="secret_key" type="password"', html)

    def test_the_mask_posted_back_keeps_the_secret(self):
        self.setup_admin()
        settings.update({'remote': {'secret_key': 'TOPSECRETVALUE'}})
        self.assertEqual(self.post('/settings?secret=change', secret_key='********').status_code, 302)
        self.assertEqual(settings.load()['remote']['secret_key'], 'TOPSECRETVALUE')
        self.post('/settings?secret=change', secret_key='NEWSECRET123')
        self.assertEqual(settings.load()['remote']['secret_key'], 'NEWSECRET123')

    def test_api_key_follows_the_server_rule(self):
        self.setup_admin()
        r = self.post(api_key='grand empire')
        self.assertEqual(r.status_code, 200)
        self.assertIn('API key must be 8-100 letters', r.get_data(as_text=True))
        self.assertNotEqual(settings.load()['remote'].get('api_key'), 'grand empire')
        self.assertEqual(self.post(api_key='grand-empire').status_code, 302)
        self.assertEqual(settings.load()['remote']['api_key'], 'grand-empire')


class ConnectionTileTests(_Web):
    def test_settings_shows_the_live_heartbeat_tile(self):
        self.setup_admin()
        html = self.c.get('/settings').get_data(as_text=True)
        self.assertIn('data-tile="heartbeat" data-tile-base="tile tile-wide" data-status-url="/api/status"', html)
        self.assertIn('data-field="heartbeat_try"', html)
        self.assertIn('Turn on Send heartbeats and save.', html)

    def test_tile_text_names_the_last_attempt(self):
        from uptime_sync.web.views import tile_text
        p = {'engine': {'running': True, 'updated_at': ''}, 'counts': {'up': 0, 'enabled': 0},
             'signing': {'state': 'not-yet', 'since': ''}, 'now': 1000,
             'heartbeat': {'enabled': True, 'failures': 0, 'last_ok': None,
                           'error': 'HTTP 422: Invalid or missing api_key', 'last_try': 990}}
        t = tile_text(p)
        self.assertEqual(t['heartbeat'], 'Error')
        self.assertIn('Invalid or missing api_key', t['heartbeat_sub'])
        self.assertEqual(t['heartbeat_try'], 'last attempt 10 s ago')
        p['heartbeat']['last_try'] = None
        self.assertIn('no attempt yet', tile_text(p)['heartbeat_try'])


def _reply(status, body=b'', headers=None):
    r = mock.Mock(status_code=status, headers=headers or {})
    return r, body


class HeartbeatReasonTests(unittest.TestCase):
    def send(self, status, body=b'', headers=None, url='https://mon.example/api/heartbeat.php'):
        s = util.deep_merge(settings.load(), {'remote': {'enabled': True, 'url': url, 'api_key': 'grand-empire'}})
        hb = heartbeat.Heartbeat(0)
        r, raw = _reply(status, body, headers)
        with mock.patch.object(hb.session, 'post', return_value=r), \
                mock.patch.object(heartbeat, '_read_body', return_value=raw):
            self.assertIsNone(hb.send(s))
        self.assertIsNotNone(hb.last_try)
        return hb.last_error

    def test_the_servers_error_text_is_kept(self):
        self.assertEqual(self.send(422, b'{"success":false,"error":"Invalid or missing api_key"}'),
                         'HTTP 422: Invalid or missing api_key')
        self.assertEqual(self.send(401, b'not json'), 'HTTP 401')

    def test_a_redirect_names_where_without_query_or_userinfo(self):
        why = self.send(301, headers={'Location': 'https://u:p@mon.example/itasset/api/heartbeat.php?t=SECRET'},
                        url='http://mon.example/itasset/api/heartbeat.php')
        self.assertEqual(why, 'HTTP 301 - the server redirects to '
                              'https://mon.example/itasset/api/heartbeat.php; put that URL in Settings')
        self.assertIn('/x/heartbeat.php', self.send(302, headers={'Location': '/x/heartbeat.php'}))


class BeatOnSettingsChangeTests(unittest.TestCase):
    def test_saving_reporting_cuts_the_wait_short(self):
        from uptime_sync import engine
        e = engine.Engine.__new__(engine.Engine)
        e.stop_event = mock.Mock(is_set=mock.Mock(return_value=False), wait=mock.Mock())
        e.heartbeat = heartbeat.Heartbeat(0)
        e.heartbeat.failures, e.heartbeat.next_override = 4, 600.0
        before = engine._remote_key(settings.load())
        settings.update({'remote': {'api_key': 'grand-empire'}})
        started = time.monotonic()
        e._wait_for_beat(600, before)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(e.stop_event.wait.call_count, 1)        # one poll, then out
        self.assertEqual((e.heartbeat.failures, e.heartbeat.next_override), (0, None))


if __name__ == '__main__':
    unittest.main()
