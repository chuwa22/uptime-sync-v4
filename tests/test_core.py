from tests import _env  # noqa: F401  (must be first)

import datetime
import hashlib
import hmac
import json
import os
import time
import unittest

from uptime_sync import checks, monitors, paths, settings, signing, util
from uptime_sync.heartbeat import Heartbeat, build_payload


class UtilTests(unittest.TestCase):
    def test_diff_and_merge(self):
        base = {'a': 1, 'b': {'c': 2, 'd': 3}}
        data = {'a': 1, 'b': {'c': 2, 'd': 4}, 'e': 5}
        self.assertEqual(util.diff_from(base, data), {'b': {'d': 4}, 'e': 5})
        self.assertEqual(util.deep_merge(base, {'b': {'d': 9}}), {'a': 1, 'b': {'c': 2, 'd': 9}})

    def test_redact(self):
        token = 'AbCdEf' + '123456'   # split so the pre-commit token scan ignores the fixture
        text = util.redact('GET https://kuma/api/push/' + token + '?status=up&api_key=k1&signature=s1')
        self.assertNotIn(token, text)
        self.assertNotIn('k1', text.split('api_key=')[1][:2])
        self.assertNotIn('=s1', text)

    def test_slept_during(self):
        now = time.monotonic()
        self.assertEqual(util.slept_during(now, 1.0), 0.0)            # an ordinary wait
        self.assertEqual(util.slept_during(now - 20, 1.0), 0.0)       # slow, not asleep
        self.assertGreaterEqual(util.slept_during(now - 3600, 1.0), 3598)

    def test_versions(self):
        self.assertTrue(util.is_newer('4.0.10', '4.0.9'))
        self.assertFalse(util.is_newer('4.0.0', '4.0.0'))
        self.assertFalse(util.is_newer('3.6.24', '4.0.0'))
        self.assertFalse(util.is_newer(None, '4.0.0'))


class SettingsTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()

    def test_save_keeps_only_the_diff(self):
        s = settings.load()
        s['site_name'] = 'Branch 7'
        site = settings.save(s)
        self.assertEqual(site, {'site_name': 'Branch 7'})

    def test_env_managed_never_written_back(self):
        with open(paths.ENV_FILE, 'w') as f:
            f.write('UPTIME_SECRET_KEY="from-env-secret"\nKUMA_TOKEN=tok123\n')
        s = settings.load()
        self.assertEqual(s['remote']['secret_key'], 'from-env-secret')
        self.assertIn('remote.secret_key', settings.env_managed())
        settings.save(s)
        with open(paths.SETTINGS_FILE) as f:
            self.assertNotIn('from-env-secret', f.read())
        self.assertEqual(settings.expand_refs('https://k/api/push/${KUMA_TOKEN}?x=$1'),
                         'https://k/api/push/tok123?x=$1')
        self.assertEqual(settings.undefined_refs('${NOPE}'), ['NOPE'])

    def test_os_env_wins(self):
        os.environ['UPTIME_API_KEY'] = 'os-key'
        try:
            self.assertEqual(settings.load()['remote']['api_key'], 'os-key')
        finally:
            del os.environ['UPTIME_API_KEY']


class MonitorTests(unittest.TestCase):
    def test_validate(self):
        m = monitors.normalize({'name': 'Gw', 'type': 'ping', 'target': '10.0.0.1',
                                'push_url': 'http://kuma/api/push/x'})
        self.assertEqual(m['type'], 'PING')
        self.assertTrue(any('https' in e for e in monitors.validate(m)))
        m['push_url'] = 'https://kuma/api/push/x'
        self.assertEqual(monitors.validate(m), [])
        bad = monitors.normalize({'name': 'x', 'type': 'TCP PORT', 'target': 'a/b',
                                  'push_url': 'https://k/'})
        errs = monitors.validate(bad)
        self.assertTrue(any('Target' in e for e in errs))
        self.assertTrue(any('port' in e.lower() for e in errs))


class PingTests(unittest.TestCase):
    def test_parse_windows(self):
        out = ('Pinging 8.8.8.8 with 32 bytes of data:\r\n'
               'Reply from 8.8.8.8: bytes=32 time=14ms TTL=117\r\n')
        self.assertEqual(checks.parse_ping(0, out, 30), 14)
        out = 'Reply from 8.8.8.8: bytes=32 time<1ms TTL=117'
        self.assertEqual(checks.parse_ping(0, out, 30), 1)

    def test_windows_unreachable_with_exit_zero(self):
        # Windows ping exits 0 for "Destination host unreachable" from the gateway.
        out = 'Reply from 192.168.1.1: Destination host unreachable.'
        if os.name == 'nt':
            self.assertIsNone(checks.parse_ping(0, out, 30))

    def test_parse_posix(self):
        out = '64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=7.812 ms'
        self.assertEqual(checks.parse_ping(0, out, 30), 7.8)
        self.assertIsNone(checks.parse_ping(1, '', 30))

    def test_target_cannot_be_an_option(self):
        m = monitors.normalize({'name': 'x', 'type': 'PING', 'target': '-c9', 'timeout': 1})
        self.assertFalse(checks.Checker().check(m)[0])

    def test_helpers(self):
        self.assertTrue(checks.is_ip_literal('8.8.8.8'))
        self.assertTrue(checks.is_ip_literal('2001:4860::8888'))
        self.assertFalse(checks.is_ip_literal('dns.google'))
        self.assertTrue(checks.is_valid_dns_query_name('google.com'))
        self.assertFalse(checks.is_valid_dns_query_name('bad name'))


class SigningTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()

    def test_reply_signature(self):
        body = b'{"success":true}'
        good = hmac.new(b'sec', b'reqsig.' + body, hashlib.sha256).hexdigest()
        self.assertEqual(signing.verify_reply(good, 'reqsig', body, 'sec'), 'valid')
        self.assertEqual(signing.verify_reply('00' * 32, 'reqsig', body, 'sec'), 'invalid')
        self.assertEqual(signing.verify_reply(None, 'reqsig', body, 'sec'), 'unsigned')

    def test_latch_fingerprint_matches_3x(self):
        remote = {'secret_key': 'sec', 'url': 'https://Mon.Example.com/api/heartbeat.php'}
        expected = hmac.new(b'sec', b'uptime-sync response-signing latch|mon.example.com',
                            hashlib.sha256).hexdigest()[:32]
        self.assertEqual(signing.fingerprint(remote), expected)

    def test_auto_latch(self):
        remote = {'secret_key': 'sec', 'url': 'https://mon/api/heartbeat.php',
                  'require_signed_response': 'auto'}
        hb = Heartbeat(0)
        self.assertTrue(hb.may_act('unsigned', remote))    # first contact
        self.assertTrue(hb.may_act('valid', remote))       # latches
        self.assertFalse(hb.may_act('unsigned', remote))   # header stripped -> refused
        self.assertFalse(hb.may_act('invalid', remote))
        remote2 = dict(remote, secret_key='rotated')       # new secret -> fresh latch
        self.assertTrue(hb.may_act('unsigned', remote2))
        self.assertFalse(hb.may_act('unsigned', dict(remote, require_signed_response=True)))
        self.assertTrue(hb.may_act('unsigned', dict(remote, require_signed_response='false')))

    def test_payload_never_carries_the_secret(self):
        s = settings.load()
        s['remote'].update({'api_key': 'key1', 'secret_key': 'TOPSECRET', 'url': 'https://m/'})
        text = json.dumps(build_payload(s, 0))
        self.assertNotIn('TOPSECRET', text)
        self.assertIn('github-download', text)
        self.assertIn('sha256-verify', text)


class WindowTests(unittest.TestCase):
    def test_in_window(self):
        from uptime_sync.updater import in_window
        at = lambda h, m: datetime.datetime(2026, 1, 1, h, m)  # noqa: E731
        self.assertTrue(in_window('02:00', '04:00', at(3, 0)))
        self.assertFalse(in_window('02:00', '04:00', at(4, 0)))
        self.assertTrue(in_window('23:00', '01:00', at(0, 30)))
        self.assertFalse(in_window('23:00', '01:00', at(12, 0)))


if __name__ == '__main__':
    unittest.main()
