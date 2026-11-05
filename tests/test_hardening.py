"""Regression tests for the 4.0.6 full review (engine, supervisor, OS layer)."""

from tests import _env  # noqa: F401  (must be first)

import os
import re
import threading
import time
import unittest
from unittest import mock

from uptime_sync import checks, engine, monitors, paths, perms, settings, signing, supervisor, updater, util


class VersionTests(unittest.TestCase):
    def test_strict(self):
        self.assertTrue(util.is_version('4.0.6'))
        for bad in ('4.0.6/../../x', '4.0.6-rc1', 'v4.0.6', '4.0', '', None, 406):
            self.assertFalse(util.is_version(bad), repr(bad))
            self.assertFalse(util.is_newer(bad, '1.0.0'), repr(bad))


class PingTests(unittest.TestCase):
    def test_windows_ipv6_reply_has_no_ttl(self):
        with mock.patch.object(checks.sys, 'platform', 'win32'):
            self.assertEqual(checks.parse_ping(0, 'Reply from ::1: time<1ms', 30), 1)
            self.assertEqual(checks.parse_ping(0, 'Reply from 2001:db8::1: time=12ms', 30), 12)
            self.assertIsNone(checks.parse_ping(0, 'Reply from 192.168.1.1: Destination host unreachable.', 30))


class SigningTests(unittest.TestCase):
    def test_non_ascii_header_is_invalid_not_a_crash(self):
        self.assertEqual(signing.verify_reply('\u0e01' * 64, 'req', b'{}', 'sec'), 'invalid')


class HttpCheckTests(unittest.TestCase):
    def test_bad_header_value_is_down_and_url_not_logged(self):
        url = 'http://127.0.0.1:9/health?token=SEKRIT1'
        with self.assertLogs('checks', 'DEBUG') as cm:
            ok, _ = checks.Checker().check_http(url, timeout=1, headers={'X-Site': '\u0e17\u0e14'})
        self.assertFalse(ok)
        self.assertNotIn('SEKRIT1', '\n'.join(cm.output))


class EngineCycleTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        self.e = engine.Engine(supervised=True)
        self.m = monitors.normalize({'name': 'slow', 'type': 'PING', 'target': '192.0.2.1'})
        self.e.monitors = [self.m]
        self.e.settings = util.deep_merge(settings.load(), {'check_interval': 10, 'max_workers': 2})

    def test_check_still_running_is_not_started_again(self):
        self.e._inflight[self.m['id']] = time.monotonic()
        with mock.patch.object(self.e, '_check_and_push') as run:
            self.e._run_cycle()
        run.assert_not_called()

    def test_stop_is_seen_during_a_cycle(self):
        release = threading.Event()
        with mock.patch.object(self.e, '_check_and_push', side_effect=lambda m: release.wait(8)):
            threading.Timer(0.3, self.e.stop).start()
            t = time.monotonic()
            self.e._run_cycle()
            took = time.monotonic() - t
            release.set()
        self.assertLess(took, 3)

    def test_inflight_cleared_even_when_a_check_raises(self):
        with mock.patch.object(self.e, '_check_and_push', side_effect=RuntimeError('x')):
            self.e._run_cycle()
        self.assertEqual(self.e._inflight, {})


class SupervisorRestartTests(unittest.TestCase):
    """A server-requested restart must not leave an untracked web process."""

    def test_no_untracked_child(self):
        _env.reset()
        paths.ensure_dirs()
        started = []
        codes = [updater.EXIT_RESTART]

        class Proc:
            n = 0

            def __init__(self, code):
                Proc.n += 1
                self.pid, self.code, self.returncode, self.t = 1000 + Proc.n, code, None, time.monotonic()

            def poll(self):
                if self.returncode is None and self.code is not None and time.monotonic() - self.t > 0.6:
                    self.returncode = self.code
                return self.returncode

        def start(child):
            child.proc = Proc(codes.pop(0) if child.name == 'engine' and codes else None)
            child.started = time.monotonic()
            started.append(child)

        def stop(child, grace=0):
            child.proc = None

        sup = supervisor.Supervisor()
        threading.Timer(2.5, lambda: setattr(sup, 'stopping', True)).start()
        with mock.patch.object(supervisor.Child, 'start', start), \
                mock.patch.object(supervisor.Child, 'stop', stop):
            sup._loop()
        tracked = set(id(c) for c in sup.children.values())
        live = [c for c in started if c.proc is not None]
        self.assertTrue(all(id(c) in tracked for c in live), [c.name for c in live])
        self.assertEqual(sorted(c.name for c in started), ['engine', 'engine', 'web', 'web'])


class InstallBatTests(unittest.TestCase):
    def test_no_percent0_after_shift(self):
        with open(os.path.join(_env.REPO, 'install.bat'), 'rb') as f:
            bat = f.read().decode('ascii')
        after = bat.split('\r\nshift\r\n', 1)[1]
        self.assertIsNone(re.search(r'%~[a-z]*0', after), 'SHIFT moves %0: use %SELF% / %HERE%')


class PermsTests(unittest.TestCase):
    def test_root_acl(self):
        cmd = perms.root_icacls_command(r'C:\Uptime Sync 4', ('*S-1-5-21-1',))
        self.assertEqual(cmd[:3], ['icacls', r'C:\Uptime Sync 4', '/inheritance:r'])
        self.assertIn('*S-1-5-32-545:(OI)(CI)RX', cmd)      # Users: read + execute only
        self.assertIn('*S-1-5-21-1:(OI)(CI)F', cmd)
        self.assertNotIn('*S-1-5-11', ' '.join(cmd))

    def test_console_text_is_ascii(self):
        self.assertEqual(perms._console_text('ok \u0e01'.encode('utf-8')).encode('ascii').decode(), perms._console_text('ok \u0e01'.encode('utf-8')))


if __name__ == '__main__':
    unittest.main()
