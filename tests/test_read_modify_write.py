"""4.0.11: a file another program holds for a moment (an antivirus scan, a
backup tool) is no longer read as empty by code that saves it back (R-1),
and lowering check_interval no longer gets a healthy engine killed as
stalled (R-2)."""

from tests import _env  # noqa: F401  (must be first)

import builtins
import contextlib
import hashlib
import logging
import os
import re
import threading
import time
import unittest
from unittest import mock

from uptime_sync import engine, monitors, paths, settings, signing, supervisor, updater, util
from uptime_sync.web import auth, create_app
from tests.test_restore_rerun import zip_with
from tests.test_selfheal import _FakeInstall
from tests.test_updater import NEXT, REPO, FakeResponse, _read

PW = 'correct horse battery'


@contextlib.contextmanager
def held(*held_paths, times=None):
    """Opening any of held_paths raises PermissionError (Windows' "in use by
    another process"), every time or only the first `times` opens."""
    real = builtins.open
    targets = {os.path.abspath(p) for p in held_paths}
    count = [0]

    def fake(file, *args, **kwargs):
        if isinstance(file, str) and os.path.abspath(file) in targets:
            if times is None or count[0] < times:
                count[0] += 1
                raise PermissionError(13, 'in use by another process')
        return real(file, *args, **kwargs)
    with mock.patch('uptime_sync.util.open', create=True, side_effect=fake), \
            mock.patch.object(util.time, 'sleep'):
        yield count


def raw(path):
    with open(path, 'rb') as f:
        return f.read()


class ReadForUpdateTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()

    def test_retries_then_reads(self):
        util.atomic_write_json(paths.UPDATE_STATE_FILE, {'backup': 'b'})
        with held(paths.UPDATE_STATE_FILE, times=2) as n:
            self.assertEqual(util.read_json_for_update(paths.UPDATE_STATE_FILE, {}), {'backup': 'b'})
        self.assertEqual(n[0], 2)

    def test_raises_when_it_stays_held_and_missing_is_default(self):
        util.atomic_write_json(paths.UPDATE_STATE_FILE, {'backup': 'b'})
        with held(paths.UPDATE_STATE_FILE) as n:
            with self.assertRaises(OSError):
                util.read_json_for_update(paths.UPDATE_STATE_FILE, {})
        self.assertEqual(n[0], len(util.READ_RETRY_DELAYS) + 1)
        missing = os.path.join(paths.DATA_DIR, 'nope.json')
        self.assertEqual(util.read_json_for_update(missing, {'d': 1}), {'d': 1})

    def test_set_state_keeps_the_rollback_record(self):
        updater.set_state(status='Applied', backup='/x/backups/v1', previous='4.0.10')
        # Held for longer than the retries: merged onto what this process
        # last saw, never written as {crashes: 1} alone.
        with held(paths.UPDATE_STATE_FILE), self.assertLogs('update', 'WARNING'):
            updater.set_state(crashes=1)
        s = updater.state()
        self.assertEqual((s['backup'], s['previous'], s['crashes']), ('/x/backups/v1', '4.0.10', 1))

    def test_set_state_raises_when_this_process_never_saw_the_state(self):
        updater.set_state(status='Applied', backup='/x/backups/v1')
        before = raw(paths.UPDATE_STATE_FILE)
        with mock.patch.object(updater, '_known_state', None), held(paths.UPDATE_STATE_FILE):
            with self.assertRaises(OSError):
                updater.set_state(crashes=1)
            self.assertEqual(updater.state(), {})     # nothing known, nothing invented
        self.assertEqual(raw(paths.UPDATE_STATE_FILE), before)

    def test_settings_update_does_not_reset_the_site(self):
        settings.update({'site_name': 'Branch 7', 'check_interval': 120})
        before = raw(paths.SETTINGS_FILE)
        with held(paths.SETTINGS_FILE):
            with self.assertRaises(OSError):
                settings.update({'log_level': 'DEBUG'})
            self.assertEqual(settings.load()['site_name'], settings.defaults()['site_name'])  # reads fall back
        self.assertEqual(raw(paths.SETTINGS_FILE), before)
        self.assertEqual(settings.load()['site_name'], 'Branch 7')

    def test_monitor_load_strict_retries(self):
        monitors.save([monitors.normalize({'name': 'a', 'type': 'PING', 'target': '192.0.2.1'})])
        with held(paths.MONITORS_FILE, times=1):
            self.assertEqual(len(monitors.load(strict=True)), 1)
        with held(paths.MONITORS_FILE):
            with self.assertRaises(OSError):
                monitors.load(strict=True)

    def test_users_are_not_wiped(self):
        auth.create_user('admin', PW)
        auth.create_user('viewer1', PW, role='viewer')
        before = raw(paths.USERS_FILE)
        with held(paths.USERS_FILE):
            with self.assertRaises(OSError):
                auth.create_user('third', PW)
            with self.assertRaises(OSError):
                auth.set_password('admin', PW + 'x')
            with self.assertRaises(OSError):
                auth.revoke_sessions('admin')
        self.assertEqual(raw(paths.USERS_FILE), before)
        self.assertEqual(sorted(auth.load_users()), ['admin', 'viewer1'])

    def test_sign_in_works_when_the_second_read_fails(self):
        auth.create_user('admin', PW)
        real = auth.load_users

        def flaky(strict=False):
            if strict:
                raise PermissionError(13, 'in use')
            return real()
        with mock.patch.object(auth, 'load_users', flaky):
            with self.assertLogs('web', 'WARNING'):
                self.assertIsNotNone(auth.authenticate('admin', PW))

    def test_unreadable_latch_is_treated_as_latched(self):
        remote = {'url': 'https://mon.example.com/api/heartbeat.php', 'secret_key': 's' * 32}
        self.assertEqual(signing.latched_since(remote), '')
        self.assertTrue(signing.save_latch(remote, '2026-11-07'))
        self.assertEqual(signing.latched_since(remote), '2026-11-07')
        os.remove(paths.LATCH_FILE)
        util.atomic_write_json(paths.LATCH_FILE, {'fingerprint': 'other', 'since': 'x'})
        with held(paths.LATCH_FILE):
            self.assertEqual(signing.latched_since(remote), '?')


class WebUnreadableTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        auth._attempts.clear()
        self.app = create_app()
        self.app.testing = True
        self.c = self.app.test_client()
        r = self.c.get('/setup')
        token = re.search(r'name="csrf" value="([^"]+)"', r.get_data(as_text=True)).group(1)
        self.assertEqual(self.c.post('/setup', data={'csrf': token, 'password': PW, 'confirm': PW}).status_code, 302)

    def csrf(self, path):
        return re.search(r'name="csrf" value="([^"]+)"', self.c.get(path).get_data(as_text=True)).group(1)

    def test_monitor_toggle_changes_nothing_while_held(self):
        monitors.save([monitors.normalize({'name': 'a', 'type': 'PING', 'target': '192.0.2.1'}),
                       monitors.normalize({'name': 'b', 'type': 'PING', 'target': '192.0.2.2'})])
        mid = monitors.load()[0]['id']
        token = self.csrf('/monitors')
        before = raw(paths.MONITORS_FILE)
        with held(paths.MONITORS_FILE), self.assertLogs('web', 'WARNING'):
            r = self.c.post('/monitors/%s/toggle' % mid, data={'csrf': token})
        self.assertEqual(r.status_code, 302)
        self.assertIn('/monitors', r.headers['Location'])
        self.assertEqual(raw(paths.MONITORS_FILE), before)
        self.assertEqual(len(monitors.load()), 2)

    def test_sign_out_works_while_users_json_is_held(self):
        token = self.csrf('/')
        real = auth.load_users

        def flaky(strict=False):
            if strict:
                raise PermissionError(13, 'in use')
            return real()
        with mock.patch.object(auth, 'load_users', flaky), self.assertLogs('web', 'WARNING'):
            self.assertEqual(self.c.post('/logout', data={'csrf': token}).status_code, 302)
        self.assertIn('/login', self.c.get('/').headers['Location'])


class ResetPasswordTests(unittest.TestCase):
    def test_held_users_json_is_an_error_not_a_new_account(self):
        _env.reset()
        paths.ensure_dirs()
        auth.create_user('admin', PW)
        before = raw(paths.USERS_FILE)
        from uptime_sync import cli
        said = []
        with held(paths.USERS_FILE), mock.patch.object(cli, '_say', said.append), \
                mock.patch('getpass.getpass') as ask:
            self.assertEqual(cli.cmd_reset_password(mock.Mock(username='admin')), 1)
        ask.assert_not_called()
        self.assertIn('cannot be read', said[0])
        self.assertEqual(raw(paths.USERS_FILE), before)


class IntervalChangeTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()

    def test_supervisor_uses_the_interval_the_engine_runs_on(self):
        settings.update({'check_interval': 30})        # was 300 a moment ago
        sup = supervisor.Supervisor()
        child = mock.Mock()
        child.running.return_value = True
        child.started = time.monotonic() - 10000
        child.proc.pid = 4242
        sup.children['engine'] = child
        util.atomic_write_json(paths.STATUS_FILE, {'check_interval': 300})
        sup._check_pulse()
        # 200 s without a new status: past 3 x 30 + 60, within 3 x 300 + 60.
        with mock.patch.object(supervisor.time, 'monotonic', return_value=time.monotonic() + 200):
            sup._check_pulse()
        child.stop.assert_not_called()
        with mock.patch.object(supervisor.time, 'monotonic', return_value=time.monotonic() + 961):
            with self.assertLogs('supervisor', 'ERROR'):
                sup._check_pulse()
        child.stop.assert_called_once_with()

    def test_a_silly_status_value_cannot_disable_the_check(self):
        sup = supervisor.Supervisor()
        child = mock.Mock()
        child.running.return_value = True
        child.started = time.monotonic() - 10 ** 6
        child.proc.pid = 4242
        sup.children['engine'] = child
        util.atomic_write_json(paths.STATUS_FILE, {'check_interval': 10 ** 9})
        sup._check_pulse()
        limit = 3 * settings.BOUNDS['check_interval'][1] + 60
        with mock.patch.object(supervisor.time, 'monotonic', return_value=time.monotonic() + limit + 1):
            with self.assertLogs('supervisor', 'ERROR'):
                sup._check_pulse()
        child.stop.assert_called_once_with()

    def test_engine_wakes_when_the_interval_changes(self):
        settings.update({'check_interval': 300})
        e = engine.Engine(supervised=True)
        e.settings = settings.load()
        e._wake = threading.Event()
        e._wake_on_interval_change()                   # first look: records only
        self.assertFalse(e._wake.is_set())
        settings.update({'site_name': 'x'})
        os.utime(paths.SETTINGS_FILE, (time.time() + 5, time.time() + 5))
        e._wake_on_interval_change()                   # changed, same interval
        self.assertFalse(e._wake.is_set())
        settings.update({'check_interval': 30})
        os.utime(paths.SETTINGS_FILE, (time.time() + 10, time.time() + 10))
        with held(paths.SETTINGS_FILE):              # held: no false "changed to 60s"
            e._wake_on_interval_change()
        self.assertFalse(e._wake.is_set())
        with self.assertLogs('engine', 'INFO'):
            e._wake_on_interval_change()             # readable again: the change is seen
        self.assertTrue(e._wake.is_set())

    def test_status_names_the_interval(self):
        e = engine.Engine(supervised=True)
        e.settings = dict(settings.load(), check_interval=45)
        e._write_status()
        self.assertEqual(util.read_json(paths.STATUS_FILE, {})['check_interval'], 45)



class ApplyWhileHeldTests(_FakeInstall):
    """The review case: update-state.json held by an antivirus while an
    update is applied. It must end 'Applied', not stay 'Applying' (which
    the next start would roll back, and never retry)."""

    def test_update_applied_with_the_state_file_held(self):
        logging.getLogger('update').disabled = True
        self.addCleanup(setattr, logging.getLogger('update'), 'disabled', False)
        data = zip_with(_read('requirements.txt'))
        with mock.patch.object(updater, '_open', return_value=FakeResponse(data)):
            updater.download_and_stage(updater.github_url(REPO, NEXT), NEXT,
                                       hashlib.sha256(data).hexdigest(), self.settings)
        updater.state()                                  # the supervisor reads it at start
        with held(paths.UPDATE_STATE_FILE), \
                mock.patch.object(updater, '_smoke_test', return_value=(True, '')):
            self.assertEqual(updater.apply(), NEXT)
        s = updater.state()
        self.assertEqual((s['status'], s['version']), ('Applied', NEXT))
        self.assertTrue(s['backup'])
        self.assertFalse(updater.recover_interrupted())


if __name__ == '__main__':
    unittest.main()
