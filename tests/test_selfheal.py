"""Regression tests for the 4.0.8 audit: self-healing files, the log store,
settings coercion, update recovery, and the security fixes."""

from tests import _env  # noqa: F401  (must be first)

import io
import json
import logging
import os
import shutil
import sqlite3
import struct
import sys
import time
import unittest
from unittest import mock

import requests
import urllib3

from uptime_sync import (__version__, autostart, checks, engine, heartbeat, log as logsetup, logstore,
                         loglevel, monitors, paths, perms, procs, settings, supervisor, updater, util)
from uptime_sync.web import auth, create_app
from uptime_sync.web.views import mask_push_url
from tests.test_updater import NEXT, REPO, FakeResponse, _read, make_zip

TOKEN = 'TOKEN1234567890'


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)


def read(path):
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()


# -- self-healing JSON ---------------------------------------------------------------

class HealJsonTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        self.path = os.path.join(paths.DATA_DIR, 'thing.json')

    def test_missing_is_default_without_noise(self):
        self.assertEqual(util.read_json(self.path, {'a': 1}), {'a': 1})
        self.assertEqual(util.corrupt_copies(self.path), [])

    def test_corrupt_is_quarantined_and_restored_from_backup(self):
        util.atomic_write_json(self.path, {'v': 1}, backup=True)
        util.atomic_write_json(self.path, {'v': 2}, backup=True)   # .bak = v1
        write(self.path, '{"v": 3')                                  # torn write
        with self.assertLogs('heal', 'CRITICAL') as cm:
            self.assertEqual(util.read_json(self.path, {}), {'v': 1})
        self.assertIn('restored', cm.output[0])
        self.assertEqual(len(util.corrupt_copies(self.path)), 1)
        self.assertEqual(json.loads(read(self.path)), {'v': 1})

    def test_corrupt_without_backup_gives_default(self):
        write(self.path, 'garbage')
        with self.assertLogs('heal', 'CRITICAL'):
            self.assertEqual(util.read_json(self.path, {'d': 0}), {'d': 0})
        self.assertFalse(os.path.exists(self.path))
        self.assertEqual(len(util.corrupt_copies(self.path)), 1)

    def test_heal_false_leaves_the_file(self):
        write(self.path, 'garbage')
        self.assertEqual(util.read_json(self.path, {}, heal=False), {})
        self.assertEqual(read(self.path), 'garbage')

    def test_corrupt_file_never_replaces_good_backup(self):
        util.atomic_write_json(self.path, {'v': 1})
        util.atomic_write_json(self.path, {'v': 2}, backup=True)   # .bak = v1
        write(self.path, 'garbage')
        util.atomic_write_json(self.path, {'v': 3}, backup=True)   # must not back up garbage
        self.assertEqual(json.loads(read(self.path + '.bak')), {'v': 1})

    def test_only_a_few_corrupt_copies_kept(self):
        for i in range(util.CORRUPT_KEEP + 3):
            write(self.path, 'bad')
            stamp = '20260101-0000%02d' % i
            with mock.patch.object(util.time, 'strftime', return_value=stamp):
                with self.assertLogs('heal', 'CRITICAL'):
                    util.read_json(self.path, {})
        self.assertEqual(len(util.corrupt_copies(self.path)), util.CORRUPT_KEEP)

    def test_compact(self):
        util.atomic_write_json(self.path, {'a': [1, 2]}, compact=True)
        self.assertEqual(read(self.path), '{"a":[1,2]}\n')

    def test_settings_and_monitors_keep_a_backup(self):
        settings.update({'site_name': 'one'})
        settings.update({'site_name': 'two'})
        self.assertEqual(json.loads(read(paths.SETTINGS_FILE + '.bak'))['site_name'], 'one')
        write(paths.SETTINGS_FILE, '{')
        with self.assertLogs('heal', 'CRITICAL'):
            self.assertEqual(settings.load()['site_name'], 'one')

    def test_corrupt_users_keep_setup_closed(self):
        write(paths.USERS_FILE, 'garbage')
        with self.assertLogs('heal', 'CRITICAL'):
            self.assertTrue(auth.has_users())
        self.assertTrue(auth.accounts_lost())


class WebHealTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        auth._attempts.clear()
        self.app = create_app()
        self.app.testing = True
        self.c = self.app.test_client()

    def test_lost_accounts_point_at_reset_password(self):
        write(paths.USERS_FILE, 'garbage')
        logging.disable(logging.CRITICAL)
        try:
            self.assertEqual(self.c.get('/setup').status_code, 302)
            html = self.c.get('/login').get_data(as_text=True)
        finally:
            logging.disable(logging.NOTSET)
        self.assertIn('reset-password', html)

    def test_setup_refuses_a_foreign_host_header(self):
        # DNS rebinding: loopback address, but the page is evil.example's
        r = self.c.get('/setup', headers={'Host': 'evil.example:5000'})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.c.get('/setup', headers={'Host': '127.0.0.1:5000'}).status_code, 200)
        self.assertEqual(self.c.get('/setup', headers={'Host': '[::1]:5000'}).status_code, 200)

    def test_rate_limiter_forgets_idle_ips(self):
        auth._attempts['10.0.0.9'] = [time.time() - 3600]
        self.assertFalse(auth.rate_limited('10.0.0.9'))
        self.assertNotIn('10.0.0.9', auth._attempts)


# -- log store ------------------------------------------------------------------------

def _insert(rows):
    logstore.init_db()
    conn = logstore.connect()
    with conn:
        conn.executemany('INSERT INTO logs (ts, proc, level, logger, msg) VALUES (?, ?, ?, ?, ?)', rows)
    conn.close()


class LogStoreTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        os.makedirs(paths.LOG_DIR, exist_ok=True)

    def test_writer_thread_stores_lines(self):
        logstore.init_db()
        h = logstore.SQLiteHandler('engine')
        lg = logging.getLogger('selfheal.writer')
        lg.addHandler(h)
        lg.propagate = False
        try:
            lg.warning('hello %s', 'world')
        finally:
            lg.removeHandler(h)
            h.close()
        rows = logstore.query(text='hello world')
        self.assertEqual([r['msg'] for r in rows], ['hello world'])
        self.assertEqual(rows[0]['proc'], 'engine')

    def test_like_wildcards_are_literal(self):
        now = time.time()
        _insert([(now, 'engine', 20, 'x', '100% done'), (now, 'engine', 20, 'x', '1000 done'),
                 (now, 'engine', 20, 'x', 'a_b'), (now, 'engine', 20, 'x', 'axb')])
        self.assertEqual([r['msg'] for r in logstore.query(text='0%')], ['100% done'])
        self.assertEqual([r['msg'] for r in logstore.query(text='a_b')], ['a_b'])

    def test_filters_use_indexes_and_survive_a_missing_one(self):
        now = time.time()
        _insert([(now, 'engine', 20, 'x', 'info')] * 50 + [(now, 'web', 40, 'x', 'boom')])
        self.assertEqual([r['msg'] for r in logstore.query(min_level=30)], ['boom'])
        self.assertEqual(len(logstore.query(proc='engine')), 50)
        conn = logstore.connect()
        plan = conn.execute('EXPLAIN QUERY PLAN SELECT id FROM logs INDEXED BY logs_level_id '
                            'WHERE level >= 30 ORDER BY id DESC').fetchall()
        conn.execute('DROP INDEX logs_level_id')
        conn.commit()
        conn.close()
        self.assertIn('logs_level_id', str(plan))
        self.assertEqual([r['msg'] for r in logstore.query(min_level=30)], ['boom'])

    def test_prune_gives_space_back(self):
        old = time.time() - 30 * 86400
        _insert([(old, 'engine', 20, 'x', 'y' * 1000) for _ in range(4000)])
        conn = logstore.connect()
        conn.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchall()
        conn.close()
        before = os.path.getsize(logstore.DB_FILE)
        self.assertEqual(logstore.prune(14), 4000)
        self.assertLess(os.path.getsize(logstore.DB_FILE), before / 4)

    def test_size_cap_drops_the_oldest(self):
        now = time.time()
        _insert([(now, 'engine', 20, 'x', '%05d %s' % (i, 'y' * 1000)) for i in range(3000)])
        with self.assertLogs('log', 'WARNING'):
            removed = logstore.prune(14, max_bytes=1024 * 1024, target_bytes=512 * 1024)
        self.assertGreater(removed, 2000)
        left = logstore.query(limit=1000)
        self.assertTrue(left and left[0]['msg'].startswith('02999'))   # newest kept
        self.assertLess(os.path.getsize(logstore.DB_FILE), 1024 * 1024)

    def test_corrupt_database_is_quarantined(self):
        write(logstore.DB_FILE, 'this is not a database ' * 200)
        logstore.init_db()
        self.assertTrue(any(n.startswith('logs.db.corrupt-') for n in os.listdir(paths.LOG_DIR)))
        _insert([(time.time(), 'engine', 20, 'x', 'fresh')])
        self.assertEqual([r['msg'] for r in logstore.query()], ['fresh'])

    def test_prune_and_query_on_a_corrupt_file_do_not_raise(self):
        write(logstore.DB_FILE, 'garbage ' * 600)
        self.assertEqual(logstore.query(), [])
        self.assertEqual(logstore.prune(14), 0)
        self.assertEqual(logstore.query(), [])   # a fresh, empty database

    def test_setup_never_raises(self):
        root = logging.getLogger()
        saved = list(root.handlers)
        try:
            with mock.patch.object(logstore, 'init_db', side_effect=OSError('read-only')), \
                    mock.patch.object(logging, 'FileHandler', side_effect=OSError('disk full')):
                logsetup.setup('engine', 'INFO', console=False)
            self.assertTrue(root.handlers)
        finally:
            for h in list(root.handlers):
                root.removeHandler(h)
            for h in saved:
                root.addHandler(h)


# -- settings ---------------------------------------------------------------------------

class SettingsTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        settings._warned.clear()

    def test_numbers_are_coerced_and_clamped(self):
        util.atomic_write_json(paths.SETTINGS_FILE, {
            'check_interval': 'abc', 'max_workers': 999, 'retry_delay': float('nan'),
            'web': {'port': 0}, 'remote': {'heartbeat_interval': '120'}})
        with self.assertLogs('settings', 'WARNING') as cm:
            s = settings.load()
        self.assertEqual((s['check_interval'], s['max_workers'], s['retry_delay']), (60, 64, 1.0))
        self.assertEqual((s['web']['port'], s['remote']['heartbeat_interval']), (1, 120))
        n = len(cm.output)
        with self.assertLogs('settings', 'WARNING') as cm2:
            settings.load()
            logging.getLogger('settings').warning('marker')
        self.assertEqual(len(cm2.output), 1, 'warned again: %s' % cm2.output[:n])

    def test_agent_credentials_never_expand_in_monitors(self):
        write(paths.ENV_FILE, 'UPTIME_SECRET_KEY=hmacsecret\nUPTIME_SYNC_SECRET_KEY=flask\n'
                              'PUSH_TOKEN=%s\n' % TOKEN)
        url = 'https://kuma.example/api/push/${PUSH_TOKEN}?k=${UPTIME_SECRET_KEY}&f=${UPTIME_SYNC_SECRET_KEY}'
        out = settings.expand_refs(url)
        self.assertIn(TOKEN, out)
        self.assertNotIn('hmacsecret', out)
        self.assertNotIn('flask', out.split('?')[1].replace('f=${UPTIME_SYNC_SECRET_KEY}', ''))
        self.assertIn('${UPTIME_SECRET_KEY}', out)
        m = monitors.normalize({'name': 'x', 'type': 'PING', 'target': '1.1.1.1', 'push_url': url})
        self.assertTrue(any('own credentials' in e for e in monitors.validate(m)))
        rt = monitors.runtime_view(m)
        self.assertNotIn('hmacsecret', rt['push_url'])

    def test_server_download_flag_is_not_in_the_web_form(self):
        # The web Settings form builds its dict by hand; it must never carry this key.
        with open(os.path.join(_env.REPO, 'uptime_sync', 'web', 'views.py'), encoding='utf-8') as f:
            self.assertNotIn('allow_server_download', f.read())
        self.assertIs(settings.load()['update']['allow_server_download'], False)


# -- updater ----------------------------------------------------------------------------

class _FakeInstall(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        root = paths.ROOT
        write(os.path.join(root, 'uptime_sync', '__init__.py'), '# old\n')
        write(os.path.join(root, 'main.py'), '# old\n')
        write(os.path.join(root, 'requirements.txt'), _read('requirements.txt'))
        self.settings = {'remote': {'url': 'https://mon.example.com/api/heartbeat.php',
                                    'api_key': 'k', 'secret_key': 's'},
                         'update': {'github_repo': REPO}}
        p = mock.patch.object(updater, '_smoke_test', return_value=(True, ''))
        p.start()
        self.addCleanup(p.stop)

    def tearDown(self):
        shutil.rmtree(os.path.join(paths.ROOT, 'config'), ignore_errors=True)
        shutil.copytree(os.path.join(_env.REPO, 'config'), os.path.join(paths.ROOT, 'config'))
        write(os.path.join(paths.ROOT, 'VERSION'), _read('VERSION'))

    def stage(self):
        data = make_zip(NEXT)
        import hashlib
        with mock.patch.object(updater, '_open', return_value=FakeResponse(data)):
            updater.download_and_stage(updater.github_url(REPO, NEXT), NEXT,
                                       hashlib.sha256(data).hexdigest(), self.settings)

    def assert_old_code(self):
        self.assertEqual(read(os.path.join(paths.ROOT, 'main.py')), '# old\n')
        self.assertEqual(read(os.path.join(paths.ROOT, 'uptime_sync', '__init__.py')), '# old\n')
        self.assertEqual(read(os.path.join(paths.ROOT, 'VERSION')).split()[0], __version__)


class ServerDownloadGateTests(_FakeInstall):
    def test_server_download_refused_unless_allowed(self):
        with self.assertRaises(updater.UpdateRefused) as cm:
            updater.download_and_stage('/dist/download.php', NEXT, 'a' * 64, self.settings)
        self.assertIn('allow_server_download', str(cm.exception))
        self.settings['update']['allow_server_download'] = True
        with mock.patch.object(updater, '_open', return_value=FakeResponse(b'not a zip')):
            with self.assertRaises(updater.UpdateRefused) as cm:   # past the gate: hash check
                updater.download_and_stage('/dist/download.php', NEXT, 'a' * 64, self.settings)
        self.assertIn('SHA-256', str(cm.exception))


class InterruptedApplyTests(_FakeInstall):
    def _interrupt(self, **patch):
        self.stage()
        with mock.patch.multiple(updater, **patch):
            with self.assertRaises(KeyboardInterrupt):
                updater.apply()
        self.assertEqual(updater.state()['status'], 'Applying')
        self.assertEqual(updater.heartbeat_fields()[0], 'Installing')

    def _recover(self):
        with self.assertLogs('update', 'CRITICAL'):
            self.assertTrue(updater.recover_interrupted())
        self.assert_old_code()
        s = updater.state()
        self.assertEqual(s['status'], 'Failed')
        self.assertIn('interrupted', s['detail'])
        self.assertFalse(os.path.exists(paths.STAGING_DIR))
        self.assertEqual([d for d in os.listdir(paths.BACKUP_DIR) if not d.startswith('v')], [])
        self.assertFalse(updater.recover_interrupted())   # once only

    def test_killed_after_the_swap(self):
        self._interrupt(_smoke_test=mock.Mock(side_effect=KeyboardInterrupt))
        self.assertEqual(read(os.path.join(paths.ROOT, 'main.py')), '# new\n')
        self._recover()

    def test_killed_while_moving_out(self):
        real = updater._move

        def partial(names, src, dst, done):
            real(names[:1], src, dst, done)
            raise KeyboardInterrupt
        self._interrupt(_move=partial)
        self._recover()

    def test_killed_while_moving_in(self):
        real, calls = updater._move, []

        def partial(names, src, dst, done):
            calls.append(1)
            if len(calls) == 1:
                return real(names, src, dst, done)
            real(names[:2], src, dst, done)
            raise KeyboardInterrupt
        self._interrupt(_move=partial)
        self._recover()

    def test_nothing_moved(self):
        logging.getLogger('update').disabled = True
        self.addCleanup(setattr, logging.getLogger('update'), 'disabled', False)
        updater.set_state(status='Applying', version=NEXT, previous=__version__,
                          backup=os.path.join(paths.BACKUP_DIR, 'v-none'), installed=['main.py'])
        self.assertFalse(updater.recover_interrupted())
        self.assertEqual(updater.state()['status'], 'Failed')
        self.assert_old_code()

    def test_pending_not_rewritten_for_the_same_offer(self):
        updater.write_pending(NEXT, 'u', 'a' * 64, 'manual')
        first = read(paths.UPDATE_PENDING)
        with mock.patch.object(updater, 'atomic_write_json') as w:
            updater.write_pending(NEXT, 'u', 'a' * 64, 'manual')
        w.assert_not_called()
        self.assertEqual(read(paths.UPDATE_PENDING), first)


# -- heartbeat ---------------------------------------------------------------------------

class FakeReply:
    def __init__(self, status, body=b'{"success": true}', headers=None):
        self.status_code = status
        self.content = body
        self.headers = headers or {}
        # a real urllib3 response over the bytes: util.iter_body reads raw
        self.raw = urllib3.HTTPResponse(body=io.BytesIO(body), headers=self.headers, status=status,
                                        preload_content=False)

    def json(self):
        return json.loads(self.content.decode('utf-8'))

    def close(self):
        self.closed = True


class HeartbeatSendTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        self.s = util.deep_merge(settings.load(), {'remote': {
            'enabled': True, 'url': 'https://mon.example.com/api/heartbeat.php', 'api_key': 'k',
            'secret_key': '', 'require_signed_response': False}})
        self.hb = heartbeat.Heartbeat(time.time())

    def send(self, reply):
        with mock.patch.object(self.hb.session, 'post', side_effect=reply
                               if isinstance(reply, Exception) else None, return_value=reply):
            return self.hb.send(self.s)

    def test_ok_and_next_check_in(self):
        self.assertEqual(self.send(FakeReply(200, b'{"success": true, "next_check_in": 120}'))['success'], True)
        self.assertEqual(self.hb.interval(self.s), 120)
        self.assertEqual(self.hb.failures, 0)

    def test_5xx_and_network_errors_back_off(self):
        self.assertIsNone(self.send(FakeReply(503)))
        self.assertEqual(self.hb.interval(self.s), 30)
        with self.assertLogs('heartbeat', 'WARNING'):
            self.assertIsNone(self.send(requests.ConnectionError('down')))
        self.assertEqual(self.hb.interval(self.s), 60)
        with self.assertLogs('heartbeat', 'INFO') as cm:
            self.send(FakeReply(200))
        self.assertIn('recovered after 2', '\n'.join(cm.output))
        self.assertEqual(self.hb.interval(self.s), 60)   # back to heartbeat_interval

    def test_4xx_does_not_back_off(self):
        with self.assertLogs('heartbeat', 'WARNING'):
            self.assertIsNone(self.send(FakeReply(401)))
        self.assertEqual(self.hb.failures, 0)

    def test_non_json_reply_is_a_failure(self):
        self.assertIsNone(self.send(FakeReply(200, b'<html>')))
        self.assertEqual(self.hb.failures, 1)

    def test_uses_one_session(self):
        self.assertIsInstance(self.hb.session, requests.Session)
        self.assertIn('UptimeSync/', self.hb.session.headers['User-Agent'])


# -- checks -----------------------------------------------------------------------------

class FakeUdp:
    """A DNS server that answers every query (with REFUSED)."""
    answered = True

    def __init__(self, family, kind):
        self.q = []

    def connect(self, addr):
        self.addr = addr

    def send(self, data):
        self.q.append(data)

    def settimeout(self, t):
        pass

    def recv(self, n):
        if not FakeUdp.answered:
            import socket
            raise socket.timeout()
        txid = struct.unpack('>H', self.q[-1][:2])[0]
        return struct.pack('>HHHHHH', txid, 0x8185, 1, 0, 0, 0) + self.q[-1][12:]

    def close(self):
        pass


class DnsTests(unittest.TestCase):
    def test_query_dns_server(self):
        c = checks.Checker()
        with mock.patch.object(checks.socket, 'socket', FakeUdp):
            FakeUdp.answered = True
            self.assertIsNotNone(c.query_dns_server('192.0.2.53', 'example.com', 1.0))
            FakeUdp.answered = False
            self.assertIsNone(c.query_dns_server('192.0.2.53', 'example.com', 1.0))

    def test_breaker_is_half_open_after_the_window(self):
        c = checks.Checker()
        calls = []

        def fail(*a):
            calls.append(1)
            raise OSError('nxdomain')
        with mock.patch.object(checks.socket, 'getaddrinfo', fail):
            with self.assertLogs('checks', 'WARNING'):
                for _ in range(3):
                    c.check_dns('dead.example')
            self.assertEqual(c.check_dns('dead.example'), (False, 0))
            self.assertEqual(len(calls), 3)                  # open: no lookup
            count, opened, probing = c._dns_failures['dead.example']
            c._dns_failures['dead.example'] = (count, opened - 120, False)
            self.assertFalse(c._circuit_open('dead.example'))   # this caller probes
            self.assertTrue(c._circuit_open('dead.example'))    # others still fail fast
            c._dns_failures['dead.example'] = (count, opened - 120, False)
            c.check_dns('dead.example')                          # the probe fails ...
            self.assertEqual(len(calls), 4)
            c.check_dns('dead.example')                          # ... reopened at once
            self.assertEqual(len(calls), 4)
        with mock.patch.object(checks.socket, 'getaddrinfo', return_value=[]):
            c._dns_failures['dead.example'] = (count, opened - 120, False)
            with self.assertLogs('checks', 'INFO'):
                self.assertTrue(c.check_dns('dead.example')[0])
        self.assertNotIn('dead.example', c._dns_failures)

    def test_ping_that_cannot_run_logs_error_once(self):
        c = checks.Checker()
        with mock.patch.object(checks.procs, 'run', return_value=(None, b'', 'no such file')):
            with self.assertLogs('checks', 'DEBUG') as cm:
                c.ping('192.0.2.1', 1)
                c.ping('192.0.2.2', 1)
        levels = [r.levelname for r in cm.records]
        self.assertEqual(levels, ['ERROR', 'DEBUG'])


class ProcsRunTests(unittest.TestCase):
    def test_timeout_kills(self):
        t = time.monotonic()
        code, out, error = procs.run([sys.executable, '-c', 'import time; time.sleep(20)'], 1)
        self.assertIsNone(code)
        self.assertIn('timed out', error)
        self.assertLess(time.monotonic() - t, 10)

    def test_cannot_start(self):
        code, out, error = procs.run(['/nonexistent/prog'], 5)
        self.assertIsNone(code)
        self.assertTrue(error)

    def test_pid_write_failure_is_not_fatal(self):
        with mock.patch('uptime_sync.util.atomic_write_text', side_effect=OSError('ro')):
            self.assertFalse(procs.write_pid(os.path.join(paths.RUN_DIR, 'x.pid')))


# -- engine -----------------------------------------------------------------------------

class EngineTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        self.e = engine.Engine(supervised=True)
        self.m = monitors.normalize({'name': 'kuma', 'type': 'PING', 'target': '192.0.2.1',
                                     'push_url': 'https://kuma.example/api/push/' + TOKEN})
        self.e.monitors = [self.m]
        self.e.settings = util.deep_merge(settings.load(), {'check_interval': 10})

    def test_push_failure_logs_host_only(self):
        err = requests.ConnectionError('HTTPSConnectionPool: /api/push/%s?status=up' % TOKEN)
        with mock.patch.object(self.e.session, 'get', side_effect=err):
            with self.assertLogs('engine', 'WARNING') as cm:
                self.e._push(self.m, True, 5, 0)
        text = '\n'.join(cm.output)
        self.assertIn('https://kuma.example', text)
        self.assertNotIn(TOKEN, text)

    def test_steady_pushes_log_at_debug(self):
        r = mock.Mock(status_code=200, is_redirect=False)
        with mock.patch.object(self.e.session, 'get', return_value=r):
            with self.assertLogs('engine', 'DEBUG') as cm:
                self.e._push(self.m, True, 5, 0)
                self.e._push(self.m, True, 6, 0)
                self.e._push(self.m, False, 0, 0)
        self.assertEqual([x.levelname for x in cm.records], ['INFO', 'DEBUG', 'INFO'])

    def test_404_streak_warns_once_without_token(self):
        with self.assertLogs('engine', 'WARNING') as cm:
            for _ in range(engine.PUSH_WINDOW + 5):
                self.e._track_push(self.m, 404)
        alerts = [o for o in cm.output if '[PUSH]' in o]
        self.assertEqual(len(alerts), 1)
        self.assertNotIn(TOKEN, alerts[0])
        with self.assertLogs('engine', 'INFO'):
            self.e._track_push(self.m, 200)
        self.assertEqual(self.e._push_alerted, set())

    def test_push_telemetry_dropped_with_the_monitor(self):
        self.e._track_push(self.m, 200)
        monitors.save([])
        self.e._reload_monitors(force=True)
        self.assertEqual(self.e._push_codes, {})

    def test_act_on(self):
        with mock.patch.object(settings, 'update') as upd, mock.patch.object(loglevel, 'apply'):
            with self.assertLogs('engine', 'WARNING'):
                self.e._act_on({'settings': {'log_level': 'debug'}}, self.e.settings)
        upd.assert_called_once_with({'log_level': 'DEBUG'})
        with self.assertLogs('engine', 'WARNING'):
            self.e._act_on({'restart_requested': True, 'update_available': True}, self.e.settings)
        self.assertEqual(self.e.exit_code, updater.EXIT_RESTART)

    def test_stuck_check_reported_down_then_engine_restarts(self):
        self.e._inflight[self.m['id']] = time.monotonic() - 5
        with mock.patch.object(self.e, '_push'):
            with self.assertLogs('engine', 'WARNING'):
                self.e._run_cycle()
        self.assertFalse(self.e.results[self.m['id']]['ok'])
        self.assertTrue(self.e.results[self.m['id']]['stuck'])
        self.assertEqual(self.e.exit_code, 0)
        self.e._inflight[self.m['id']] = time.monotonic() - 10 * engine.STUCK_CYCLES - 1
        with mock.patch.object(self.e, '_push'):
            with self.assertLogs('engine', 'ERROR'):
                self.e._run_cycle()
        self.assertEqual(self.e.exit_code, updater.EXIT_STUCK)

    def test_history_saved_every_n_cycles(self):
        with mock.patch.object(self.e, '_check_and_push'):
            for _ in range(engine.HISTORY_SAVE_EVERY - 1):
                self.e._run_cycle()
            self.assertFalse(os.path.exists(paths.HISTORY_FILE))
            self.e._run_cycle()
        self.assertTrue(os.path.exists(paths.HISTORY_FILE))

    def test_housekeeping_never_raises(self):
        with mock.patch.object(logsetup, 'prune', side_effect=sqlite3.DatabaseError('boom')):
            with self.assertLogs('engine', 'ERROR'):
                self.e._housekeeping()
        self.e._housekeeping()   # within the hour: not run again, no error

    def test_low_disk_shortens_retention(self):
        with mock.patch.object(heartbeat, 'free_disk_ok', return_value=False), \
                mock.patch.object(logsetup, 'prune', return_value=0) as prune:
            with self.assertLogs('engine', 'WARNING'):
                self.e._housekeeping()
        prune.assert_called_once_with(engine.LOW_DISK_RETENTION_DAYS)

    def test_budget_warning_once(self):
        slow = monitors.normalize({'name': 's', 'type': 'HTTPS', 'target': 'x.example',
                                   'timeout': 30, 'retry_count': 3})
        self.e.monitors = [slow]
        with self.assertLogs('engine', 'WARNING') as cm:
            self.e._warn_budget(1, 9)
            self.e._warn_budget(1, 9)
            logging.getLogger('engine').warning('marker')
        self.assertEqual(len(cm.output), 2)


# -- supervisor / autostart / perms / web helpers ------------------------------------

class SupervisorTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()

    def test_lock_first_then_logging(self):
        other = procs.InstanceLock(paths.LOCK_FILE)
        self.assertTrue(other.acquire())
        try:
            with mock.patch.object(supervisor.logsetup, 'setup') as setup:
                self.assertEqual(supervisor.Supervisor().run(), 0)
            setup.assert_not_called()
        finally:
            other.release()

    def test_backoff(self):
        c = supervisor.Child('engine', [])
        c.started = time.monotonic()
        self.assertEqual([c.schedule_restart() for _ in range(8)], [1, 2, 5, 10, 30, 60, 60, 60])
        c.started = time.monotonic() - supervisor.STABLE_SECONDS - 1
        self.assertEqual(c.schedule_restart(), 1)

    def test_stalled_engine_is_restarted(self):
        sup = supervisor.Supervisor()
        child = mock.Mock()
        child.running.return_value = True
        child.started = time.monotonic() - 10000
        child.schedule_restart.return_value = 1
        child.proc.pid = 4242
        sup.children['engine'] = child
        util.touch(paths.STATUS_FILE, '{}')
        sup._check_pulse()
        child.stop.assert_not_called()                 # fresh status file
        # The wall clock stepped back 10000 s (w32time): the file's mtime now
        # looks ancient, but it CHANGED, so the engine is alive.
        old = time.time() - 10000
        os.utime(paths.STATUS_FILE, (old, old))
        sup._check_pulse()
        child.stop.assert_not_called()
        # Unchanged for longer than 3 intervals + 60 s of monotonic time: stalled.
        later = time.monotonic() + 3 * settings.load()['check_interval'] + 61
        with mock.patch.object(supervisor.time, 'monotonic', return_value=later):
            with self.assertLogs('supervisor', 'ERROR'):
                sup._check_pulse()
        child.stop.assert_called_once_with()


class AutostartNameTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()

    def test_choose_name(self):
        ours = '<Arguments>"%s" run</Arguments>' % autostart.MAIN_PY
        self.assertEqual(autostart.choose_name('UptimeSync4', lambda n: None), 'UptimeSync4')
        self.assertEqual(autostart.choose_name('UptimeSync4', lambda n: ours), 'UptimeSync4')
        other = autostart.choose_name('UptimeSync4', lambda n: '"C:\\Other\\main.py" run')
        self.assertTrue(other.startswith('UptimeSync4-') and len(other) == len('UptimeSync4-') + 8)
        util.atomic_write_json(autostart.STATE_FILE, {'name': 'Kept'})
        self.assertEqual(autostart.choose_name('UptimeSync4', lambda n: 'x'), 'Kept')

    def test_definitions(self):
        self.assertIn('<string>lbl-1</string>', autostart.launchd_plist('/py', '/opt/us', label='lbl-1'))
        self.assertIn('ExecStart="/py" "%s" run' % os.path.join('/opt/us', 'main.py'),
                      autostart.systemd_unit('/py', '/opt/us', 'svc'))
        xml = autostart.windows_task_xml('C:\\us\\.venv\\Scripts\\pythonw.exe', 'C:\\A&B')
        self.assertIn('C:\\A&amp;B', xml)


class PermsTests(unittest.TestCase):
    def test_broad_writers(self):
        out = '\n'.join(['S-1-5-18 2032127',
                         'S-1-5-32-545 1179817',      # Users: read + execute
                         'S-1-5-11 1245631',          # Authenticated Users: modify
                         'S-1-1-0 -536805376',        # Everyone: GENERIC (inherit-only)
                         ' junk'])
        self.assertEqual(perms.broad_writers(out), ['Authenticated Users', 'Everyone'])
        self.assertEqual(perms.broad_writers('S-1-5-32-545 1179817'), [])
        # A per-user Python: one user SID with full control, and the owner.
        per_user = '\n'.join(['S-1-5-18 2032127', 'S-1-5-32-544 2032127',
                               'S-1-5-21-1-2-3-1001 2032127', 'S-1-3-0 268435456',
                               'OWNER S-1-5-21-1-2-3-1001'])
        self.assertEqual(perms.broad_writers(per_user),
                         ['S-1-5-21-1-2-3-1001', 'its owner S-1-5-21-1-2-3-1001'])
        self.assertEqual(perms.broad_writers('S-1-5-18 2032127\nOWNER S-1-5-32-544'), [])

    def test_under_user_profile(self):
        import ntpath
        with mock.patch.object(perms.os, 'path', ntpath), mock.patch.object(perms.os, 'sep', '\\'):
            self.assertTrue(perms.under_user_profile(
                'C:\\Users\\lab\\AppData\\Local\\Programs\\Python\\Python38-32', 'C:'))
            self.assertFalse(perms.under_user_profile('C:\\Python38', 'C:'))
            self.assertFalse(perms.under_user_profile('C:\\UsersX\\Python', 'C:'))

    def test_acl_ps_command_quotes(self):
        cmd = perms.acl_ps_command("C:\\Py'38")
        self.assertIn("'C:\\Py''38'", cmd[-1])

    def test_root_acl_reapplied_only_when_changed(self):
        _env.reset()
        paths.ensure_dirs()
        calls = []

        def run(cmd, timeout=300):
            calls.append(cmd)
            return 0, 'same acl listing'
        with mock.patch.object(perms, '_run', run), mock.patch.object(perms, '_dirs', return_value=[]):
            perms._windows_harden(False)
            self.assertTrue(any('/inheritance:r' in c for c in calls))
            calls[:] = []
            perms._windows_harden(False)
            self.assertFalse(any('/inheritance:r' in c for c in calls))


class MaskTests(unittest.TestCase):
    def test_mask_push_url(self):
        self.assertEqual(mask_push_url('https://kuma.example/api/push/%s?status=up' % TOKEN),
                         'https://kuma.example/api/push/***')
        self.assertEqual(mask_push_url('https://u:pw@kuma.example:8443/api/push/x'),
                         'https://kuma.example:8443/api/push/***')
        self.assertEqual(mask_push_url('not a url'), '')


if __name__ == '__main__':
    unittest.main()


class ServerTlsTests(unittest.TestCase):
    def test_is_local_host(self):
        for host in ('127.0.0.1', 'localhost', '192.168.1.10', '10.1.2.3', '172.16.0.9',
                     '100.64.0.1', '::1', 'fe80::1', '[::1]'):
            self.assertTrue(util.is_local_host(host), host)
        for host in ('8.8.8.8', '1.1.1.1', '', None, '2001:4860:4860::8888'):
            self.assertFalse(util.is_local_host(host), host)

    def test_verify_off_only_for_local_on_a_local_address(self):
        local = {'server_type': 'local', 'url': 'https://8.8.8.8/x', 'local_url': 'https://192.168.1.10/x'}
        self.assertEqual(util.active_server_url(local), 'https://192.168.1.10/x')
        self.assertFalse(util.server_tls_verify(local))
        self.assertTrue(util.server_tls_verify(dict(local, local_url='https://8.8.8.8/x')))
        public = dict(local, server_type='public', url='https://192.168.1.10/x')
        self.assertEqual(util.active_server_url(public), 'https://192.168.1.10/x')
        self.assertTrue(util.server_tls_verify(public))
        self.assertTrue(util.server_tls_verify({'url': 'https://192.168.1.10/x'}))

    def test_heartbeat_passes_verify(self):
        _env.reset()
        paths.ensure_dirs()
        hb = heartbeat.Heartbeat(time.time())
        s = util.deep_merge(settings.load(), {'remote': {
            'enabled': True, 'url': 'https://mon.example.com/api/heartbeat.php', 'api_key': 'k',
            'local_url': 'https://192.168.1.10/api/heartbeat.php',
            'server_type': 'local', 'require_signed_response': False}})
        with mock.patch.object(hb.session, 'post', return_value=FakeReply(200)) as post:
            with self.assertLogs('heartbeat', 'INFO'):
                hb.send(s)
        self.assertEqual(post.call_args[0][0], 'https://192.168.1.10/api/heartbeat.php')
        self.assertIs(post.call_args[1]['verify'], False)
        s['remote']['local_url'] = 'https://8.8.8.8/api/heartbeat.php'
        with mock.patch.object(hb.session, 'post', return_value=FakeReply(200)) as post:
            with self.assertLogs('heartbeat', 'WARNING'):
                hb.send(s)
        self.assertIs(post.call_args[1]['verify'], True)
        s['remote']['server_type'] = 'public'
        with mock.patch.object(hb.session, 'post', return_value=FakeReply(200)) as post:
            hb.send(s)
        self.assertEqual(post.call_args[0][0], 'https://mon.example.com/api/heartbeat.php')
        self.assertIs(post.call_args[1]['verify'], True)
