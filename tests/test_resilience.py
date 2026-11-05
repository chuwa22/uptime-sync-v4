"""Fixes from the 4.0.9 audit: heartbeat replies, settings types, the
supervisor loop, the engine's cycle, the Logs page query, HTTP checks."""

from tests import _env  # noqa: F401  (must be first)

import logging
import os
import threading
import time
import unittest
from unittest import mock


from uptime_sync import (checks, engine, heartbeat, log as logsetup, loglevel, logstore, monitors, paths,
                         settings, supervisor, updater, util)
from tests.test_selfheal import FakeReply


def _hb_settings(**remote):
    base = {'enabled': True, 'url': 'https://mon.example.com/api/heartbeat.php', 'api_key': 'k',
            'secret_key': 'sec', 'require_signed_response': True}
    base.update(remote)
    return util.deep_merge(settings.load(), {'remote': base})


class HeartbeatReplyTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        self.hb = heartbeat.Heartbeat(time.time())

    def send(self, reply, s):
        with mock.patch.object(self.hb.session, 'post', return_value=reply) as post:
            out = self.hb.send(s)
        return out, post

    def test_untrusted_reply_cannot_slow_the_beat(self):
        body = b'{"success": true, "next_check_in": 3600, "deprecation_warning": "x"}'
        with self.assertLogs('heartbeat', 'WARNING') as cm:     # unsigned, signing required
            out, _ = self.send(FakeReply(200, body), _hb_settings())
        self.assertEqual(out, {})
        self.assertIsNone(self.hb.next_override)
        self.assertNotIn('Server says', '\n'.join(cm.output))

    def test_trusted_reply_is_used_and_its_text_cleaned(self):
        body = ('{"success": true, "next_check_in": 120, "deprecation_warning": "old\\nagent \\u00e9%s"}'
                % ('y' * 500)).encode('ascii')
        with self.assertLogs('heartbeat', 'WARNING') as cm:
            out, post = self.send(FakeReply(200, body), _hb_settings(require_signed_response=False))
        self.assertTrue(out['success'])
        self.assertEqual(self.hb.interval({}), 120)
        line = [l for l in cm.output if 'Server says' in l][0]
        self.assertNotIn('\n', line)
        self.assertTrue(all(ord(c) < 128 for c in line))
        self.assertTrue(line.endswith('...'))
        kw = post.call_args[1]
        self.assertIs(kw['stream'], True)
        self.assertEqual(kw['headers']['Accept-Encoding'], 'identity')

    def test_oversized_reply_is_a_failure_and_the_connection_is_closed(self):
        reply = FakeReply(200, b'{"success": true, "pad": "' + b'x' * (heartbeat.MAX_REPLY + 10) + b'"}')
        out, _ = self.send(reply, _hb_settings(require_signed_response=False))
        self.assertIsNone(out)
        self.assertEqual(self.hb.failures, 1)
        self.assertIn('too large', self.hb.last_error)
        self.assertTrue(reply.closed)


class LibraryLevelFloorTests(unittest.TestCase):
    """urllib3 at DEBUG logs every request URL: push tokens, signed URLs."""

    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        settings._warned.clear()

    def tearDown(self):
        loglevel.reset()
        for lib in loglevel.LIBRARIES:
            logging.getLogger(lib).setLevel(logging.NOTSET)

    def test_never_below_info(self):
        self.assertNotIn('DEBUG', loglevel.choices('libraries'))
        self.assertIn('DEBUG', loglevel.choices('checks'))
        util.atomic_write_json(paths.SETTINGS_FILE, {'log_levels': {'libraries': 'DEBUG'}})
        with self.assertLogs('settings', 'WARNING'):
            s = settings.load()
        self.assertEqual(s['log_levels'], {'libraries': 'INFO'})
        loglevel.apply({'log_level': 'DEBUG', 'log_levels': {'libraries': 'DEBUG'}})   # unchecked input
        self.assertEqual(logging.getLogger('urllib3').level, logging.INFO)
        self.assertEqual(loglevel.effective({'log_levels': {'libraries': 'DEBUG'}}, 'libraries'), 'INFO')


class SettingsTypeTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        settings._warned.clear()

    def test_wrong_section_types_fall_back_to_defaults(self):
        util.atomic_write_json(paths.SETTINGS_FILE, {
            'web': None, 'remote': 'x', 'update': {'enabled': 'yes'}, 'site_name': 5,
            'check_interval': '120', 'remote_x': 1})
        with self.assertLogs('settings', 'WARNING') as cm:
            s = settings.load()
        self.assertTrue(s['web']['enabled'])
        self.assertIsInstance(s['remote'], dict)
        self.assertIs(s['update']['enabled'], True)
        self.assertEqual(s['site_name'], '')
        self.assertEqual(s['check_interval'], 120)        # numbers are converted, not dropped
        self.assertEqual(len(cm.output), 5)    # 4 types + "120" converted by _coerce
        self.assertEqual(supervisor.Supervisor()._wanted(), ['engine', 'web'])

    def test_env_credentials_survive_a_broken_remote_section(self):
        util.atomic_write_json(paths.SETTINGS_FILE, {'remote': 'x'})
        with mock.patch.dict(os.environ, {'UPTIME_API_KEY': 'from-env'}):
            with self.assertLogs('settings', 'WARNING'):
                self.assertEqual(settings.load()['remote']['api_key'], 'from-env')

    def test_require_signed_response_keeps_its_mixed_type(self):
        util.atomic_write_json(paths.SETTINGS_FILE, {'remote': {'require_signed_response': True}})
        self.assertIs(settings.load()['remote']['require_signed_response'], True)


class FakeProc:
    def __init__(self, code=None):
        self.returncode = code
        self.pid = 4242

    def poll(self):
        return self.returncode


class SupervisorLoopTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        self.sup = supervisor.Supervisor()

    def test_stuck_engine_restarts_at_once_without_counting_a_crash(self):
        updater.set_state(status='Applied', version='9.9.9', crashes=0)
        child = supervisor.Child('engine', [])
        child.proc = FakeProc(updater.EXIT_STUCK)
        child.started = time.monotonic()
        self.sup.children['engine'] = child
        with self.assertLogs('supervisor', 'WARNING'):
            self.assertIsNone(self.sup._tick())
        self.assertEqual(child.failures, 0)
        self.assertLessEqual(child.next_start - time.monotonic(), 1.01)
        self.assertEqual(updater.state()['crashes'], 0)

    def test_a_failing_iteration_does_not_end_the_loop(self):
        calls = []

        def tick():
            calls.append(1)
            if len(calls) == 1:
                raise OSError('disk full')
            return 0
        with mock.patch.object(self.sup, '_tick', side_effect=tick), \
                mock.patch.object(self.sup, '_wanted', return_value=[]), \
                mock.patch.object(supervisor.time, 'sleep'):
            with self.assertLogs('supervisor', 'ERROR'):
                self.assertEqual(self.sup._loop(), 0)
        self.assertEqual(len(calls), 2)

    def test_popen_failure_is_retried_with_backoff(self):
        child = supervisor.Child('web', ['/nonexistent/python'])
        self.sup.children['web'] = child
        with mock.patch.object(supervisor.subprocess, 'Popen', side_effect=OSError('no memory')):
            with self.assertLogs('supervisor', 'ERROR'):
                self.sup._tick()
        self.assertIsNone(child.proc)
        self.assertEqual(child.failures, 1)
        self.assertGreater(child.next_start, time.monotonic())

    def test_new_version_whose_supervisor_keeps_dying_is_rolled_back(self):
        updater.set_state(status='Applied', version='9.9.9', supervisor_starts=0)
        with mock.patch.object(updater, 'rollback', return_value=True) as rb:
            for _ in range(supervisor.UPDATE_MAX_CRASHES):
                self.assertFalse(self.sup._count_start_after_update())
            with self.assertLogs('supervisor', 'ERROR'):
                self.assertTrue(self.sup._count_start_after_update())
        rb.assert_called_once()
        updater.set_state(status='Success')
        self.assertFalse(self.sup._count_start_after_update())


class EngineCycleTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        self.e = engine.Engine(supervised=True)
        self.e.monitors = [monitors.normalize({'name': n, 'type': 'PING', 'target': '192.0.2.1',
                                               'push_url': 'https://kuma.example/api/push/t'})
                           for n in ('a', 'b', 'c')]
        self.e.settings = util.deep_merge(settings.load(), {'check_interval': 10, 'max_workers': 1})

    def test_checks_never_started_are_cancelled(self):
        release = threading.Event()
        started = []

        def slow(m):
            started.append(m['name'])
            release.wait(5)
        with mock.patch.object(self.e, '_check_and_push', side_effect=slow), \
                mock.patch.object(self.e, '_cycle_budget', return_value=0.3), \
                mock.patch.object(self.e, '_warn_budget'):
            with self.assertLogs('engine', 'WARNING') as cm:
                self.e._run_cycle()
            self.assertEqual(started, ['a'])
            self.assertEqual(set(self.e._inflight), {self.e.monitors[0]['id']})
            self.assertIn('not started', '\n'.join(cm.output))
            release.set()
            for _ in range(50):
                if not self.e._inflight:
                    break
                time.sleep(0.05)
        self.assertEqual(started, ['a'])          # b and c never ran late
        self.assertFalse(self.e._inflight)

    def test_status_write_failure_still_shows_a_pulse(self):
        util.touch(paths.STATUS_FILE, '{}')
        old = time.time() - 1000
        os.utime(paths.STATUS_FILE, (old, old))
        with mock.patch.object(engine, 'atomic_write_json', side_effect=OSError(28, 'No space left')):
            with self.assertLogs('engine', 'WARNING'):
                self.e._write_status()
        self.assertGreater(os.path.getmtime(paths.STATUS_FILE), time.time() - 60)

    def test_server_log_level_written_once(self):
        with mock.patch.object(settings, 'update', wraps=settings.update) as upd, \
                mock.patch.object(loglevel, 'apply'):
            with self.assertLogs('engine', 'WARNING'):
                self.e._act_on({'settings': {'log_level': 'debug'}}, self.e.settings)
            self.e._act_on({'settings': {'log_level': 'debug'}}, self.e.settings)   # stale self.settings
        upd.assert_called_once_with({'log_level': 'DEBUG'})


class ThreadDeathTests(unittest.TestCase):
    def test_a_dying_thread_is_logged(self):
        root = logging.getLogger()
        saved, hook = list(root.handlers), threading.excepthook
        try:
            logsetup.setup('engine', 'INFO', console=False)
            with self.assertLogs('engine', 'CRITICAL') as cm:
                t = threading.Thread(target=lambda: 1 / 0, name='heartbeat')
                t.start()
                t.join()
            self.assertIn('Thread heartbeat died', cm.output[0])
        finally:
            threading.excepthook = hook
            for h in list(root.handlers):
                root.removeHandler(h)
                h.close()
            for h in saved:
                root.addHandler(h)
            loglevel.reset()


class LogQueryTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        logstore.init_db()
        conn = logstore.connect()
        levels = [10, 20, 30, 40, 50, 30, 20]
        with conn:
            conn.executemany('INSERT INTO logs (ts, proc, level, logger, msg) VALUES (?, ?, ?, ?, ?)',
                             [(i, 'web' if i % 2 else 'engine', levels[i % 7], 'x', 'line %d' % i)
                              for i in range(700)])
        conn.close()

    def naive(self, min_level, proc='', text='', before=None, limit=50):
        sql = 'SELECT id FROM logs WHERE level >= ?'
        args = [min_level]
        if proc:
            sql += ' AND proc = ?'
            args.append(proc)
        if text:
            sql += ' AND msg LIKE ?'
            args.append('%' + text + '%')
        if before:
            sql += ' AND id < ?'
            args.append(before)
        conn = logstore.connect()
        try:
            return [r[0] for r in conn.execute(sql + ' ORDER BY id DESC LIMIT ?', args + [limit])]
        finally:
            conn.close()

    def test_same_rows_as_the_plain_query(self):
        for min_level in (0, 20, 30, 40, 50):
            for proc in ('', 'web'):
                for text in ('', '9'):
                    for before in (None, 400):
                        got = [r['id'] for r in logstore.query(min_level, proc, text, before, 50)]
                        self.assertEqual(got, self.naive(min_level, proc, text, before),
                                         (min_level, proc, text, before))

    def test_warning_plan_does_not_sort_the_table(self):
        sql, args = logstore._select(30, '', '', None, 300)
        conn = logstore.connect()
        try:
            plan = [r[3] for r in conn.execute('EXPLAIN QUERY PLAN ' + sql, args)]
        finally:
            conn.close()
        # each branch walks logs_level_id with level = ?; only the merged
        # (at most limit x levels) rows are sorted
        self.assertEqual(sum('logs_level_id (level=? AND id<?)' in p or 'logs_level_id (level=?)' in p
                             for p in plan), 3)


class HttpDnsTests(unittest.TestCase):
    def setUp(self):
        self.c = checks.Checker()
        self.m = monitors.normalize({'name': 'site', 'type': 'HTTPS', 'target': 'no-such.example',
                                     'push_url': 'https://kuma.example/api/push/t'})

    def test_unresolvable_name_is_down_without_a_request(self):
        with mock.patch.object(self.c, 'check_dns', return_value=(False, 0)), \
                mock.patch.object(self.c, 'check_http') as http, \
                mock.patch.object(checks, '_uses_proxy', return_value=False):
            self.assertEqual(self.c.check(self.m), (False, 0, 0))
        http.assert_not_called()

    def test_behind_a_proxy_the_request_is_still_made(self):
        with mock.patch.object(self.c, 'check_dns', return_value=(False, 0)), \
                mock.patch.object(self.c, 'check_http', return_value=(True, 40)) as http, \
                mock.patch.dict(os.environ, {'HTTPS_PROXY': 'http://proxy.example:3128'}):
            self.assertEqual(self.c.check(self.m)[:2], (True, 40))
        http.assert_called_once()


def _wait_for(pred, seconds=5.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.05)
    return False


class LogDbReplacedTests(unittest.TestCase):
    """A quarantined logs.db must not keep receiving every process's lines."""

    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        logstore.init_db()
        self.h = logstore.SQLiteHandler('engine')
        self.lg = logging.getLogger('resilience.writer')
        self.lg.addHandler(self.h)
        self.lg.propagate = False
        self.lg.setLevel(logging.INFO)

    def tearDown(self):
        self.lg.removeHandler(self.h)
        self.h.close()

    def msgs(self):
        return [r['msg'] for r in logstore.query(limit=100)]

    def test_writer_follows_a_moved_database(self):
        self.lg.info('before')
        self.assertTrue(_wait_for(lambda: self.msgs() == ['before']))
        self.assertTrue(logstore.quarantine('test'))         # another process moves it away
        self.lg.info('after')
        self.assertTrue(_wait_for(lambda: self.msgs() == ['after']), self.msgs())

    def test_a_database_held_open_elsewhere_is_moved_once_writers_let_go(self):
        self.lg.info('first')
        self.assertTrue(_wait_for(lambda: self.msgs() == ['first']))
        real = os.replace
        held = {'n': 1}

        def windows_replace(src, dst):
            if src == logstore.DB_FILE and held['n']:
                held['n'] -= 1
                raise PermissionError(13, 'in use by another process')
            return real(src, dst)
        with mock.patch.object(logstore.os, 'replace', side_effect=windows_replace):
            self.assertFalse(logstore.quarantine('corrupt'))
            self.assertTrue(os.path.exists(logstore.RESET_FLAG))
            self.lg.info('second')                            # the writer lets go and moves it
            self.assertTrue(_wait_for(lambda: not os.path.exists(logstore.RESET_FLAG)))
        self.assertTrue(_wait_for(lambda: self.msgs() == ['second']), self.msgs())
        self.assertTrue([n for n in os.listdir(paths.LOG_DIR) if n.startswith('logs.db.corrupt-')])

    def test_stale_flag_never_moves_a_healthy_database(self):
        with open(logstore.RESET_FLAG, 'w') as f:
            f.write('1 2\nold\n')
        self.lg.info('kept')
        self.assertTrue(_wait_for(lambda: self.msgs() == ['kept']))
        self.assertFalse(os.path.exists(logstore.RESET_FLAG))
        self.assertFalse([n for n in os.listdir(paths.LOG_DIR) if n.startswith('logs.db.corrupt-')])


class ChunkedPruneTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        logstore.init_db()

    def test_retention_and_cap_delete_in_chunks(self):
        old, now = time.time() - 30 * 86400, time.time()
        conn = logstore.connect()
        with conn:
            conn.executemany('INSERT INTO logs (ts, proc, level, logger, msg) VALUES (?, ?, ?, ?, ?)',
                             [(old, 'engine', 20, 'x', 'old')] * 250 +
                             [(now, 'engine', 20, 'x', '%05d %s' % (i, 'y' * 1000)) for i in range(3000)])
        conn.close()
        statements = []
        real = logstore._delete_chunked

        def spy(conn, where, args, chunk=logstore.DELETE_CHUNK):
            statements.append(where)
            return real(conn, where, args, chunk=100)
        with mock.patch.object(logstore, '_delete_chunked', side_effect=spy):
            with self.assertLogs('log', 'WARNING'):
                removed = logstore.prune(14, max_bytes=1024 * 1024, target_bytes=512 * 1024)
        self.assertEqual(statements, ['ts < ?', 'id <= ?'])
        self.assertGreater(removed, 2250)
        left = logstore.query(limit=1000)
        self.assertNotIn('old', [r['msg'] for r in left])
        self.assertTrue(left[0]['msg'].startswith('02999'))   # newest kept


class LocalNetworkTests(unittest.TestCase):
    def test_explicit_ranges_only(self):
        for host in ('192.168.1.10', '10.1.2.3', '172.16.0.1', '127.0.0.1', '169.254.1.1',
                     '100.64.0.1', '::1', 'fd00::1', 'fe80::1', '::ffff:10.0.0.1', '[fd00::5]'):
            self.assertTrue(util.is_local_host(host), host)
        for host in ('8.8.8.8', '2001::1', '2001:0:4136:e378::1', '198.18.0.1', '240.0.0.1',
                     '0.0.0.1', '172.32.0.1', '2606:4700::1111', ''):
            self.assertFalse(util.is_local_host(host), host)


class NumericBoundsTests(unittest.TestCase):
    """One table (settings.NUMERIC) for load(), the Settings form and its HTML."""

    def setUp(self):
        from uptime_sync.web import auth, create_app
        from tests.test_web import WebTests
        _env.reset()
        paths.ensure_dirs()
        auth._attempts.clear()
        self.app = create_app()
        self.app.testing = True
        self.c = self.app.test_client()
        WebTests.setup_admin(self)
        self.WebTests = WebTests

    def post(self, **over):
        form = {'csrf': self.WebTests.csrf(self, '/settings'), 'check_interval': '60', 'max_workers': '10',
                'log_retention_days': '14', 'log_level': 'INFO', 'web_port': '5000',
                'heartbeat_interval': '60', 'require_signed': 'auto', 'server_type': 'public'}
        form.update(over)
        return self.c.post('/settings', data=form)

    def test_form_accepts_what_load_accepts(self):
        util.atomic_write_json(paths.SETTINGS_FILE, {'check_interval': 7200})
        html = self.c.get('/settings').get_data(as_text=True)
        lo, hi = settings.BOUNDS['check_interval']
        self.assertIn('name="check_interval" type="number" min="%d" max="%d" value="7200"' % (lo, hi), html)
        self.assertEqual(self.post(check_interval='7200').status_code, 302)
        self.assertEqual(settings.load()['check_interval'], 7200)

    def test_out_of_range_is_an_error_not_a_silent_clamp(self):
        r = self.post(check_interval='5', max_workers='999')
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        self.assertIn('Check every must be a whole number from 10 to 86400.', html)
        self.assertIn('Parallel checks must be a whole number from 1 to 64.', html)
        self.assertEqual(settings.load()['check_interval'], 60)

    def test_monitor_form_uses_the_same_limits(self):
        html = self.c.get('/monitors/new').get_data(as_text=True)
        self.assertIn('name="timeout" type="number" min="%d" max="%d"' % monitors.LIMITS['timeout'][:2], html)
        self.assertEqual(monitors.normalize({'timeout': 999})['timeout'], monitors.LIMITS['timeout'][1])


if __name__ == '__main__':
    unittest.main()
