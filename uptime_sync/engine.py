"""The monitoring engine: check every monitor, push the result, beat.

Runs as a child of the supervisor (`main.py engine --supervised`). It stops
when run/engine.stop appears, when its parent dies, or with an exit code
the supervisor acts on (updater.EXIT_UPDATE / EXIT_RESTART).
"""

import collections
import concurrent.futures
import logging
import os
import threading
import time

import requests

from . import __version__, heartbeat, log as logsetup, loglevel, monitors, paths, procs, settings, updater
from .checks import Checker
from .util import (USER_AGENT, atomic_write_json, is_newer, iso_now, read_json, redact,
                   remove_quietly, url_host)

log = logging.getLogger('engine')

HISTORY_LEN = 120
HISTORY_SAVE_EVERY = 10        # cycles; and always on stop
UPDATE_GRACE_SECONDS = 180
PUSH_WINDOW = 10
STUCK_CYCLES = 3               # a check running this many intervals -> restart the engine
HOUSEKEEPING_SECONDS = 3600
LOW_DISK_RETENTION_DAYS = 3


class Engine:
    def __init__(self, supervised=False, parent_pid=0):
        self.settings = settings.load()
        self.supervised = supervised
        self.parent_pid = parent_pid
        self.start_time = time.time()        # timestamp, reported to the server
        self._start_mono = time.monotonic()  # durations: immune to clock steps
        self.checker = Checker()
        self.session = requests.Session()
        self.session.headers['User-Agent'] = USER_AGENT
        # One pooled connection per worker thread: with the default pool of
        # 10, workers above 10 open and drop a TLS connection per push.
        pool = max(10, int(self.settings.get('max_workers', 10)))
        adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=pool)
        self.session.mount('https://', adapter)
        self.session.mount('http://', adapter)
        self.heartbeat = heartbeat.Heartbeat(self.start_time)
        self.stop_event = threading.Event()
        self.exit_code = 0
        self.monitors = []
        self._monitor_stamp = None
        self.results = {}
        h = read_json(paths.HISTORY_FILE, {})
        self.history = h if isinstance(h, dict) else {}
        self._push_codes = {}
        self._push_alerted = set()
        self._updating = threading.Lock()
        self._housekept = None          # monotonic time of the last log prune
        self._last_cycle_ok = True
        self._skip_logged = None
        self._lock = threading.Lock()   # results + history: written by check threads
        self._inflight = {}             # monitor id -> monotonic start of its running check
        self._cycles = 0
        self._last_state = {}           # monitor id -> (ok, push code), to log only changes
        self._errors_logged = set()
        self._status_warned = False
        self._budget_warned = None

    # -- lifecycle -----------------------------------------------------------

    def run(self):
        logsetup.setup('engine', self.settings)
        procs.write_pid(paths.child_pid_file('engine'))
        remove_quietly(paths.child_stop_flag('engine'))
        log.info('Uptime Sync %s engine starting (pid %d)', __version__, os.getpid())
        self._reload_monitors(force=True)
        self._warn_insecure_push_urls()
        threading.Thread(target=self._heartbeat_loop, name='heartbeat', daemon=True).start()
        threading.Thread(target=self._watch, name='watch', daemon=True).start()
        try:
            while not self.stop_event.is_set():
                started = time.monotonic()
                self.settings = settings.load()
                loglevel.apply(self.settings)
                self._reload_monitors()
                self._run_cycle()
                self._housekeeping()
                interval = self.settings['check_interval']
                # monotonic: a clock stepped back by w32time must not stretch the sleep
                self.stop_event.wait(min(interval, max(1.0, interval - (time.monotonic() - started))))
        finally:
            self._save_history()
            remove_quietly(paths.child_pid_file('engine'))
            log.info('Engine stopped (exit code %d)', self.exit_code)
        return self.exit_code

    def checks_running(self):
        with self._lock:
            return bool(self._inflight)

    def stop(self, code=0):
        if code and not self.exit_code:
            self.exit_code = code
        self.stop_event.set()

    def _watch(self):
        """Stop on run/engine.stop, on an install click, or when orphaned."""
        while not self.stop_event.wait(1.0):
            loglevel.refresh()
            if os.path.exists(paths.child_stop_flag('engine')):
                log.info('Stop requested')
                self.stop()
            elif self.parent_pid and not procs.pid_alive(self.parent_pid):
                log.warning('Supervisor (pid %d) is gone - stopping', self.parent_pid)
                self.stop()
            elif os.path.exists(paths.INSTALL_TRIGGER):
                remove_quietly(paths.INSTALL_TRIGGER)
                p = updater.pending()
                if p:
                    log.info('[UPDATE] Install of v%s requested from the web UI', p['version'])
                    threading.Thread(target=self._install, args=(p['url'], p['version'], p['sha256']),
                                     daemon=True).start()

    # -- monitors ------------------------------------------------------------

    def _stamp(self):
        out = []
        for p in (paths.MONITORS_FILE, paths.ENV_FILE):
            try:
                out.append(os.path.getmtime(p))
            except OSError:
                out.append(None)
        return tuple(out)

    def _reload_monitors(self, force=False):
        stamp = self._stamp()
        if not force and stamp == self._monitor_stamp:
            return
        self._monitor_stamp = stamp
        env = settings.env_values()
        all_monitors = monitors.load()
        self.monitors = [monitors.runtime_view(m, env) for m in all_monitors if m['enabled']]
        known = {m['id'] for m in all_monitors}
        urls = {m['push_url'] for m in self.monitors}
        with self._lock:
            self.results = {k: v for k, v in self.results.items() if k in known}
            self.history = {k: v for k, v in self.history.items() if k in known}
        # Push telemetry of deleted monitors / replaced URLs would otherwise
        # stay in memory for the life of the process.
        self._push_codes = {u: w for u, w in self._push_codes.items() if u in urls}
        self._push_alerted &= urls
        self._last_state = {k: v for k, v in self._last_state.items() if k in known}
        self._budget_warned = None
        log.info('Loaded %d monitor(s), %d enabled', len(all_monitors), len(self.monitors))

    def _warn_insecure_push_urls(self):
        for m in self.monitors:
            if m['push_url'].lower().startswith('http://'):
                log.warning('[SECURITY] %s pushes over plain http - its token travels in clear '
                            'text; switch the push URL to https', m['name'])

    # -- check cycle ---------------------------------------------------------

    def _run_cycle(self):
        if not self.monitors:
            self._write_status()
            return
        interval = self.settings['check_interval']
        workers = max(1, min(self.settings['max_workers'], len(self.monitors)))
        budget = max(10, interval * 0.9)
        self._warn_budget(workers, budget)
        # A check that overran the last budget is still running in its old
        # pool thread: do not start a second copy of it alongside.
        now = time.monotonic()
        with self._lock:
            todo = [m for m in self.monitors if m['id'] not in self._inflight]
            busy = [m for m in self.monitors if m['id'] in self._inflight]
            stuck = [m for m in busy if now - self._inflight[m['id']] > STUCK_CYCLES * interval]
            for m in todo:
                self._inflight[m['id']] = now
        if busy:
            log.warning('%d check(s) from the last cycle still running - not started again, '
                        'reported down', len(busy))
            for m in busy:
                self._report_stuck(m)
        if stuck:
            # A thread stuck in a call that never returns cannot be killed
            # from inside Python; a fresh process is the only cure.
            log.error('Check of %s has been running for over %d intervals - restarting the engine',
                      stuck[0]['name'], STUCK_CYCLES)
            self.stop(updater.EXIT_STUCK)
            return
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
        futures = {pool.submit(self._check_one, m): m for m in todo}
        deadline = time.monotonic() + budget
        not_done = set(futures)
        while not_done and not self.stop_event.is_set():
            left = deadline - time.monotonic()
            if left <= 0:
                break
            # short waits so a stop request is seen within a second
            done_now, not_done = concurrent.futures.wait(not_done, timeout=min(1.0, left))
        done = set(futures) - set(not_done)
        if self.stop_event.is_set():
            not_done = set()   # stopping: nothing to warn about
        for f in done:
            if f.exception():
                log.error('Check of %s crashed: %s', futures[f]['name'], f.exception())
        for f in not_done:
            log.warning('Check of %s did not finish within %ds', futures[f]['name'], budget)
        pool.shutdown(wait=False)
        self._last_cycle_ok = not not_done and not busy
        self._cycles += 1
        if self._cycles % HISTORY_SAVE_EVERY == 0:
            self._save_history()
        self._write_status()

    def _warn_budget(self, workers, budget):
        """Once per configuration: warn when the worst case of the checks
        (every attempt timing out) cannot fit in the cycle."""
        key = (workers, budget, len(self.monitors))
        if self._budget_warned == key:
            return
        self._budget_warned = key
        delay = self.settings['retry_delay']
        worst = []
        for m in self.monitors:
            per_try = m['timeout'] * (3 if m['type'] in ('HTTP', 'HTTPS') else 1) + 2
            worst.append(m['retry_count'] * per_try + (m['retry_count'] - 1) * delay)
        worst.sort(reverse=True)
        # slowest first, spread over the workers: a rough upper bound
        rounds = [sum(worst[i::workers]) for i in range(workers)]
        if rounds and max(rounds) > budget:
            log.warning('With these timeouts and retries, %d monitor(s) on %d worker(s) may need '
                        'up to %ds when targets do not answer - more than the %ds a cycle allows. '
                        'Raise check_interval or max_workers, or lower timeout / retry_count.',
                        len(self.monitors), workers, max(rounds), budget)

    def _report_stuck(self, m):
        """A check still running from an earlier cycle counts as down, so the
        dashboard and Uptime Kuma do not keep showing its last 'up'."""
        with self._lock:
            self.results[m['id']] = {'name': m['name'], 'type': m['type'], 'target': m['target'],
                                     'ok': False, 'ms': 0, 'checked_at': iso_now(), 'stuck': True}
            h = self.history.setdefault(m['id'], [])
            h.append([int(time.time()), 0, 0])
            del h[:-HISTORY_LEN]
        threading.Thread(target=self._push, args=(m, False, 0, 0), daemon=True).start()

    def _check_one(self, m):
        try:
            self._check_and_push(m)
        finally:
            with self._lock:
                self._inflight.pop(m['id'], None)

    def _check_and_push(self, m):
        retry_delay = self.settings['retry_delay']
        ok, ms, dns_ms = False, 0, 0
        for attempt in range(m['retry_count']):
            if self.stop_event.is_set():
                return
            try:
                ok, ms, dns_ms = self.checker.check(m)
            except Exception as e:
                # A bug, not a down target: ERROR with the traceback once per
                # monitor and exception type, then quietly.
                key = (m['id'], type(e).__name__)
                first = key not in self._errors_logged
                self._errors_logged.add(key)
                log.log(logging.ERROR if first else logging.DEBUG, 'Check of %s raised %s: %s',
                        m['name'], type(e).__name__, e, exc_info=first)
                ok = False
            if ok:
                break
            if attempt < m['retry_count'] - 1 and self.stop_event.wait(retry_delay):
                return
        with self._lock:
            self.results[m['id']] = {'name': m['name'], 'type': m['type'], 'target': m['target'],
                                     'ok': ok, 'ms': ms, 'checked_at': iso_now()}
            h = self.history.setdefault(m['id'], [])
            h.append([int(time.time()), 1 if ok else 0, ms])
            del h[:-HISTORY_LEN]
        self._push(m, ok, ms, dns_ms)

    def _push(self, m, ok, ms, dns_ms):
        if not m['push_url']:
            return
        params = {'status': 'up' if ok else 'down',
                  'msg': '%s: %s' % (m['name'], 'All systems UP' if ok else 'Service is DOWN'),
                  'ping': ms, 'dns_ping': dns_ms}
        try:
            r = self.session.get(monitors.push_base_url(m['push_url']), params=params, timeout=10)
            code = r.status_code
            r.close()
        except requests.RequestException as e:
            code = 0
            # Host only: the exception text carries the whole URL, and the
            # path / query of a push URL is its token.
            log.error('Push for %s to %s failed: %s', m['name'], url_host(m['push_url']),
                      type(e).__name__)
        # INFO only when something changed: a steady 'UP, 200' for every
        # monitor every minute is most of the log and none of the news.
        state = (ok, code == 200)
        changed = self._last_state.get(m['id']) != state
        self._last_state[m['id']] = state
        if code != 200:
            level = logging.WARNING
        else:
            level = logging.INFO if changed else logging.DEBUG
        log.log(level, '%s %s %sms -> push HTTP %s', '[UP]' if ok else '[DOWN]', m['name'], ms, code)
        self._track_push(m, code)

    def _track_push(self, m, code):
        """Warn once when >= 80% of the last 10 pushes got 404 (the monitor
        was deleted or its token changed in Uptime Kuma); re-arm on a 200."""
        url = m['push_url']
        window = self._push_codes.setdefault(url, collections.deque(maxlen=PUSH_WINDOW))
        window.append(code)
        if code == 200 and url in self._push_alerted:
            self._push_alerted.discard(url)
            log.info('[PUSH] %s: push URL works again', m['name'])
        if code == 404 and len(window) == PUSH_WINDOW and url not in self._push_alerted and \
                sum(1 for c in window if c == 404) >= 0.8 * PUSH_WINDOW:
            self._push_alerted.add(url)
            log.warning('[PUSH] %s: most recent pushes to %s returned 404 - the push monitor '
                        'may have been deleted in Uptime Kuma', m['name'], url_host(url))

    def _save_history(self):
        with self._lock:   # a snapshot: check threads keep appending meanwhile
            snap = {k: list(v) for k, v in self.history.items()}
        try:
            atomic_write_json(paths.HISTORY_FILE, snap, compact=True)
        except OSError as e:
            log.warning('Could not save history: %s', e)

    def _write_status(self):
        hb = self.heartbeat
        with self._lock:
            results = dict(self.results)
        try:
            atomic_write_json(paths.STATUS_FILE, {
                'updated_at': iso_now(), 'version': __version__, 'pid': os.getpid(),
                'started_at': int(self.start_time), 'monitors': results,
                'heartbeat': {'last_ok': hb.last_ok, 'failures': hb.failures, 'error': hb.last_error},
            })
            self._status_warned = False
        except OSError as e:
            # The supervisor reads this file's age as the engine's pulse.
            if not self._status_warned:
                self._status_warned = True
                log.warning('Could not write run/status.json: %s', e)

    def _housekeeping(self):
        """Hourly: log retention + the logs.db size cap. Never raises -- an
        error here (a corrupt database, a full disk) must not crash-loop the
        engine, which would then report nothing at all."""
        now = time.monotonic()
        if self._housekept is not None and now - self._housekept < HOUSEKEEPING_SECONDS:
            return
        self._housekept = now
        days = self.settings['log_retention_days']
        if not heartbeat.free_disk_ok() and days > LOW_DISK_RETENTION_DAYS:
            log.warning('Low disk space - keeping only %d days of logs', LOW_DISK_RETENTION_DAYS)
            days = LOW_DISK_RETENTION_DAYS
        try:
            n = logsetup.prune(days)
        except Exception as e:
            log.error('Log cleanup failed: %s', e)
            return
        if n:
            log.debug('Removed %d old log line(s)', n)

    # -- heartbeat + server-driven actions ----------------------------------

    def _heartbeat_loop(self):
        self.stop_event.wait(3)
        while not self.stop_event.is_set():
            s = self.settings
            if s.get('remote', {}).get('enabled'):
                try:
                    reply = self.heartbeat.send(s, healthy=self._last_cycle_ok and heartbeat.free_disk_ok())
                    if reply:
                        self._act_on(reply, s)
                    wait = self.heartbeat.interval(s)
                except Exception as e:
                    log.error('Heartbeat handling failed: %s', e, exc_info=True)
                    wait = 60
            else:
                wait = 30
            self.stop_event.wait(wait)

    def _act_on(self, reply, s):
        # The server sets the global level only; per-part log_levels stay.
        level = loglevel.normalize((reply.get('settings') or {}).get('log_level'))
        if level and level != loglevel.normalize(s.get('log_level')):
            log.warning('Log level set by server: %s -> %s', s.get('log_level'), level)
            settings.update({'log_level': level})
            loglevel.apply(dict(s, log_level=level))
        if reply.get('restart_requested'):
            log.warning('[RESTART] Requested by the server')
            self.stop(updater.EXIT_RESTART)
            return
        if reply.get('update_available'):
            self._consider_update(reply, s)

    def _consider_update(self, reply, s):
        version = str(reply.get('latest_version') or '')
        if not is_newer(version, __version__):
            return
        if not s.get('update', {}).get('enabled', True):
            log.info('[UPDATE] v%s offered, but updates are disabled on this box', version)
            return
        url, sha = reply.get('update_url', ''), reply.get('update_sha256', '')
        force = bool(reply.get('force_install'))
        mode = str(reply.get('update_mode') or 'auto').lower()
        window = reply.get('update_window') or {}
        last = updater.state()
        if force:
            log.warning('[UPDATE] Admin forced install of v%s', version)
        elif last.get('status') == 'Failed' and last.get('version') == version:
            # Already tried here and refused or rolled back: wait for a newer
            # release or an explicit Force Update, instead of looping.
            if self._skip_logged != version:
                self._skip_logged = version
                log.warning('[UPDATE] v%s failed on this box before (%s) - not retrying it '
                            'unless Force Update is used', version, last.get('detail') or '?')
            return
        elif time.monotonic() - self._start_mono < UPDATE_GRACE_SECONDS:
            log.info('[UPDATE] v%s offered; waiting for the post-start grace period', version)
            return
        elif mode == 'manual':
            if not updater.pending():
                log.info('[UPDATE] v%s available - waiting for Install in the web UI', version)
            updater.write_pending(version, url, sha, mode)
            return
        elif mode == 'scheduled' and not updater.in_window(window.get('start'), window.get('end')):
            updater.write_pending(version, url, sha, mode)
            log.info('[UPDATE] v%s available - deferred to the %s-%s window', version,
                     window.get('start', '?'), window.get('end', '?'))
            return
        self._install(url, version, sha)

    def _install(self, url, version, sha):
        if not self.supervised:
            log.warning('[UPDATE] v%s offered, but this engine is not running under the '
                        'supervisor (main.py run) - not installing', version)
            return
        if not self._updating.acquire(blocking=False):
            return
        staged = False
        try:
            updater.download_and_stage(url, version, sha, settings.load())
            staged = True
        except updater.UpdateRefused as e:
            log.error('[UPDATE] [SECURITY] Refusing v%s: %s', version, e)
            try:
                updater.set_state(status='Failed', version=version, time=iso_now(), detail=str(e))
            except OSError as e2:
                log.error('[UPDATE] Could not record the refusal: %s', e2)
            return
        except Exception as e:
            log.error('[UPDATE] v%s failed: %s', version, redact(e))
            return
        finally:
            if not staged:
                self._updating.release()
        log.warning('[UPDATE] v%s verified and staged - handing over to the supervisor', version)
        self.stop(updater.EXIT_UPDATE)


def main(supervised=False, parent_pid=0):
    paths.ensure_dirs()
    engine = Engine(supervised, parent_pid)
    code = engine.run()
    if engine.checks_running():
        # Python joins pool threads at exit: one hung in a call that never
        # returns would keep this process alive for ever.
        logging.shutdown()
        os._exit(code)
    return code
