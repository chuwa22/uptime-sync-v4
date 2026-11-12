"""The monitoring engine: check every monitor, push the result, beat.

Runs as a child of the supervisor (`main.py engine --supervised`). It stops
when run/engine.stop appears, when its parent dies, or with an exit code
the supervisor acts on (updater.EXIT_UPDATE / EXIT_RESTART).
"""

import collections
import concurrent.futures
import json
import logging
import os
import threading
import time

import requests

from . import __version__, heartbeat, log as logsetup, loglevel, monitors, paths, procs, settings, updater
from .checks import Checker
from .util import (atomic_write_json, get_following, http_session, is_newer, iso_now, read_json, recent_checks,
                   redact, remove_quietly, slept_during, uptime_pct, url_host)

log = logging.getLogger('engine')

HISTORY_LEN = 120
HISTORY_SAVE_EVERY = 10        # cycles; and always on stop
UPDATE_GRACE_SECONDS = 180
PUSH_WINDOW = 10
STUCK_CYCLES = 3               # a check running this many intervals -> restart the engine
PUSH_REMINDER_SECONDS = 3600   # a push that keeps failing is logged again this often
HEARTBEAT_STUCK_SECONDS = 600  # one beat in flight this long -> restart the engine
WATCH_SECONDS = 1.0            # _watch wakes this often
HOUSEKEEPING_SECONDS = 3600
# A saved monitor (web UI or a hand edit of monitors.json / data/.env) is
# checked within about a second instead of at the next check_interval; a
# burst of saves still runs at most one extra cycle per this many seconds.
MONITOR_CHANGE_MIN_GAP = 5
HB_SETTINGS_POLL = 5        # s between looks at Settings while the heartbeat waits
LOW_DISK_RETENTION_DAYS = 3


class Engine:
    def __init__(self, supervised=False, parent_pid=0):
        self.settings = settings.load()
        self.supervised = supervised
        self.parent_pid = parent_pid
        self.start_time = time.time()        # timestamp, reported to the server
        self._start_mono = time.monotonic()  # durations: immune to clock steps
        self.checker = Checker()
        self.session = http_session()
        # One pooled connection per worker thread: with the default pool of
        # 10, workers above 10 open and drop a TLS connection per push.
        pool = max(10, int(self.settings.get('max_workers', 10)))
        adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=pool)
        self.session.mount('https://', adapter)
        self.session.mount('http://', adapter)
        self.heartbeat = heartbeat.Heartbeat(self.start_time)
        self.stop_event = threading.Event()
        self._wake = threading.Event()       # stop, or monitors changed: end the wait early
        self.exit_code = 0
        self.monitors = []
        self._monitor_stamp = None
        self._woken_for = None               # the stamp _watch last woke the loop for
        self._settings_mtime = False         # settings.json mtime as _watch last saw it (False: not yet)
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
        self._hb_busy_since = None      # monotonic start of the beat in flight
        self._resumed_at = None         # monotonic time _watch saw the computer wake (4.3.1)
        self._monitor_read_error = None
        self._cycles = 0
        self._last_state = {}           # monitor id -> (ok, push code, error), to log only changes
        self._push_failing = {}         # monitor id -> [failed pushes in a row, last reminder]
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
                self._wake.wait(min(interval, max(1.0, interval - (time.monotonic() - started))))
                self._wake.clear()
                gap = MONITOR_CHANGE_MIN_GAP - (time.monotonic() - started)
                if gap > 0 and not self.stop_event.is_set():
                    self.stop_event.wait(gap)
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
        self._wake.set()

    def _since_wake(self, started):
        """A monotonic start time, moved up to the last wake from sleep."""
        woke = self._resumed_at
        if started is None or woke is None:
            return started
        return max(started, woke)

    def _watch(self):
        """Stop on run/engine.stop, on an install click, or when orphaned."""
        while True:
            before = time.monotonic()
            if self.stop_event.wait(WATCH_SECONDS):
                break
            slept = slept_during(before, WATCH_SECONDS)
            if slept:
                # Windows' monotonic() counted the sleep: a beat or a check
                # in flight when the lid shut is not stuck. Their age now
                # counts from the wake (only this thread writes it).
                self._resumed_at = time.monotonic()
                log.debug('The computer was asleep for about %ds', slept)
            loglevel.refresh()
            self._wake_on_monitor_change()
            self._wake_on_interval_change()
            busy = self._since_wake(self._hb_busy_since)
            if busy is not None and time.monotonic() - busy > HEARTBEAT_STUCK_SECONDS:
                # requests' timeout is per read: a server that trickles its
                # reply, or a hung TLS handshake, can hold the beat for ever,
                # and with it every restart / update the server would send.
                log.error('A heartbeat has been in flight for over %ds - restarting the engine',
                          HEARTBEAT_STUCK_SECONDS)
                self._hb_busy_since = None
                self.stop(updater.EXIT_STUCK)
            elif os.path.exists(paths.child_stop_flag('engine')):
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
                    self._start_install(p['url'], p['version'], p['sha256'])

    # -- monitors ------------------------------------------------------------

    def _stamp(self):
        out = []
        for p in (paths.MONITORS_FILE, paths.ENV_FILE):
            try:
                out.append(os.path.getmtime(p))
            except OSError:
                out.append(None)
        return tuple(out)

    def _wake_on_interval_change(self):
        """A saved check_interval takes effect now, not after a sleep of the
        old one (up to an hour): end the wait when settings.json changed and
        its interval differs from the one in use (4.0.11)."""
        try:
            mtime = os.path.getmtime(paths.SETTINGS_FILE)
        except OSError:
            mtime = None
        if self._settings_mtime is False or mtime == self._settings_mtime:
            self._settings_mtime = mtime       # the first look only records it
            return
        try:
            # strict: a held file must not read as the default interval
            interval = settings.load(strict=True)['check_interval']
        except OSError:
            return                             # stamp not kept: look again in a second
        self._settings_mtime = mtime
        if interval != self.settings.get('check_interval'):
            log.info('check_interval changed to %ds - starting a cycle now', interval)
            self._wake.set()

    def _wake_on_monitor_change(self):
        """monitors.json or data/.env changed since the last load: end the
        main loop's wait so the change is checked now. Once per change -- a
        file that cannot be read keeps its old stamp, and must not start a
        cycle every second."""
        stamp = self._stamp()
        if self._monitor_stamp is None or stamp == self._monitor_stamp or stamp == self._woken_for:
            return
        self._woken_for = stamp
        log.debug('Monitors changed - checking now instead of at the next interval')
        self._wake.set()

    def _reload_monitors(self, force=False):
        stamp = self._stamp()
        if not force and stamp == self._monitor_stamp:
            return
        try:
            all_monitors = monitors.load(strict=True)
        except OSError as e:
            # Held by an antivirus or backup tool right now: keep checking
            # what we have, and try again next cycle (the stamp is not
            # stored, so the change is not lost).
            if self._monitor_read_error != str(e):
                self._monitor_read_error = str(e)
                log.warning('Could not read monitors.json (%s) - keeping the %d monitor(s) loaded '
                            'before, retrying next cycle', e, len(self.monitors))
            return
        self._monitor_read_error = None
        self._monitor_stamp = stamp
        env = settings.env_values()
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
        self._push_failing = {k: v for k, v in self._push_failing.items() if k in known}
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
        budget = self._cycle_budget(interval)
        self._warn_budget(workers, budget)
        # A check that overran the last budget is still running in its old
        # pool thread: do not start a second copy of it alongside.
        now = time.monotonic()
        with self._lock:
            todo = [m for m in self.monitors if m['id'] not in self._inflight]
            busy = [m for m in self.monitors if m['id'] in self._inflight]
            stuck = [m for m in busy
                     if now - self._since_wake(self._inflight[m['id']]) > STUCK_CYCLES * interval]
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
        skipped = []
        for f in not_done:
            m = futures[f]
            # Never started (all workers busy): cancel it. Left queued, the
            # old pool started it late, next to the next cycle's pool -- more
            # threads than max_workers, and a false DOWN then UP in Kuma.
            if f.cancel():
                with self._lock:
                    self._inflight.pop(m['id'], None)
                skipped.append(m['name'])
            else:
                log.warning('Check of %s did not finish within %ds', m['name'], budget)
        if skipped:
            log.warning('%d check(s) not started within %ds (all %d workers busy) - skipped this '
                        'cycle: %s', len(skipped), budget, workers, ', '.join(skipped[:10]))
        pool.shutdown(wait=False)
        self._last_cycle_ok = not not_done and not busy   # a skipped check is not ok either
        self._cycles += 1
        if self._cycles % HISTORY_SAVE_EVERY == 0:
            self._save_history()
        self._write_status()

    @staticmethod
    def _cycle_budget(interval):
        """Seconds the checks of one cycle may take."""
        return max(10, interval * 0.9)

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
        error = ''
        try:
            # Only the status matters: no body is read, on a redirect either
            # (util.http_session / get_following).
            r = get_following(self.session, monitors.push_base_url(m['push_url']), params=params,
                              timeout=10)
            code = r.status_code
            r.close()
        except requests.RequestException as e:
            code = 0
            error = type(e).__name__
        self._log_push(m, ok, ms, code, error)
        self._track_push(m, code)

    def _log_push(self, m, ok, ms, code, error):
        """One line per push, and only news at INFO / WARNING: a steady
        'UP, 200' is most of the log and none of the news, and so is the same
        failure every cycle (5 monitors whose Kuma is down wrote ~29,000
        lines a day). A failure that goes on is repeated once an hour."""
        mark = '[UP]' if ok else '[DOWN]'
        state = (ok, code, error)
        changed = self._last_state.get(m['id']) != state
        self._last_state[m['id']] = state
        failing = self._push_failing.get(m['id'])
        if code == 200:
            if failing:
                del self._push_failing[m['id']]
                log.info('%s %s %sms -> push HTTP 200 (works again after %d failed push(es))',
                         mark, m['name'], ms, failing[0])
            else:
                log.log(logging.INFO if changed else logging.DEBUG, '%s %s %sms -> push HTTP 200',
                        mark, m['name'], ms)
            return
        # Host only: the exception text carries the whole URL, and the path /
        # query of a push URL is its token.
        what = ('push to %s failed: %s' % (url_host(m['push_url']), error) if error else
                'push HTTP %s from %s' % (code, url_host(m['push_url'])))
        now = time.monotonic()
        if failing is None:
            failing = self._push_failing[m['id']] = [0, now]
        failing[0] += 1
        if changed:
            failing[1] = now
            log.warning('%s %s %sms -> %s', mark, m['name'], ms, what)
        elif now - failing[1] >= PUSH_REMINDER_SECONDS:
            failing[1] = now
            log.warning('%s %s %sms -> %s (still failing: %d in a row)', mark, m['name'], ms, what,
                        failing[0])
        else:
            log.debug('%s %s %sms -> %s', mark, m['name'], ms, what)

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
            # recent checks + uptime from the in-memory history: history.json
            # is written only every HISTORY_SAVE_EVERY cycles, so the dashboard
            # lagged by up to ten minutes when it read the file.
            results = {}
            for k, v in self.results.items():
                recent = recent_checks(self.history.get(k))
                results[k] = dict(v, recent=recent, uptime=uptime_pct(recent))
        try:
            atomic_write_json(paths.STATUS_FILE, {
                'updated_at': iso_now(), 'version': __version__, 'pid': os.getpid(),
                'started_at': int(self.start_time), 'monitors': results,
                # The interval this engine is cycling on: the supervisor's
                # stall check must not use a lower one saved since (4.0.11).
                'check_interval': self.settings.get('check_interval'),
                'heartbeat': {'last_ok': hb.last_ok, 'failures': hb.failures, 'error': hb.last_error,
                              'last_try': hb.last_try},
            })
            self._status_warned = False
        except OSError as e:
            # The supervisor reads this file's age as the engine's pulse:
            # on a full disk the write fails while the engine is healthy,
            # and touching the mtime needs no free blocks.
            try:
                os.utime(paths.STATUS_FILE, None)
            except OSError:
                pass
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
            s = settings.load()
            sent_with = _remote_key(s)
            try:
                enabled = bool(s.get('remote', {}).get('enabled'))
            except Exception:   # settings.load() fixes types; never let this thread die
                enabled = False
            if enabled:
                self._hb_busy_since = time.monotonic()
                try:
                    reply = self.heartbeat.send(s, healthy=self._last_cycle_ok and heartbeat.free_disk_ok())
                    if reply:
                        self._act_on(reply, s)
                    wait = self.heartbeat.interval(s)
                except Exception as e:
                    log.error('Heartbeat handling failed: %s', e, exc_info=True)
                    wait = 60
                finally:
                    self._hb_busy_since = None
            else:
                wait = 30
            self._wait_for_beat(wait, sent_with)

    def _wait_for_beat(self, wait, sent_with):
        """Sleep until the next beat, but beat at once when Reporting is
        changed in Settings: a fixed API key or URL is confirmed (or not) in
        seconds, instead of after the interval or a 10 min backoff."""
        deadline = time.monotonic() + wait
        while not self.stop_event.is_set():
            left = deadline - time.monotonic()
            if left <= 0:
                return
            self.stop_event.wait(min(HB_SETTINGS_POLL, left))
            try:
                changed = _remote_key(settings.load()) != sent_with
            except Exception:
                changed = False
            if changed:
                log.info('Reporting settings changed - sending a heartbeat now')
                self.heartbeat.failures = 0
                self.heartbeat.next_override = None
                return

    def _act_on(self, reply, s):
        # The server sets the global level only; per-part log_levels stay.
        # Compared with the file, not self.settings (reloaded once per check
        # cycle): otherwise every beat in between would write it again.
        level = loglevel.normalize((reply.get('settings') or {}).get('log_level'))
        current = settings.load()
        if level and level != current.get('log_level'):
            try:
                settings.update({'log_level': level})
            except OSError as e:
                # Unreadable for now: try again on the next beat, rather
                # than save the level over the defaults (4.0.11).
                log.debug('Log level from server not saved yet: %s', e)
            else:
                log.warning('Log level set by server: %s -> %s', current.get('log_level'), level)
                loglevel.apply(dict(current, log_level=level))
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
            # INFO once per offer, DEBUG on the repeats (log volume rule).
            new = updater.write_pending(version, url, sha, mode)
            (log.info if new else log.debug)(
                '[UPDATE] v%s available - waiting for Install in the web UI', version)
            return
        elif mode == 'scheduled' and not updater.in_window(window.get('start'), window.get('end')):
            new = updater.write_pending(version, url, sha, mode)
            (log.info if new else log.debug)(
                '[UPDATE] v%s available - deferred to the %s-%s window', version,
                window.get('start', '?'), window.get('end', '?'))
            return
        self._start_install(url, version, sha)

    def _start_install(self, url, version, sha):
        """The download runs in its own thread: in the heartbeat thread a
        slow 30 MB download held up every beat (and the stuck-beat check
        would restart the engine in the middle of it)."""
        t = threading.Thread(target=self._install, args=(url, version, sha), name='update', daemon=True)
        t.start()
        return t

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


def _remote_key(s):
    """What the heartbeat was sent with: a change means beat again now."""
    try:
        return json.dumps(s.get('remote', {}), sort_keys=True, default=str)
    except Exception:
        return ''


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
