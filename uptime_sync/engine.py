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

from . import __version__, heartbeat, log as logsetup, monitors, paths, procs, settings, updater
from .checks import Checker
from .util import atomic_write_json, is_newer, iso_now, read_json, redact, remove_quietly

log = logging.getLogger('engine')

HISTORY_LEN = 120
UPDATE_GRACE_SECONDS = 180
PUSH_WINDOW = 10


class Engine:
    def __init__(self, supervised=False, parent_pid=0):
        self.supervised = supervised
        self.parent_pid = parent_pid
        self.start_time = time.time()
        self.checker = Checker()
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'UptimeSync/%s' % __version__
        self.heartbeat = heartbeat.Heartbeat(self.start_time)
        self.stop_event = threading.Event()
        self.exit_code = 0
        self.settings = settings.load()
        self.monitors = []
        self._monitor_stamp = None
        self.results = {}
        self.history = read_json(paths.HISTORY_FILE, {}) or {}
        self._push_codes = {}
        self._push_alerted = set()
        self._updating = threading.Lock()
        self._pruned_day = None
        self._last_cycle_ok = True
        self._skip_logged = None

    # -- lifecycle -----------------------------------------------------------

    def run(self):
        logsetup.setup('engine', self.settings.get('log_level'))
        procs.write_pid(paths.child_pid_file('engine'))
        remove_quietly(paths.child_stop_flag('engine'))
        log.info('Uptime Sync %s engine starting (pid %d)', __version__, os.getpid())
        self._reload_monitors(force=True)
        self._warn_insecure_push_urls()
        threading.Thread(target=self._heartbeat_loop, name='heartbeat', daemon=True).start()
        threading.Thread(target=self._watch, name='watch', daemon=True).start()
        try:
            while not self.stop_event.is_set():
                started = time.time()
                self.settings = settings.load()
                logsetup.set_level(self.settings.get('log_level'))
                self._reload_monitors()
                self._run_cycle()
                self._daily_housekeeping()
                interval = max(10, int(self.settings.get('check_interval', 60) or 60))
                self.stop_event.wait(max(1.0, interval - (time.time() - started)))
        finally:
            self._save_history()
            remove_quietly(paths.child_pid_file('engine'))
            log.info('Engine stopped (exit code %d)', self.exit_code)
        return self.exit_code

    def stop(self, code=0):
        if code and not self.exit_code:
            self.exit_code = code
        self.stop_event.set()

    def _watch(self):
        """Stop on run/engine.stop, on an install click, or when orphaned."""
        while not self.stop_event.wait(1.0):
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
        self.results = {k: v for k, v in self.results.items() if k in known}
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
        workers = max(1, min(int(self.settings.get('max_workers', 10) or 10), len(self.monitors)))
        budget = max(10, int(self.settings.get('check_interval', 60) or 60) * 0.9)
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
        futures = {pool.submit(self._check_one, m): m for m in self.monitors}
        done, not_done = concurrent.futures.wait(futures, timeout=budget)
        for f in done:
            if f.exception():
                log.error('Check of %s crashed: %s', futures[f]['name'], f.exception())
        for f in not_done:
            log.warning('Check of %s did not finish within %ds', futures[f]['name'], budget)
        pool.shutdown(wait=False)
        self._last_cycle_ok = not not_done
        self._save_history()
        self._write_status()

    def _check_one(self, m):
        retry_delay = float(self.settings.get('retry_delay', 1) or 1)
        ok, ms, dns_ms = False, 0, 0
        for attempt in range(m['retry_count']):
            if self.stop_event.is_set():
                return
            try:
                ok, ms, dns_ms = self.checker.check(m)
            except Exception as e:
                log.debug('%s attempt %d raised %s', m['name'], attempt + 1, e)
                ok = False
            if ok:
                break
            if attempt < m['retry_count'] - 1:
                time.sleep(retry_delay)
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
            r = self.session.get(m['push_url'], params=params, timeout=10)
            code = r.status_code
            r.close()
        except requests.RequestException as e:
            code = 0
            log.error('Push for %s failed: %s', m['name'], redact(e))
        level = logging.INFO if code == 200 else logging.WARNING
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
        if len(window) == PUSH_WINDOW and url not in self._push_alerted and \
                sum(1 for c in window if c == 404) >= 0.8 * PUSH_WINDOW:
            self._push_alerted.add(url)
            log.warning('[PUSH] %s: most recent pushes to %s returned 404 - the push monitor '
                        'may have been deleted in Uptime Kuma', m['name'], redact(url))

    def _save_history(self):
        try:
            atomic_write_json(paths.HISTORY_FILE, self.history)
        except OSError as e:
            log.warning('Could not save history: %s', e)

    def _write_status(self):
        hb = self.heartbeat
        try:
            atomic_write_json(paths.STATUS_FILE, {
                'updated_at': iso_now(), 'version': __version__, 'pid': os.getpid(),
                'started_at': int(self.start_time), 'monitors': self.results,
                'heartbeat': {'last_ok': hb.last_ok, 'failures': hb.failures, 'error': hb.last_error},
            })
        except OSError:
            pass

    def _daily_housekeeping(self):
        today = time.strftime('%Y-%m-%d')
        if today == self._pruned_day:
            return
        self._pruned_day = today
        n = logsetup.prune(self.settings.get('log_retention_days', 14))
        if n:
            log.info('Removed %d old log file(s)', n)

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
                except Exception as e:
                    log.error('Heartbeat handling failed: %s', e, exc_info=True)
                wait = self.heartbeat.interval(s)
            else:
                wait = 30
            self.stop_event.wait(wait)

    def _act_on(self, reply, s):
        level = (reply.get('settings') or {}).get('log_level')
        if isinstance(level, str) and level.upper() in ('DEBUG', 'INFO', 'WARNING', 'ERROR') \
                and level.upper() != str(s.get('log_level', 'INFO')).upper():
            log.warning('Log level set by server: %s -> %s', s.get('log_level'), level.upper())
            settings.update({'log_level': level.upper()})
            logsetup.set_level(level)
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
        elif time.time() - self.start_time < UPDATE_GRACE_SECONDS:
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
        try:
            updater.download_and_stage(url, version, sha, settings.load())
        except updater.UpdateRefused as e:
            log.error('[UPDATE] [SECURITY] Refusing v%s: %s', version, e)
            updater.set_state(status='Failed', version=version, time=iso_now(), detail=str(e))
            self._updating.release()
            return
        except Exception as e:
            log.error('[UPDATE] v%s failed: %s', version, redact(e))
            self._updating.release()
            return
        log.warning('[UPDATE] v%s verified and staged - handing over to the supervisor', version)
        self.stop(updater.EXIT_UPDATE)


def main(supervised=False, parent_pid=0):
    paths.ensure_dirs()
    return Engine(supervised, parent_pid).run()
