"""The supervisor: the one process the OS starts (Task Scheduler, systemd,
launchd). It runs the engine and the web UI as child processes, restarts a
child that dies (with backoff), applies staged updates, and rolls an update
back when the new engine keeps crashing.

Exactly one supervisor per install: an OS file lock (run/supervisor.lock)
decides, not a PID file, so the Windows minute-trigger that doubles as a
watchdog can fire as often as it likes -- a second copy exits at once.

run/stopped (written by `main.py stop`) makes every start exit cleanly
until `main.py start` removes it, so the OS restarting us cannot undo a
deliberate stop. Exit 0 = intentional (no OS restart), non-zero = crash.
"""

import logging
import os
import signal
import subprocess
import sys
import time

from . import __version__, log as logsetup, loglevel, paths, perms, procs, settings, updater
from .util import remove_quietly, touch

log = logging.getLogger('supervisor')

BACKOFF = (1, 2, 5, 10, 30, 60)
STABLE_SECONDS = 300          # a child that ran this long resets its backoff
UPDATE_TRIAL_SECONDS = 300    # a new version that survives this long is kept
UPDATE_MAX_CRASHES = 3
STOP_GRACE_SECONDS = 20        # above a check's worst attempt (ping timeout + 2 s)
RESTART_MIN_GAP = 60          # server-requested restarts closer than this are delayed
PULSE_CHECK_SECONDS = 30      # how often the engine's run/status.json age is checked
MAIN_PY = os.path.join(paths.ROOT, 'main.py')


class Child:
    def __init__(self, name, argv):
        self.name = name
        self.argv = argv
        self.proc = None
        self.started = 0.0
        self.failures = 0
        self.next_start = 0.0

    def start(self):
        remove_quietly(paths.child_stop_flag(self.name))
        kw = procs.child_popen_kwargs()
        err = self._stderr_file()
        if err is not None:
            kw['stderr'] = err
        try:
            self.proc = subprocess.Popen(self.argv, cwd=paths.ROOT, **kw)
        finally:
            if err is not None:
                err.close()
        self.started = time.monotonic()
        log.info('Started %s (pid %d)', self.name, self.proc.pid)

    def _stderr_file(self):
        """logs/<name>-stderr.log (append) so a crash before logging starts --
        an import error, a bad interpreter -- still leaves a trace. Rotated
        once at 1 MB; None if it cannot be opened (then stderr is dropped)."""
        path = os.path.join(paths.LOG_DIR, '%s-stderr.log' % self.name)
        try:
            if os.path.getsize(path) > 1024 * 1024:
                os.replace(path, path + '.1')
        except OSError:
            pass
        try:
            f = open(path, 'ab')
            f.write(('--- %s start %s ---\n' % (self.name, time.strftime('%Y-%m-%d %H:%M:%S'))).encode('ascii'))
            f.flush()
            return f
        except OSError:
            return None

    def running(self):
        return self.proc is not None and self.proc.poll() is None

    def stop(self, grace=STOP_GRACE_SECONDS):
        if not self.running():
            self.proc = None
            return
        touch(paths.child_stop_flag(self.name))
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline and self.proc.poll() is None:
            time.sleep(0.2)
        if self.proc.poll() is None:
            log.warning('%s did not stop within %ds - killing it', self.name, grace)
            self.proc.kill()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                pass
        remove_quietly(paths.child_stop_flag(self.name))
        self.proc = None

    def schedule_restart(self):
        ran = time.monotonic() - self.started
        if ran > STABLE_SECONDS:
            self.failures = 0
        delay = BACKOFF[min(self.failures, len(BACKOFF) - 1)]
        self.failures += 1
        self.next_start = time.monotonic() + delay
        return delay


class Supervisor:
    def __init__(self):
        self.lock = procs.InstanceLock(paths.LOCK_FILE)
        self.children = {}
        self.stopping = False
        self._last_restart = None

    def _argv(self, role):
        py = procs.background_python()
        argv = [py, MAIN_PY, role, '--parent', str(os.getpid())]
        if role == 'engine':
            argv.append('--supervised')
        return argv

    def run(self, wait_for_lock=0):
        # The lock first, and nothing else: the Windows minute trigger starts
        # a copy every minute, and every copy but one must leave at once
        # without opening logs.db or reading settings.
        deadline = time.monotonic() + wait_for_lock
        while not self.lock.acquire():
            if time.monotonic() >= deadline:
                return 0   # another supervisor owns this install
            time.sleep(0.5)
        try:
            if os.path.exists(paths.STOPPED_FLAG):
                return 0   # stopped by `main.py stop`; `main.py start` resumes
            paths.ensure_dirs()
            logsetup.setup('supervisor')
            if updater.recover_interrupted():
                return self._reexec()
            procs.write_pid(paths.SUPERVISOR_PID)
            remove_quietly(paths.SHUTDOWN_FLAG)
            for problem in perms.harden():
                log.warning('[SECURITY] Could not restrict permissions: %s', problem)
            self._install_signal_handlers()
            log.info('Uptime Sync %s supervisor starting (pid %d, python %s)',
                     __version__, os.getpid(), sys.version.split()[0])
            return self._loop()
        finally:
            for child in self.children.values():
                child.stop()
            remove_quietly(paths.SUPERVISOR_PID)
            self.lock.release()

    def _install_signal_handlers(self):
        def handler(signum, _frame):
            log.info('Signal %d received - shutting down', signum)
            self.stopping = True
        for name in ('SIGTERM', 'SIGINT', 'SIGBREAK'):
            if hasattr(signal, name):
                try:
                    signal.signal(getattr(signal, name), handler)
                except (OSError, ValueError):
                    pass

    def _wanted(self):
        roles = ['engine']
        if settings.load().get('web', {}).get('enabled', True):
            roles.append('web')
        return roles

    def _check_pulse(self):
        """Restart an engine that is alive but no longer cycling: it rewrites
        run/status.json every check_interval, so a file older than three
        intervals (+60 s) means its main loop is stuck somewhere."""
        engine = self.children.get('engine')
        if not engine or not engine.running():
            return
        interval = settings.load()['check_interval']
        limit = 3 * interval + 60
        if time.monotonic() - engine.started < limit:
            return
        try:
            age = time.time() - os.path.getmtime(paths.STATUS_FILE)
        except OSError:
            age = None
        if age is None or age > limit:
            log.error('Engine (pid %d) has not finished a check cycle for over %ds - restarting it',
                      engine.proc.pid, limit)
            engine.stop()
            self._note_crash('engine', 'stalled')
            log.warning('engine restarting in %ds', engine.schedule_restart())

    def _loop(self):
        for role in self._wanted():
            self.children[role] = Child(role, self._argv(role))
            self.children[role].start()
        next_pulse = time.monotonic() + PULSE_CHECK_SECONDS
        while True:
            time.sleep(0.5)
            loglevel.refresh()
            if time.monotonic() >= next_pulse:
                next_pulse = time.monotonic() + PULSE_CHECK_SECONDS
                self._check_pulse()
            if self.stopping or os.path.exists(paths.SHUTDOWN_FLAG):
                remove_quietly(paths.SHUTDOWN_FLAG)
                log.info('Shutting down')
                return 0
            if os.path.exists(paths.RESTART_FLAG):
                remove_quietly(paths.RESTART_FLAG)
                log.info('Restart requested - restarting children')
                self._restart_children()
            self._check_update_trial()
            # By role, looking each child up afresh: _restart_children()
            # replaces the Child objects, and a stale one started here would
            # be a second, untracked process.
            for role in list(self.children):
                child = self.children.get(role)
                if child is None:
                    continue
                if child.proc is not None and child.proc.poll() is not None:
                    code = child.proc.returncode
                    child.proc = None
                    if role == 'engine' and code == updater.EXIT_UPDATE:
                        return self._apply_update()
                    if role == 'engine' and code == updater.EXIT_RESTART:
                        now = time.monotonic()
                        if self._last_restart is None or now - self._last_restart >= RESTART_MIN_GAP:
                            self._last_restart = now
                            log.warning('Engine asked for a restart')
                            self._restart_children()
                            break
                        # The server keeps asking: restart only the engine, with backoff.
                        log.warning('Engine asked for another restart within %ds - restarting '
                                    'the engine only, in %ds', RESTART_MIN_GAP, child.schedule_restart())
                        continue
                    if code != 0:
                        self._note_crash(role, code)
                    delay = child.schedule_restart()
                    if role == 'engine' and code == updater.EXIT_STUCK:
                        log.warning('engine stopped itself: a check was hung - restarting in %ds', delay)
                    else:
                        log.warning('%s exited with code %s - restarting in %ds', role, code, delay)
                if child.proc is None and time.monotonic() >= child.next_start:
                    if self._check_rollback_needed():
                        return self._reexec()
                    child.start()

    def _restart_children(self):
        for child in self.children.values():
            child.stop()
        self.children = {}
        for role in self._wanted():
            self.children[role] = Child(role, self._argv(role))
            self.children[role].start()

    # -- updates -------------------------------------------------------------

    def _apply_update(self):
        if 'web' in self.children:
            self.children['web'].stop()
        version = updater.apply()
        if version:
            log.warning('[UPDATE] v%s installed - restarting the supervisor on the new code', version)
        else:
            log.error('[UPDATE] Update not applied - continuing on v%s', __version__)
        return self._reexec()

    def _note_crash(self, role, code):
        s = updater.state()
        if role == 'engine' and s.get('status') == 'Applied':
            crashes = int(s.get('crashes', 0)) + 1
            updater.set_state(crashes=crashes)
            log.error('[UPDATE] New v%s engine crashed (exit %s), %d/%d', s.get('version'),
                      code, crashes, UPDATE_MAX_CRASHES)

    def _check_rollback_needed(self):
        s = updater.state()
        if s.get('status') == 'Applied' and int(s.get('crashes', 0)) >= UPDATE_MAX_CRASHES:
            for child in self.children.values():
                child.stop()
            return updater.rollback('the new engine crashed %d times after the update'
                                    % UPDATE_MAX_CRASHES)
        return False

    def _check_update_trial(self):
        s = updater.state()
        if s.get('status') != 'Applied':
            return
        engine = self.children.get('engine')
        if engine and engine.running() and time.monotonic() - engine.started > UPDATE_TRIAL_SECONDS:
            updater.set_state(status='Success')
            log.info('[UPDATE] v%s has run for %ds - update successful', s.get('version'),
                     UPDATE_TRIAL_SECONDS)

    def _reexec(self):
        """Start this supervisor again on the code now on disk."""
        for child in self.children.values():
            child.stop()
        self.children = {}
        argv = [procs.background_python(), MAIN_PY, 'run', '--wait-lock', '30']
        logging.shutdown()
        if procs.IS_WINDOWS:
            # A detached copy takes the lock once we release it on exit. The
            # Task Scheduler instance ends with us; its minute trigger then
            # finds the lock held and exits at once.
            subprocess.Popen(argv, cwd=paths.ROOT, **procs.detached_popen_kwargs())
            return 0
        self.lock.release()
        os.chdir(paths.ROOT)
        os.execv(argv[0], argv)


def run(wait_for_lock=0):
    return Supervisor().run(wait_for_lock)
