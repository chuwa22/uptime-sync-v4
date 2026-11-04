"""Command line: `python main.py <command>`. Run with no arguments for help.

The OS autostart runs `main.py run` (the supervisor); everything else is
for the person at the keyboard. Output is plain ASCII.
"""

import argparse
import getpass
import json
import os
import sys
import time

from . import __version__, paths, perms, procs, settings
from .util import read_json, remove_quietly, touch

STOP_WAIT_SECONDS = 40


def _say(msg=''):
    print(msg)


def _running():
    """(pid, True) when a supervisor holds this install's lock."""
    held = procs.InstanceLock(paths.LOCK_FILE).held_by_other()
    return (procs.read_pid(paths.SUPERVISOR_PID) if held else None), held


def _web_url(s=None):
    s = s or settings.load()
    host = s.get('web', {}).get('host', '0.0.0.0')
    if host in ('0.0.0.0', '::', ''):
        host = '127.0.0.1'
    return 'http://%s:%s/' % (host, s.get('web', {}).get('port', 5000))


# -- process roles (started by the OS / the supervisor) ------------------------

def cmd_run(a):
    from . import supervisor
    perms.restrict_umask()
    return supervisor.run(wait_for_lock=a.wait_lock)


def cmd_engine(a):
    from . import engine
    perms.restrict_umask()
    return engine.main(supervised=a.supervised, parent_pid=a.parent)


def cmd_web(a):
    from . import web
    perms.restrict_umask()
    return web.main(parent_pid=a.parent)


# -- lifecycle -------------------------------------------------------------------

def _spawn_supervisor():
    import subprocess
    argv = [procs.background_python(), os.path.join(paths.ROOT, 'main.py'), 'run']
    subprocess.Popen(argv, cwd=paths.ROOT, **procs.detached_popen_kwargs())


def _wait_running(seconds=15):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if _running()[1]:
            return True
        time.sleep(0.5)
    return False


def cmd_start(a):
    from . import autostart
    paths.ensure_dirs()
    remove_quietly(paths.STOPPED_FLAG)
    perms.return_to_sudo_user()       # before the service (as that user) starts
    pid, running = _running()
    if running:
        _say('[OK] Already running (supervisor pid %s)' % pid)
        return 0
    state = autostart.installed()
    if state:
        try:
            autostart.start()
        except autostart.AutostartError as e:
            if procs.IS_WINDOWS:
                _say('[INFO] Could not start the task now (%s).' % e)
                _say('[INFO] The scheduled task starts it within a minute.')
                return 0
            _say('[ERROR] %s' % e)
            return 1
    else:
        _spawn_supervisor()
    if _wait_running():
        _say('[OK] Started. Web UI: %s' % _web_url())
        return 0
    _say('[WARN] Not running yet. See `main.py logs` and logs/*-stderr.log.')
    return 1


def cmd_stop(a):
    paths.ensure_dirs()
    touch(paths.STOPPED_FLAG)
    pid, running = _running()
    if not running:
        _say('[OK] Not running. It stays stopped until `main.py start`.')
        return 0
    touch(paths.SHUTDOWN_FLAG)
    _say('[INFO] Stopping supervisor pid %s ...' % pid)
    deadline = time.time() + STOP_WAIT_SECONDS
    while time.time() < deadline:
        if not _running()[1]:
            remove_quietly(paths.SHUTDOWN_FLAG)
            _say('[OK] Stopped. It stays stopped (also across reboots) until `main.py start`.')
            return 0
        time.sleep(0.5)
    _say('[ERROR] Still running after %ds.' % STOP_WAIT_SECONDS)
    return 1


def cmd_restart(a):
    code = cmd_stop(a)
    if code:
        return code
    return cmd_start(a)


def cmd_status(a):
    from . import autostart, updater
    s = settings.load()
    pid, running = _running()
    st = read_json(paths.STATUS_FILE, {}) or {}
    info = {
        'version': __version__,
        'root': paths.ROOT,
        'python': sys.version.split()[0],
        'running': running,
        'supervisor_pid': pid,
        'engine_pid': _child_pid('engine'),
        'web_pid': _child_pid('web'),
        'stopped_flag': os.path.exists(paths.STOPPED_FLAG),
        'autostart': autostart.installed().get('kind') or None,
        'web_url': _web_url(s) if s.get('web', {}).get('enabled', True) else None,
        'heartbeat': st.get('heartbeat'),
        'update': updater.state() or None,
        'readable_by_others': perms.check(),
    }
    if a.json:
        info['monitors'] = st.get('monitors', {})
        _say(json.dumps(info, indent=2))
        return 0 if running else 3
    _say('Uptime Sync %s  (python %s)' % (__version__, info['python']))
    _say('  root        %s' % paths.ROOT)
    _say('  supervisor  %s' % ('running, pid %s' % pid if running else 'NOT running'))
    for role in ('engine', 'web'):
        _say('  %-11s %s' % (role, 'pid %s' % info[role + '_pid'] if info[role + '_pid'] else '-'))
    if info['stopped_flag']:
        _say('  stopped     yes (by `main.py stop`; `main.py start` resumes)')
    _say('  autostart   %s' % (info['autostart'] or 'not installed'))
    if info['web_url']:
        _say('  web UI      %s' % info['web_url'])
    hb = st.get('heartbeat') or {}
    if s.get('remote', {}).get('enabled'):
        last = hb.get('last_ok')
        _say('  heartbeat   %s%s' % ('last OK %ds ago' % (time.time() - last) if last else 'never OK',
                                     ', error: %s' % hb['error'] if hb.get('error') else ''))
    else:
        _say('  heartbeat   off (remote reporting disabled)')
    mons = st.get('monitors') or {}
    if mons:
        up = sum(1 for m in mons.values() if m.get('ok'))
        _say('  monitors    %d up, %d down (as of %s)' % (up, len(mons) - up, st.get('updated_at', '?')))
        for m in sorted(mons.values(), key=lambda m: m.get('name', '')):
            if not m.get('ok'):
                _say('    [DOWN] %s (%s %s)' % (m.get('name'), m.get('type'), m.get('target')))
    exposed = info['readable_by_others']
    if exposed:
        exposed = [os.path.relpath(e, paths.ROOT) for e in exposed]
        _say('  [SECURITY] readable by other local users: %s' % ', '.join(exposed[:5]) +
             (' (+%d more)' % (len(exposed) - 5) if len(exposed) > 5 else ''))
        _say('             fixed on the next start, or now with `main.py install --no-autostart`')
    u = info['update']
    if u:
        _say('  update      %s v%s %s' % (u.get('status'), u.get('version', '?'), u.get('time', '')))
    return 0 if running else 3


def _child_pid(name):
    pid = procs.read_pid(paths.child_pid_file(name))
    return pid if pid and procs.pid_alive(pid) else None


# -- setup -------------------------------------------------------------------------

def cmd_install(a):
    from . import autostart
    paths.ensure_dirs()
    _say('[OK] Directories ready under %s' % paths.ROOT)
    problems = perms.harden(grant_current_user=True)
    for problem in problems:
        _say('[WARN] Could not restrict permissions: %s' % problem)
    if not problems:
        _say('[OK] data/ and logs/ are readable only by this account and the service')
    if a.no_autostart:
        _say('[INFO] Autostart skipped (--no-autostart). Start with `main.py run`.')
        return 0
    try:
        state = autostart.install()
    except autostart.AutostartError as e:
        _say('[ERROR] Autostart: %s' % e)
        return 1
    _say('[OK] Autostart installed: %s %s' % (state['kind'], state.get('path') or state.get('name')))
    if state.get('note'):
        _say('[INFO] %s' % state['note'])
    code = cmd_start(a)
    from .web import auth
    if not auth.has_users():
        _say('[INFO] Open %s to create the admin account.' % _web_url())
    return code


def cmd_uninstall(a):
    from . import autostart
    cmd_stop(a)
    state = autostart.uninstall()
    _say('[OK] Autostart removed%s.' % (' (%s)' % state.get('kind') if state else ''))
    _say('[INFO] data/ and logs/ were left in place; delete the folder to remove everything.')
    return 0


def cmd_import(a):
    from . import importer
    return importer.run(a.path, dry_run=a.dry_run, force=a.force, out=_say)


def cmd_reset_password(a):
    from .web import auth
    users = auth.load_users()
    if a.username not in users:
        _say('[INFO] No user %r - a new admin account will be created.' % a.username)
    pw = getpass.getpass('New password: ')
    problem = auth.password_problem(pw, getpass.getpass('Again: '))
    if problem:
        _say('[ERROR] %s' % problem)
        return 1
    if a.username in users:
        auth.set_password(a.username, pw)
        _say('[OK] Password changed; that user\'s other sessions are signed out.')
    else:
        auth.create_user(a.username, pw, role='admin')
        _say('[OK] Admin %r created.' % a.username)
    return 0


# -- diagnostics -------------------------------------------------------------------

def cmd_check(a):
    """Run every enabled monitor once and print the result. Pushes nothing."""
    from . import monitors
    from .checks import Checker
    env = settings.env_values()
    items = [monitors.runtime_view(m, env) for m in monitors.load() if m['enabled']]
    if not items:
        _say('[INFO] No enabled monitors.')
        return 0
    checker = Checker()
    failed = 0
    for m in items:
        try:
            ok, ms, _dns = checker.check(m)
        except Exception as e:
            ok, ms = False, 0
            _say('  %s raised %s' % (m['name'], e))
        failed += 0 if ok else 1
        _say('%-7s %-30s %-8s %-30s %sms' % ('[UP]' if ok else '[DOWN]', m['name'][:30], m['type'],
                                             m['target'][:30], ms))
    return 1 if failed else 0


def cmd_logs(a):
    from . import logstore
    rows = logstore.query(min_level=logstore.LEVELS.get(a.level.upper(), 20), proc=a.proc or '',
                          text=a.grep or '', limit=a.lines)
    for r in reversed(rows):
        _say('[%s] [%s] [%s/%s] %s' % (r['time'], r['level'], r['proc'], r['logger'], r['msg']))
    return 0


def cmd_version(a):
    _say('Uptime Sync %s (python %s, %s)' % (__version__, sys.version.split()[0], sys.platform))
    return 0


# -- parser ------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(prog='main.py', description='Uptime Sync %s' % __version__)
    sub = p.add_subparsers(dest='command', metavar='<command>')

    def add(name, fn, help_):
        sp = sub.add_parser(name, help=help_, description=help_)
        sp.set_defaults(fn=fn)
        return sp

    sp = add('run', cmd_run, 'run the supervisor in the foreground (what autostart runs)')
    sp.add_argument('--wait-lock', type=float, default=0, help=argparse.SUPPRESS)
    sp = add('engine', cmd_engine, argparse.SUPPRESS)
    sp.add_argument('--supervised', action='store_true')
    sp.add_argument('--parent', type=int, default=0)
    sp = add('web', cmd_web, argparse.SUPPRESS)
    sp.add_argument('--parent', type=int, default=0)

    add('start', cmd_start, 'start in the background (through autostart when installed)')
    add('stop', cmd_stop, 'stop, and stay stopped until `start` (also across reboots)')
    add('restart', cmd_restart, 'stop, then start')
    sp = add('status', cmd_status, 'show what is running; exit 3 when not running')
    sp.add_argument('--json', action='store_true')
    sp = add('install', cmd_install, 'create folders, register autostart, start')
    sp.add_argument('--no-autostart', action='store_true')
    add('uninstall', cmd_uninstall, 'stop and remove autostart (keeps data/)')
    sp = add('import', cmd_import, 'import settings, monitors and users from an Uptime Sync 3.x folder')
    sp.add_argument('path')
    sp.add_argument('--dry-run', action='store_true', help='show what would be imported')
    sp.add_argument('--force', action='store_true', help='overwrite data that already exists here')
    sp = add('reset-password', cmd_reset_password, 'set a web UI password (creates the admin if missing)')
    sp.add_argument('username', nargs='?', default='admin')
    add('check', cmd_check, 'check every enabled monitor once and print the result (no push)')
    sp = add('logs', cmd_logs, 'print recent log lines')
    sp.add_argument('-n', '--lines', type=int, default=100)
    sp.add_argument('--level', default='INFO')
    sp.add_argument('--proc', choices=('supervisor', 'engine', 'web', 'cli'))
    sp.add_argument('--grep')
    add('version', cmd_version, 'print the version')
    return p


def main(argv=None):
    parser = build_parser()
    a = parser.parse_args(argv)
    if not getattr(a, 'fn', None):
        parser.print_help()
        return 2
    try:
        return a.fn(a) or 0
    except KeyboardInterrupt:
        return 130
    finally:
        if a.fn not in (cmd_run, cmd_engine, cmd_web):
            perms.return_to_sudo_user()
