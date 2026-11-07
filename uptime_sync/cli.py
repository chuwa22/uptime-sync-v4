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

from . import __version__, log as logsetup, paths, perms, procs, settings
from .util import read_json, remove_quietly, touch

STOP_WAIT_SECONDS = 60


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
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
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
    deadline = time.monotonic() + STOP_WAIT_SECONDS
    while time.monotonic() < deadline:
        if not _running()[1]:
            # The lock goes first; the process lingers ~1 s (log flush,
            # interpreter exit). A `restart` that starts the task inside that
            # window is dropped by Task Scheduler (IgnoreNew) / launchd.
            while pid and procs.pid_alive(pid) and time.monotonic() < deadline:
                time.sleep(0.2)
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
    from . import autostart, bootstrap
    if (a.recreate or a.wheels) and not os.environ.get(bootstrap.DONE_FLAG):
        # Started on .venv's own python: the .venv step (bootstrap) did not run.
        _say('[ERROR] --recreate and --wheels build .venv, so they need the system Python:')
        _say('        %s main.py install%s%s' % ('py -3' if procs.IS_WINDOWS else 'python3',
                                                ' --recreate' if a.recreate else '',
                                                ' --wheels DIR' if a.wheels else ''))
        return 2
    paths.ensure_dirs()
    _say('[OK] Directories ready under %s' % paths.ROOT)
    problems = perms.set_owner_admins(paths.ROOT) + perms.harden(grant_current_user=True)
    for problem in problems:
        _say('[WARN] Could not restrict permissions: %s' % problem)
    if not problems:
        _say('[OK] data/ and logs/ are readable only by this account and the service')
    home, writers = perms.base_python_writable()
    if writers:
        _say('[WARN] %s can be changed by %s. The agent runs as SYSTEM on the Python in that '
             'folder, so any local user could run code as SYSTEM. Fix (as administrator):'
             % (home, ' / '.join(writers)))
        if perms.under_user_profile(home):
            _say('       install Python "for all users" (C:\\Program Files), then run '
                 '`py -3 main.py install --recreate` again so .venv is rebuilt on it')
        else:
            _say('       icacls "%s" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F '
                 '*S-1-5-32-544:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX /Q' % home)
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
    from . import loglevel, logstore
    rows = logstore.query(min_level=loglevel.filter_value(a.level), proc=a.proc or '',
                          text=a.grep or '', limit=a.lines)
    for r in reversed(rows):
        _say('[%s] [%s] [%s/%s] %s' % (r['time'], r['level'], r['proc'], r['logger'], r['msg']))
    return 0


def cmd_version(a):
    _say('Uptime Sync %s (python %s, %s)' % (__version__, sys.version.split()[0], sys.platform))
    return 0


# -- parser ------------------------------------------------------------------------

# Shown by `main.py help` in this order. engine/web are started by the
# supervisor and stay out of every list (argparse prints a hidden sub-command
# as "==SUPPRESS==", so the overview is written here instead).
HELP_GROUPS = (
    ('Run it', ('start', 'stop', 'restart', 'status', 'run')),
    ('Set it up', ('install', 'uninstall', 'import', 'reset-password')),
    ('Look at it', ('check', 'logs', 'version', 'help')),
)
HIDDEN_COMMANDS = ('engine', 'web')
HELP_WORDS = ('-h', '--help', '?', '-?', '/?', '/h', '/help')
VERSION_WORDS = ('--version', '-version', '-v', '-V', '/v', '/version')

EXAMPLES = (
    ('main.py status', 'is it running? which pids?'),
    ('main.py restart', 'after changing settings by hand'),
    ('main.py check', 'try every enabled monitor now'),
    ('main.py logs -n 50 --proc engine', 'last 50 engine lines'),
    ('main.py logs --level WARNING --grep push', 'push problems only'),
    ('main.py reset-password admin', 'locked out of the web UI'),
    ('main.py help logs', 'every option of one command'),
)


class _CmdParser(argparse.ArgumentParser):
    """Every parse error ends with where to look next."""

    def error(self, message):
        self.print_usage(sys.stderr)
        cmd = self.prog.split(' ', 1)[1] if ' ' in self.prog else ''
        hint = ('Run "main.py help %s" for its options.' % cmd) if cmd else 'Run "main.py help" for the list of commands.'
        self.exit(2, '%s: error: %s\n%s\n' % (self.prog, message, hint))


class _Parser(_CmdParser):
    """Top level: its help is the grouped overview. Sub-commands are built as
    _CmdParser (add_subparsers would otherwise copy this class, and every
    `main.py logs --help` would print the overview)."""

    def format_help(self):
        return overview(self)


def overview(parser):
    subs = parser._uptime_subs
    width = max(len(n) for _, names in HELP_GROUPS for n in names) + 4
    out = ['Uptime Sync %s' % __version__, '',
           'Usage:  main.py <command> [options]',
           '        main.py help <command>     everything about one command',
           '        main.py --version          same as `version` (also -v, -V)',
           '',
           'Commands and options work with -, -- or / in front:',
           '        main.py -restart    main.py --logs -n 50    main.py /logs /n 50 /proc engine', '']
    for title, names in HELP_GROUPS:
        out.append(title)
        for n in names:
            out.append('  %s%s' % (n.ljust(width), subs[n].description or ''))
        out.append('')
    out.append('Examples')
    ew = max(len(c) for c, _ in EXAMPLES) + 3
    for cmd, why in EXAMPLES:
        out.append('  %s%s' % (cmd.ljust(ew), why))
    out.append('')
    try:
        out.append('Web UI: %s' % _web_url())
    except Exception:   # help must work even with a broken settings file
        pass
    if os.name != 'nt':
        out.append('zsh: "?" is a wildcard there, so type `main.py help` (or quote it: main.py "?").')
    return '\n'.join(out) + '\n'


def _epilog(*lines):
    return 'examples:\n' + '\n'.join('  ' + l for l in lines)


def build_parser():
    p = _Parser(prog='main.py', description='Uptime Sync %s' % __version__, add_help=False)
    p.add_argument('-h', '--help', action='help', help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest='command', metavar='<command>', parser_class=_CmdParser)
    p._uptime_subs = {}

    def add(name, fn, help_, epilog=None):
        sp = sub.add_parser(name, description=help_, epilog=epilog,
                            formatter_class=argparse.RawDescriptionHelpFormatter)
        sp.set_defaults(fn=fn)
        p._uptime_subs[name] = sp
        return sp

    sp = add('run', cmd_run, 'run the supervisor in the foreground (what autostart runs)')
    # 2 s by default: a `status` probe holds the lock for a moment, and a
    # supervisor that met it would exit 0 -- which systemd/launchd treat as a
    # deliberate stop and never restart.
    sp.add_argument('--wait-lock', type=float, default=2, help=argparse.SUPPRESS)
    sp = add('engine', cmd_engine, None)
    sp.add_argument('--supervised', action='store_true')
    sp.add_argument('--parent', type=int, default=0)
    sp = add('web', cmd_web, None)
    sp.add_argument('--parent', type=int, default=0)

    add('start', cmd_start, 'start in the background (through autostart when installed)')
    add('stop', cmd_stop, 'stop, and stay stopped until `start` (also across reboots)')
    add('restart', cmd_restart, 'stop, then start')
    sp = add('status', cmd_status, 'show what is running; exit 3 when not running',
             _epilog('main.py status', 'main.py status --json      for scripts and monitoring'))
    sp.add_argument('--json', action='store_true', help='print JSON instead of text')
    sp = add('install', cmd_install, 'build .venv, register autostart, start (run it with the system Python)',
             _epilog('py -3 main.py install            (Windows, elevated; or Launcher.bat -> I)',
                     'sudo python3 main.py install     (Linux / macOS)',
                     'main.py install --wheels C:\\wheels   (offline)'))
    sp.add_argument('--no-autostart', action='store_true', help='do not register autostart')
    sp.add_argument('--recreate', action='store_true',
                    help='delete .venv and build it again first (run with the system Python)')
    sp.add_argument('--wheels', metavar='DIR',
                    help='install the packages from wheel files in DIR, offline (system Python)')
    add('uninstall', cmd_uninstall, 'stop and remove autostart (keeps data/)')
    sp = add('import', cmd_import, 'import settings, monitors and users from an Uptime Sync 3.x folder',
             _epilog('main.py import "C:\\Uptime Sync" --dry-run    see what would come over',
                     'main.py import "C:\\Uptime Sync"'))
    sp.add_argument('path', help='the 3.x install folder (the one with data/ or config/)')
    sp.add_argument('--dry-run', action='store_true', help='show what would be imported')
    sp.add_argument('--force', action='store_true', help='overwrite data that already exists here')
    sp = add('reset-password', cmd_reset_password, 'set a web UI password (creates the admin if missing)',
             _epilog('main.py reset-password', 'main.py reset-password alice'))
    sp.add_argument('username', nargs='?', default='admin', help='user to reset (default: admin)')
    add('check', cmd_check, 'check every enabled monitor once and print the result (no push)')
    sp = add('logs', cmd_logs, 'print recent log lines (oldest first, newest at the bottom)',
             _epilog('main.py logs', 'main.py logs -n 50 --proc engine',
                     'main.py logs --level WARNING', 'main.py logs --grep "push HTTP 404"'))
    sp.add_argument('-n', '--lines', type=int, default=100, metavar='N', help='how many lines (default: 100)')
    sp.add_argument('--level', default='INFO', metavar='LEVEL',
                    help='lowest level shown: DEBUG, INFO, WARNING, ERROR (default: INFO)')
    sp.add_argument('--proc', choices=logsetup.PROCS, help='one process only')
    sp.add_argument('--grep', metavar='TEXT', help='only lines containing TEXT')
    add('version', cmd_version, 'print the version')
    sp = add('help', None, 'show this list, or everything about one command')
    sp.add_argument('topic', nargs='?', metavar='command', help='a command name, e.g. logs')
    return p


def _normalize_options(sp, args):
    """Let every option of a command be typed with -, -- or /, like the
    command itself: `logs /n 50`, `logs -lines 50`, `status /json`,
    `import /dry-run`, `logs /?`. Only a word that names one of this
    command's options is rewritten, and never the value after an option that
    takes one, so `--grep /api` and a path like `/Users/me/old` pass through."""
    names, takes_value = {}, set()
    for act in sp._actions:
        for opt in act.option_strings:
            key = opt.lstrip('-')
            if key not in names or opt.startswith('--'):   # prefer --lines over -n for "lines"
                names[key] = opt
            if act.nargs != 0:
                takes_value.add(opt)
    out, expect_value, rest = [], False, False
    for tok in args:
        if rest or expect_value:
            out.append(tok)
            expect_value = False
            continue
        if tok == '--':
            rest = True
        elif tok in HELP_WORDS:
            tok = '--help'
        elif tok[:1] in ('-', '/'):
            key, eq, val = tok.lstrip('-/').partition('=')
            if key in names:
                tok = names[key] + eq + val
        out.append(tok)
        expect_value = tok in takes_value
    return out


def _help(parser, topic):
    """`main.py help [command]` -> 0, or 2 for a command that does not exist."""
    subs = parser._uptime_subs
    if not topic or topic in HELP_WORDS:
        sys.stdout.write(overview(parser))
        return 0
    if topic.lstrip('-/') in subs:
        topic = topic.lstrip('-/')
    if topic in subs and topic not in HIDDEN_COMMANDS:
        subs[topic].print_help()
        return 0
    _unknown(parser, topic)
    return 2


def _unknown(parser, word):
    import difflib
    names = [n for n in parser._uptime_subs if n not in HIDDEN_COMMANDS]
    close = difflib.get_close_matches(word.lstrip('-/'), names, n=1)
    msg = 'Unknown command "%s".' % word
    if close:
        msg += ' Did you mean "%s"?' % close[0]
    sys.stderr.write(msg + '\nRun "main.py help" for the list of commands.\n')


def main(argv=None):
    parser = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        sys.stdout.write(overview(parser))
        return 2
    first = argv[0]
    if first in HELP_WORDS or first == 'help':
        return _help(parser, argv[1] if len(argv) > 1 else None)
    if first in VERSION_WORDS:
        return cmd_version(None)
    if first[:1] in ('-', '/'):
        # -restart, --restart, /restart (Windows habit) -> restart. The top
        # level has no options of its own besides help/version, so any other
        # dash word here is a mistyped command, not an option.
        name = first.lstrip('-/')
        if name == 'help':
            return _help(parser, argv[1] if len(argv) > 1 else None)
        if name not in parser._uptime_subs or name in HIDDEN_COMMANDS:
            _unknown(parser, first)
            return 2
        argv[0] = first = name
    if first not in parser._uptime_subs:
        _unknown(parser, first)
        return 2
    if first not in HIDDEN_COMMANDS:   # the supervisor's own command lines stay exact
        argv[1:] = _normalize_options(parser._uptime_subs[first], argv[1:])
    a = parser.parse_args(argv)
    if a.fn not in (cmd_run, cmd_engine, cmd_web):   # those set up their own logging
        logsetup.setup_console()
    try:
        return a.fn(a) or 0
    except KeyboardInterrupt:
        return 130
    finally:
        if a.fn not in (cmd_run, cmd_engine, cmd_web):
            perms.return_to_sudo_user()
