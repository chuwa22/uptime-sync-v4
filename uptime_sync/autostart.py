"""Start the supervisor with the OS and bring it back if it dies.

    Windows  Task Scheduler task (schtasks.exe + XML, works on Windows 7):
             at boot, and every minute as the watchdog. The supervisor's
             instance lock makes the extra starts exit at once, and
             MultipleInstancesPolicy=IgnoreNew skips them while it runs.
             Runs as SYSTEM; needs an elevated prompt to install.
    Linux    systemd unit, Restart=on-failure. As root: a system unit
             (runs as the sudo user if there is one); otherwise a user unit.
    macOS    launchd job, KeepAlive on a non-zero exit. As root: a
             LaunchDaemon (UserName = the sudo user); otherwise a
             LaunchAgent (runs while that user is logged in).

Exit 0 from the supervisor means "stopped on purpose", so no OS restarts it;
any crash exits non-zero and is restarted.

Names: UptimeSync4 / uptime-sync / com.uptimesync.agent, unless one with
that name already starts a DIFFERENT install folder -- then this install
gets <name>-<8 hex of its path>, so a second copy on the same box never
takes over the first one's autostart. The name chosen is kept in
data/autostart.json and reused by every later install / uninstall.
"""

import hashlib
import os
import sys
import tempfile
from xml.sax.saxutils import escape

from . import paths, perms, procs
from .util import atomic_write_json, read_json, remove_quietly

STATE_FILE = os.path.join(paths.DATA_DIR, 'autostart.json')
WIN_TASK = 'UptimeSync4'
UNIT = 'uptime-sync'
LABEL = 'com.uptimesync.agent'
MAIN_PY = os.path.join(paths.ROOT, 'main.py')


class AutostartError(Exception):
    pass


RUN_TIMEOUT = 60


def _run(cmd, check=True):
    code, raw, error = procs.run(cmd, RUN_TIMEOUT)
    out = perms._console_text(raw).strip()   # OEM code page on Windows
    if code is None:
        if check:
            raise AutostartError('%s: %s' % (' '.join(cmd[:2]), error))
        return -1, error
    if check and code != 0:
        raise AutostartError('%s failed (%d): %s' % (' '.join(cmd[:2]), code, out))
    return code, out


def is_admin():
    if procs.IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def _state():
    return read_json(STATE_FILE, {}) or {}


def _mentions_root(text):
    """Does an existing task / unit / plist start THIS install's main.py?"""
    t = (text or '').lower()
    forms = (MAIN_PY, escape(MAIN_PY))
    # schtasks output went through the OEM code page and _console_text.
    forms += tuple(f.encode('ascii', 'replace').decode('ascii') for f in forms)
    return any(f.lower() in t for f in forms)


def root_suffixed(base):
    digest = hashlib.sha1(os.path.normcase(paths.ROOT).encode('utf-8')).hexdigest()[:8]
    return '%s-%s' % (base, digest)


def choose_name(base, existing_text):
    """The registration name for this install. existing_text(name) returns
    the definition registered under `name`, or None when there is none."""
    previous = _state().get('name')
    if previous:
        return previous
    text = existing_text(base)
    if text is None or _mentions_root(text):
        return base
    return root_suffixed(base)


def _read_text(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()
    except OSError:
        return None


# -- Windows ---------------------------------------------------------------------

def windows_task_xml(python, root):
    main = os.path.join(root, 'main.py')
    return u"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Uptime Sync 4 ({root}). Starts at boot and every minute as a watchdog; a second copy exits at once.</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>PT30S</Delay>
    </BootTrigger>
    <TimeTrigger>
      <Repetition>
        <Interval>PT1M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2020-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>6</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{python}</Command>
      <Arguments>"{main}" run</Arguments>
      <WorkingDirectory>{root}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
""".format(python=escape(python), main=escape(main), root=escape(root))


def _win_task_text(name):
    code, out = _run(['schtasks', '/Query', '/TN', name, '/XML'], check=False)
    return out if code == 0 else None


def _win_install(python):
    if not is_admin():
        raise AutostartError('Run this from an elevated prompt (Run as administrator).')
    name = choose_name(WIN_TASK, _win_task_text)
    fd, xml_path = tempfile.mkstemp(suffix='.xml')
    os.close(fd)
    try:
        with open(xml_path, 'w', encoding='utf-16') as f:
            f.write(windows_task_xml(python, paths.ROOT))
        _run(['schtasks', '/Create', '/TN', name, '/XML', xml_path, '/F'])
    finally:
        remove_quietly(xml_path)
    return {'kind': 'windows-task', 'name': name}


def _win_uninstall(state):
    _run(['schtasks', '/Delete', '/TN', state.get('name', WIN_TASK), '/F'], check=False)


def _win_start(state):
    _run(['schtasks', '/Run', '/TN', state.get('name', WIN_TASK)])


def _win_installed():
    """The task name that starts this install, or ''."""
    for name in (WIN_TASK, root_suffixed(WIN_TASK)):
        if _mentions_root(_win_task_text(name)):
            return name
    return ''


# -- Linux ---------------------------------------------------------------------

def systemd_unit(python, root, user=None):
    lines = [
        '[Unit]',
        'Description=Uptime Sync 4 agent (%s)' % root,
        'After=network-online.target',
        'Wants=network-online.target',
        '',
        '[Service]',
        'Type=simple',
        'WorkingDirectory=%s' % root,
        'ExecStart="%s" "%s" run' % (python, os.path.join(root, 'main.py')),
        'Restart=on-failure',
        'RestartSec=5',
        'KillMode=mixed',
        'TimeoutStopSec=30',
    ]
    if user:
        lines.append('User=%s' % user)
    lines += ['', '[Install]', 'WantedBy=%s' % ('multi-user.target' if user is not None else 'default.target'), '']
    return '\n'.join(lines)


def _linux_paths(name=UNIT):
    if is_admin():
        return '/etc/systemd/system/%s.service' % name, []
    base = os.path.expanduser('~/.config/systemd/user')
    return os.path.join(base, '%s.service' % name), ['--user']


def _linux_install(python):
    name = choose_name(UNIT, lambda n: _read_text(_linux_paths(n)[0]))
    unit_path, scope = _linux_paths(name)
    user = (os.environ.get('SUDO_USER') or 'root') if not scope else None
    os.makedirs(os.path.dirname(unit_path), exist_ok=True)
    with open(unit_path, 'w') as f:
        f.write(systemd_unit(python, paths.ROOT, user))
    _run(['systemctl'] + scope + ['daemon-reload'])
    _run(['systemctl'] + scope + ['enable', name])
    note = '' if not scope else ('user unit: run `loginctl enable-linger %s` so it starts at boot '
                                 'without a login' % os.environ.get('USER', '<user>'))
    return {'kind': 'systemd', 'name': name, 'path': unit_path, 'scope': scope, 'note': note}


def _linux_uninstall(state):
    scope = state.get('scope', [])
    _run(['systemctl'] + scope + ['disable', '--now', state.get('name', UNIT)], check=False)
    remove_quietly(state.get('path', ''))
    _run(['systemctl'] + scope + ['daemon-reload'], check=False)


def _linux_start(state):
    _run(['systemctl'] + state.get('scope', []) + ['restart', state.get('name', UNIT)])


# -- macOS ---------------------------------------------------------------------

def launchd_plist(python, root, user=None, label=LABEL):
    def s(v):
        return '<string>%s</string>' % escape(v)
    user_xml = '\n  <key>UserName</key>\n  %s' % s(user) if user else ''
    log = os.path.join(root, 'logs', 'launchd.log')
    return """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  {label}
  <key>ProgramArguments</key>
  <array>
    {python}
    {main}
    <string>run</string>
  </array>
  <key>WorkingDirectory</key>
  {root}
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>ThrottleInterval</key>
  <integer>10</integer>
  <key>StandardOutPath</key>
  {log}
  <key>StandardErrorPath</key>
  {log}{user}
</dict>
</plist>
""".format(label=s(label), python=s(python), main=s(os.path.join(root, 'main.py')),
           root=s(root), log=s(log), user=user_xml)


def _mac_domain():
    return 'system' if is_admin() else 'gui/%d' % os.getuid()


def _mac_plist(label):
    if is_admin():
        return '/Library/LaunchDaemons/%s.plist' % label
    return os.path.expanduser('~/Library/LaunchAgents/%s.plist' % label)


def _mac_install(python):
    label = choose_name(LABEL, lambda n: _read_text(_mac_plist(n)))
    plist = _mac_plist(label)
    user = os.environ.get('SUDO_USER') if is_admin() else None
    domain = _mac_domain()
    _run(['launchctl', 'bootout', '%s/%s' % (domain, label)], check=False)
    os.makedirs(os.path.dirname(plist), exist_ok=True)
    with open(plist, 'w', encoding='utf-8') as f:
        f.write(launchd_plist(python, paths.ROOT, user, label))
    if is_admin():
        os.chmod(plist, 0o644)
    code, out = _run(['launchctl', 'bootstrap', domain, plist], check=False)
    if code != 0:
        _run(['launchctl', 'load', '-w', plist])
    return {'kind': 'launchd', 'name': label, 'path': plist, 'domain': domain,
            'note': '' if is_admin() else 'LaunchAgent: runs while this user is logged in '
                                          '(install with sudo for a boot-time LaunchDaemon)'}


def _mac_uninstall(state):
    domain = state.get('domain', _mac_domain())
    code, _ = _run(['launchctl', 'bootout', '%s/%s' % (domain, state.get('name', LABEL))], check=False)
    if code != 0 and state.get('path'):
        _run(['launchctl', 'unload', '-w', state['path']], check=False)
    remove_quietly(state.get('path', ''))


def _mac_start(state):
    _run(['launchctl', 'kickstart', '%s/%s' % (state.get('domain', _mac_domain()),
                                               state.get('name', LABEL))])


# -- public ----------------------------------------------------------------------

def install():
    """Register the supervisor with the OS. Returns the state dict."""
    python = procs.background_python()
    if not os.path.isfile(python):
        raise AutostartError('%s does not exist - run `main.py install` with the system Python first' % python)
    if procs.IS_WINDOWS:
        state = _win_install(python)
    elif sys.platform == 'darwin':
        state = _mac_install(python)
    elif sys.platform.startswith('linux'):
        state = _linux_install(python)
    else:
        raise AutostartError('No autostart support for %s' % sys.platform)
    state['python'] = python
    atomic_write_json(STATE_FILE, state)
    return state


def uninstall():
    state = _state()
    if procs.IS_WINDOWS:
        _win_uninstall(state)
    elif sys.platform == 'darwin':
        _mac_uninstall(state)
    elif state:
        _linux_uninstall(state)
    remove_quietly(STATE_FILE)
    return state


def installed():
    state = _state()
    if procs.IS_WINDOWS:
        if state:
            return state
        name = _win_installed()
        return {'kind': 'windows-task', 'name': name} if name else {}
    if state.get('path') and not os.path.exists(state['path']):
        return {}
    return state


def start():
    """Ask the OS to start the supervisor. False when no autostart is set up."""
    state = installed()
    if not state:
        return False
    if procs.IS_WINDOWS:
        _win_start(state)
    elif sys.platform == 'darwin':
        _mac_start(state)
    else:
        _linux_start(state)
    return True
