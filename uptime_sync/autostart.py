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
"""

import os
import subprocess
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


def _run(cmd, check=True):
    flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          stdin=subprocess.DEVNULL, creationflags=flags)
    out = perms._console_text(proc.stdout).strip()   # OEM code page on Windows
    if check and proc.returncode != 0:
        raise AutostartError('%s failed (%d): %s' % (' '.join(cmd[:2]), proc.returncode, out))
    return proc.returncode, out


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


def _win_install(python):
    if not is_admin():
        raise AutostartError('Run this from an elevated prompt (Run as administrator).')
    fd, xml_path = tempfile.mkstemp(suffix='.xml')
    os.close(fd)
    try:
        with open(xml_path, 'w', encoding='utf-16') as f:
            f.write(windows_task_xml(python, paths.ROOT))
        _run(['schtasks', '/Create', '/TN', WIN_TASK, '/XML', xml_path, '/F'])
    finally:
        remove_quietly(xml_path)
    return {'kind': 'windows-task', 'name': WIN_TASK}


def _win_uninstall(state):
    _run(['schtasks', '/Delete', '/TN', state.get('name', WIN_TASK), '/F'], check=False)


def _win_start(state):
    _run(['schtasks', '/Run', '/TN', state.get('name', WIN_TASK)])


def _win_installed():
    code, _ = _run(['schtasks', '/Query', '/TN', WIN_TASK], check=False)
    return code == 0


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


def _linux_paths():
    if is_admin():
        return '/etc/systemd/system/%s.service' % UNIT, []
    base = os.path.expanduser('~/.config/systemd/user')
    return os.path.join(base, '%s.service' % UNIT), ['--user']


def _linux_install(python):
    unit_path, scope = _linux_paths()
    user = (os.environ.get('SUDO_USER') or 'root') if not scope else None
    os.makedirs(os.path.dirname(unit_path), exist_ok=True)
    with open(unit_path, 'w') as f:
        f.write(systemd_unit(python, paths.ROOT, user))
    _run(['systemctl'] + scope + ['daemon-reload'])
    _run(['systemctl'] + scope + ['enable', UNIT])
    note = '' if not scope else ('user unit: run `loginctl enable-linger %s` so it starts at boot '
                                 'without a login' % os.environ.get('USER', '<user>'))
    return {'kind': 'systemd', 'name': UNIT, 'path': unit_path, 'scope': scope, 'note': note}


def _linux_uninstall(state):
    scope = state.get('scope', [])
    _run(['systemctl'] + scope + ['disable', '--now', UNIT], check=False)
    remove_quietly(state.get('path', ''))
    _run(['systemctl'] + scope + ['daemon-reload'], check=False)


def _linux_start(state):
    _run(['systemctl'] + state.get('scope', []) + ['restart', UNIT])


# -- macOS ---------------------------------------------------------------------

def launchd_plist(python, root, user=None):
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
""".format(label=s(LABEL), python=s(python), main=s(os.path.join(root, 'main.py')),
           root=s(root), log=s(log), user=user_xml)


def _mac_domain():
    return 'system' if is_admin() else 'gui/%d' % os.getuid()


def _mac_install(python):
    if is_admin():
        plist = '/Library/LaunchDaemons/%s.plist' % LABEL
        user = os.environ.get('SUDO_USER')
    else:
        plist = os.path.expanduser('~/Library/LaunchAgents/%s.plist' % LABEL)
        user = None
    domain = _mac_domain()
    _run(['launchctl', 'bootout', '%s/%s' % (domain, LABEL)], check=False)
    os.makedirs(os.path.dirname(plist), exist_ok=True)
    with open(plist, 'w', encoding='utf-8') as f:
        f.write(launchd_plist(python, paths.ROOT, user))
    if is_admin():
        os.chmod(plist, 0o644)
    code, out = _run(['launchctl', 'bootstrap', domain, plist], check=False)
    if code != 0:
        _run(['launchctl', 'load', '-w', plist])
    return {'kind': 'launchd', 'name': LABEL, 'path': plist, 'domain': domain,
            'note': '' if is_admin() else 'LaunchAgent: runs while this user is logged in '
                                          '(install with sudo for a boot-time LaunchDaemon)'}


def _mac_uninstall(state):
    domain = state.get('domain', _mac_domain())
    code, _ = _run(['launchctl', 'bootout', '%s/%s' % (domain, LABEL)], check=False)
    if code != 0 and state.get('path'):
        _run(['launchctl', 'unload', '-w', state['path']], check=False)
    remove_quietly(state.get('path', ''))


def _mac_start(state):
    _run(['launchctl', 'kickstart', '%s/%s' % (state.get('domain', _mac_domain()), LABEL)])


# -- public ----------------------------------------------------------------------

def install():
    """Register the supervisor with the OS. Returns the state dict."""
    python = procs.background_python()
    if not os.path.isfile(python):
        raise AutostartError('%s does not exist - run install.py first' % python)
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
        return state or ({'kind': 'windows-task', 'name': WIN_TASK} if _win_installed() else {})
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
