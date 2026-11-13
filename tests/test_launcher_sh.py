"""Launcher.sh, the Linux control panel (4.4.0): a POSIX sh script, run in a
terminal. ASCII, LF, a shebang, executable, shipped, and the same menu as
Launcher.bat. It runs on dash (Debian's /bin/sh) and bash."""

from tests import _env  # noqa: F401  (must be first)

import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest
import zipfile

from uptime_sync import paths, perms, updater

NAME = 'Launcher.sh'


def _read(name):
    with open(os.path.join(_env.REPO, name), 'rb') as f:
        return f.read()


def _shell(name):
    for d in ('/bin', '/usr/bin'):
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return p
    return None


class LauncherShFileTests(unittest.TestCase):
    def setUp(self):
        self.raw = _read(NAME)
        self.data = self.raw.decode('ascii')
        self.lines = [l.strip() for l in self.data.split('\n')]

    def test_ascii_lf_and_shebang(self):
        self.assertTrue(all(b < 128 for b in self.raw))
        self.assertNotIn(b'\r', self.raw)
        self.assertTrue(self.raw.startswith(b'#!/bin/sh\n'))
        self.assertIn(b'*.sh text eol=lf', _read('.gitattributes'))

    def test_shipped_executable_and_a_boot_file(self):
        self.assertIn(NAME, paths.SHIPPED)
        self.assertIn(NAME, paths.EXECUTABLE)
        # Like Launcher.bat it names a cut-off update, so it leaves last.
        self.assertIn(NAME, updater._BOOT)

    def test_committed_executable(self):
        try:
            out = subprocess.run(['git', 'ls-files', '-s', '--', NAME], cwd=_env.REPO,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30).stdout
        except (OSError, subprocess.TimeoutExpired):
            self.skipTest('no git')
        if not out.strip():
            self.skipTest('not a git checkout (or not added yet)')
        self.assertTrue(out.startswith(b'100755 '), out)

    def test_goes_to_its_own_folder(self):
        self.assertIn('HERE="$(cd "$(dirname "$0")" && pwd)" || exit 1', self.lines)
        self.assertIn('cd "$HERE" || exit 1', self.lines)

    def test_no_bashisms(self):
        # dash is /bin/sh on Debian and Ubuntu.
        code = '\n'.join(l for l in self.lines if not l.startswith('#'))
        for bad in ('[[', 'local ', 'declare ', 'read -p', 'read -n', 'mapfile', "$'", '${!', '<<<',
                    'function ', 'source ', ' == ', 'echo -e', '&>', 'pushd', '$RANDOM'):
            self.assertNotIn(bad, code, bad)

    def test_runs_main_py_in_the_venv(self):
        self.assertIn('PY="$HERE/.venv/bin/python"', self.lines)
        self.assertIn('"$PY" "$MAIN" "$@"', self.lines)

    def test_install_runs_main_py_on_the_system_python(self):
        i = self.lines.index('do_install() {')
        block = self.lines[i:self.lines.index('}', i)]
        self.assertIn('$ASROOT "$SYSPY" "$MAIN" install "$@"', block)
        self.assertFalse([l for l in block if '$PY' in l], 'install must not use .venv')
        i = self.lines.index('find_python() {')
        block = '\n'.join(self.lines[i:self.lines.index('}', i)])
        self.assertIn('sys.version_info >= (3, 8)', self.data)
        self.assertIn('"$CAND" -c "$CHECK"', block)
        self.assertIn('apt install python3 python3-venv', block)
        self.assertIn('dnf install python3', block)

    def test_same_menu_as_launcher_bat(self):
        bat = _read('Launcher.bat').decode('ascii')
        keys = set(re.findall(r'^echo {6}(\S)  ', bat, re.M))
        mine = set(re.findall(r"^ {4}say ' {5}(\S)  ", self.data, re.M))
        self.assertEqual(len(keys), 14)
        self.assertEqual(mine, keys)
        for key in keys:
            self.assertTrue(re.search(r'^ +%s(\|%s)?\)( |$)' % (re.escape(key), re.escape(key.lower())),
                                      self.data, re.M), key)

    def test_same_menu_as_launcher_command(self):
        def items(text):
            return re.findall(r"^ {4}say ' {5}(\S  .*)'$", text, re.M)
        self.assertEqual(items(self.data), items(_read('Launcher.command').decode('ascii')))

    def test_commands_exist_in_the_cli(self):
        from uptime_sync import cli
        subs = cli.build_parser()._uptime_subs
        found = re.findall(r'\brun(?:_root)? ([a-z][a-z-]+)', self.data)
        self.assertTrue(found)
        for name in found:
            self.assertIn(name, subs, name)

    def test_destructive_choices_ask_first(self):
        self.assertIn('if sure; then', self.data.split('R|r)', 1)[1].split(';;', 1)[0])
        self.assertIn('if sure; then', self.data.split('U|u)', 1)[1].split(';;', 1)[0])

    def test_names_a_cut_off_update(self):
        self.assertIn('if [ ! -f "$MAIN" ] || [ ! -f "$HERE/uptime_sync/__init__.py" ]; then', self.lines)
        self.assertIn('backups/v<version>-<date>', self.data)

    def test_readme_names_it(self):
        readme = _read('README.md').decode('utf-8')
        self.assertIn('Launcher.sh', readme)
        self.assertIn('chmod +x Launcher.sh', readme)


@unittest.skipIf(os.name == 'nt', 'a POSIX shell script')
class LauncherShRunTests(unittest.TestCase):
    """Run it for real in a folder with no .venv, from another cwd."""

    SHELLS = ('dash', 'bash')

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='uptime-sync-launcher-')
        self.folder = os.path.join(self.tmp, 'my install')
        os.makedirs(os.path.join(self.folder, 'uptime_sync'))
        shutil.copy(os.path.join(_env.REPO, NAME), self.folder)
        shutil.copy(os.path.join(_env.REPO, 'VERSION'), self.folder)
        for name in ('main.py', os.path.join('uptime_sync', '__init__.py')):
            with open(os.path.join(self.folder, name), 'w') as f:
                f.write('')
        self.bin = os.path.join(self.tmp, 'bin')
        os.makedirs(self.bin)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def launch(self, stdin, shell='bash', args=(), env=None):
        sh = _shell(shell)
        if not sh:
            self.skipTest('no %s' % shell)
        p = subprocess.run([sh, os.path.join(self.folder, NAME)] + list(args),
                           input=stdin.encode('ascii'), env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=self.tmp, timeout=30)
        return p.returncode, p.stdout.decode('ascii', 'replace')

    def stub(self, path, body):
        with open(path, 'w') as f:
            f.write('#!/bin/sh\n' + body + '\n')
        os.chmod(path, 0o755)

    def fake_world(self, scope=None):
        """A .venv python and a sudo that only say what they were asked,
        and data/autostart.json with the given systemd scope."""
        if os.geteuid() == 0:
            self.skipTest('root needs no sudo')
        os.makedirs(os.path.join(self.folder, '.venv', 'bin'), exist_ok=True)
        self.stub(os.path.join(self.folder, '.venv', 'bin', 'python'), 'echo "VENV $*"')
        self.stub(os.path.join(self.bin, 'sudo'), 'echo "SUDO $1"; exec "$@"')
        # A system python3 that passes the version check and echoes the rest.
        self.stub(os.path.join(self.bin, 'python3'),
                  'case "$1" in -c) case "$2" in *version_info*) exit 0 ;; esac; echo "[INFO] Python 3.x";'
                  ' exit 0 ;; esac; echo "SYSPY $*"')
        if scope is not None:
            os.makedirs(os.path.join(self.folder, 'data'), exist_ok=True)
            unit = ('/etc/systemd/system/uptime-sync.service' if not scope else
                    '/home/me/.config/systemd/user/uptime-sync.service')
            with open(os.path.join(self.folder, 'data', 'autostart.json'), 'w') as f:
                json.dump({'kind': 'systemd', 'name': 'uptime-sync', 'path': unit, 'scope': scope,
                           'note': ''}, f, indent=2)
        env = dict(os.environ)
        env['PATH'] = self.bin + os.pathsep + '/usr/bin:/bin'
        env.pop('DISPLAY', None)
        env.pop('WAYLAND_DISPLAY', None)
        return env

    def test_syntax(self):
        for shell in ('dash', 'bash', 'sh', 'zsh'):
            sh = _shell(shell)
            if sh:
                p = subprocess.run([sh, '-n', os.path.join(self.folder, NAME)], stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, timeout=30)
                self.assertEqual(p.returncode, 0, (shell, p.stdout))

    def test_menu_quits_and_says_not_installed(self):
        for shell in self.SHELLS:
            code, out = self.launch('1\n\nq\n', shell)
            self.assertEqual(code, 0, out)
            self.assertIn(self.folder, out)
            self.assertIn('Not installed yet', out)
            self.assertNotIn('an update was cut off', out)

    def test_end_of_input_and_empty_answers_quit(self):
        for shell in self.SHELLS:
            self.assertEqual(self.launch('', shell)[0], 0)
            code, out = self.launch('\n\n\n' + 'x\n' * 50, shell)
            self.assertEqual(code, 0)
            self.assertNotIn('Unknown choice', out)

    def test_copied_venv_and_missing_code_are_named(self):
        os.makedirs(os.path.join(self.folder, '.venv', 'bin'))
        with open(os.path.join(self.folder, '.venv', 'pyvenv.cfg'), 'w') as f:
            f.write('home = /opt/No Such Python/bin\n')
        os.remove(os.path.join(self.folder, 'main.py'))
        for shell in self.SHELLS:
            code, out = self.launch('2\n\nq\n', shell)
            self.assertIn('an update was cut off', out)
            self.assertIn('/opt/No Such Python/bin', out)
            self.assertIn('.venv does not work on this computer', out)

    def test_system_unit_starts_through_sudo(self):
        env = self.fake_world(scope=[])
        for shell in self.SHELLS:
            code, out = self.launch('1\n\n2\n\nq\n', shell, env=env)
            self.assertEqual(code, 0, out)
            self.assertIn('VENV %s status' % os.path.join(self.folder, 'main.py'), out)
            self.assertIn('systemd system unit', out)
            self.assertIn('SUDO %s' % os.path.join(self.folder, '.venv', 'bin', 'python'), out)
            self.assertIn('VENV %s start' % os.path.join(self.folder, 'main.py'), out)
            self.assertEqual(out.count('SUDO '), 1, out)

    def test_user_unit_starts_without_sudo(self):
        env = self.fake_world(scope=['--user'])
        for shell in self.SHELLS:
            code, out = self.launch('4\n\nq\n', shell, env=env)
            self.assertIn('VENV %s restart' % os.path.join(self.folder, 'main.py'), out)
            self.assertNotIn('SUDO', out)

    def test_install_uses_sudo_unless_a_user_unit(self):
        main = os.path.join(self.folder, 'main.py')
        env = self.fake_world()
        for shell in self.SHELLS:
            code, out = self.launch('', shell, ('install', '--no-autostart'), env)
            self.assertEqual(code, 0, out)
            self.assertIn('SUDO %s' % os.path.join(self.bin, 'python3'), out)
            self.assertIn('SYSPY %s install --no-autostart' % main, out)
            self.assertNotIn('VENV', out)
        env = self.fake_world(scope=['--user'])
        code, out = self.launch('', 'bash', ('install',), env)
        self.assertIn('repairing it as one', out)
        self.assertIn('SYSPY %s install' % main, out)
        self.assertNotIn('SUDO', out)

    def test_no_python_names_the_packages(self):
        for fixed in ('/usr/local/bin/python3', '/usr/bin/python3'):
            if os.path.exists(fixed):
                self.skipTest('%s is there' % fixed)
        # PATH holds only the tools the script needs, and no python3.
        for tool in ('dirname', 'id', 'sed', 'head'):
            os.symlink(shutil.which(tool), os.path.join(self.bin, tool))
        env = dict(os.environ)
        env['PATH'] = self.bin
        sh = _shell('bash')
        p = subprocess.run([sh, os.path.join(self.folder, NAME), 'install'], stdin=subprocess.DEVNULL,
                           env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        self.assertEqual(p.returncode, 1, p.stdout)
        self.assertIn(b'Python 3.8 or newer was not found', p.stdout)
        self.assertIn(b'apt install python3 python3-venv', p.stdout)

    def test_open_without_a_desktop_prints_the_address(self):
        env = self.fake_world(scope=['--user'])
        self.stub(os.path.join(self.bin, 'xdg-open'), 'echo XDG-OPEN "$@"')
        code, out = self.launch('5\n\nq\n', 'bash', env=env)
        self.assertIn('Open this address in a browser:  http://127.0.0.1:5000/', out)
        self.assertNotIn('XDG-OPEN', out)

    def test_open_on_a_desktop_uses_xdg_open(self):
        env = self.fake_world(scope=['--user'])
        mark = os.path.join(self.tmp, 'opened')
        self.stub(os.path.join(self.bin, 'xdg-open'), 'echo "$1" > "%s"' % mark)
        self.stub(os.path.join(self.folder, '.venv', 'bin', 'python'), 'echo "Web UI: http://box:5001/"')
        env['DISPLAY'] = ':0'
        code, out = self.launch('5\n\nq\n', 'bash', env=env)
        self.assertIn('Opening http://box:5001/', out)
        # xdg-open runs in the background; the script has exited by now,
        # but give the child a moment to write.
        for _ in range(50):
            if os.path.exists(mark):
                break
            time.sleep(0.1)
        with open(mark) as f:
            self.assertEqual(f.read().strip(), 'http://box:5001/')

    def test_bad_usage(self):
        code, out = self.launch('', 'bash', ('nonsense',))
        self.assertEqual(code, 2)
        self.assertIn('Usage:', out)


@unittest.skipIf(os.name == 'nt', 'POSIX modes')
class ExecBitTests(unittest.TestCase):
    """zipfile drops Unix modes; the launcher must come back executable."""

    def setUp(self):
        _env.reset()
        paths.ensure_dirs()

    def test_extract_keeps_the_x_bit(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            for name, mode in ((NAME, 0o755), ('main.py', 0o644)):
                info = zipfile.ZipInfo(name)
                info.external_attr = (0o100000 | mode) << 16
                z.writestr(info, '#!/bin/sh\n')
        zpath = os.path.join(paths.RUN_DIR, 'x.zip')
        with open(zpath, 'wb') as f:
            f.write(buf.getvalue())
        old = os.umask(0o077)
        try:
            updater._safe_extract(zpath, paths.STAGING_DIR)
        finally:
            os.umask(old)
        self.assertEqual(os.stat(os.path.join(paths.STAGING_DIR, NAME)).st_mode & 0o777, 0o700)

    def test_harden_puts_the_x_bit_back(self):
        target = os.path.join(paths.ROOT, NAME)
        with open(target, 'w') as f:
            f.write('#!/bin/sh\n')
        self.addCleanup(os.remove, target)
        os.chmod(target, 0o644)
        self.assertEqual(perms.harden(), [])
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o755)


if __name__ == '__main__':
    unittest.main()
