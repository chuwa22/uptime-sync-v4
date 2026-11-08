"""Launcher.command, the macOS control panel (4.0.13): a shell script that
Finder runs in Terminal. ASCII, LF, a shebang, executable, shipped, and the
same menu as Launcher.bat."""

from tests import _env  # noqa: F401  (must be first)

import io
import os
import re
import shutil
import subprocess
import tempfile
import unittest
import zipfile

from uptime_sync import paths, perms, updater

NAME = 'Launcher.command'


def _read(name):
    with open(os.path.join(_env.REPO, name), 'rb') as f:
        return f.read()


def _shell(name):
    for d in ('/bin', '/usr/bin'):
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return p
    return None


class LauncherCommandFileTests(unittest.TestCase):
    def setUp(self):
        self.raw = _read(NAME)
        self.data = self.raw.decode('ascii')
        self.lines = [l.strip() for l in self.data.split('\n')]

    def test_ascii_lf_and_shebang(self):
        self.assertTrue(all(b < 128 for b in self.raw))
        self.assertNotIn(b'\r', self.raw)
        self.assertTrue(self.raw.startswith(b'#!/bin/bash\n'))
        self.assertIn(b'*.command text eol=lf', _read('.gitattributes'))

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
        # Finder starts a .command file in the home folder.
        self.assertIn('HERE="$(cd "$(dirname "$0")" && pwd)" || exit 1', self.lines)
        self.assertIn('cd "$HERE" || exit 1', self.lines)

    def test_no_bashisms_that_break_bash32_or_zsh(self):
        code = '\n'.join(l for l in self.lines if not l.startswith('#'))
        for bad in ('[[', 'local ', 'declare ', 'read -p', 'read -n', 'mapfile', "$'", '${!', '<<<',
                    'function '):
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
        self.assertIn('python.org', block)
        self.assertIn('xcode-select --install', block)

    def test_same_menu_as_launcher_bat(self):
        bat = _read('Launcher.bat').decode('ascii')
        keys = set(re.findall(r'^echo {6}(\S)  ', bat, re.M))
        mine = set(re.findall(r"^ {4}say ' {5}(\S)  ", self.data, re.M))
        self.assertEqual(len(keys), 14)
        self.assertEqual(mine, keys)
        for key in keys:
            self.assertTrue(re.search(r'^ +%s(\|%s)?\)( |$)' % (re.escape(key), re.escape(key.lower())),
                                      self.data, re.M), key)

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

    def test_readme_explains_the_first_run(self):
        readme = _read('README.md').decode('utf-8')
        self.assertIn('Launcher.command', readme)
        self.assertIn('xattr -d com.apple.quarantine', readme)
        self.assertIn('chmod +x Launcher.command', readme)


@unittest.skipIf(os.name == 'nt', 'a POSIX shell script')
class LauncherCommandRunTests(unittest.TestCase):
    """Run it for real in a folder with no .venv, from another cwd."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='uptime-sync-launcher-')
        self.folder = os.path.join(self.tmp, 'my install')
        os.makedirs(os.path.join(self.folder, 'uptime_sync'))
        shutil.copy(os.path.join(_env.REPO, NAME), self.folder)
        shutil.copy(os.path.join(_env.REPO, 'VERSION'), self.folder)
        for name in ('main.py', os.path.join('uptime_sync', '__init__.py')):
            with open(os.path.join(self.folder, name), 'w') as f:
                f.write('')
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def launch(self, stdin, shell='bash'):
        sh = _shell(shell)
        if not sh:
            self.skipTest('no %s' % shell)
        p = subprocess.run([sh, os.path.join(self.folder, NAME)], input=stdin.encode('ascii'),
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=self.tmp, timeout=30)
        return p.returncode, p.stdout.decode('ascii', 'replace')

    def test_syntax(self):
        for shell in ('bash', 'zsh', 'sh'):
            sh = _shell(shell)
            if sh:
                p = subprocess.run([sh, '-n', os.path.join(self.folder, NAME)], stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, timeout=30)
                self.assertEqual(p.returncode, 0, (shell, p.stdout))

    def test_menu_quits_and_says_not_installed(self):
        for shell in ('bash', 'zsh'):
            code, out = self.launch('1\n\nq\n', shell)
            self.assertEqual(code, 0, out)
            self.assertIn(self.folder, out)
            self.assertIn('Not installed yet', out)
            self.assertNotIn('an update was cut off', out)

    def test_end_of_input_and_empty_answers_quit(self):
        self.assertEqual(self.launch('')[0], 0)
        code, out = self.launch('\n\n\n' + 'x\n' * 50)
        self.assertEqual(code, 0)
        self.assertNotIn('Unknown choice', out)

    def test_copied_venv_and_missing_code_are_named(self):
        os.makedirs(os.path.join(self.folder, '.venv', 'bin'))
        with open(os.path.join(self.folder, '.venv', 'pyvenv.cfg'), 'w') as f:
            f.write('home = /Library/Frameworks/No Such Python/bin\n')
        os.remove(os.path.join(self.folder, 'main.py'))
        code, out = self.launch('2\n\nq\n')
        self.assertIn('an update was cut off', out)
        self.assertIn('/Library/Frameworks/No Such Python/bin', out)
        self.assertIn('.venv does not work on this Mac', out)

    def test_bad_usage(self):
        sh = _shell('bash')
        p = subprocess.run([sh, os.path.join(self.folder, NAME), 'nonsense'], stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        self.assertEqual(p.returncode, 2)
        self.assertIn(b'Usage:', p.stdout)


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
                z.writestr(info, '#!/bin/bash\n')
        zpath = os.path.join(paths.RUN_DIR, 'x.zip')
        with open(zpath, 'wb') as f:
            f.write(buf.getvalue())
        old = os.umask(0o077)
        try:
            updater._safe_extract(zpath, paths.STAGING_DIR)
        finally:
            os.umask(old)
        self.assertEqual(os.stat(os.path.join(paths.STAGING_DIR, NAME)).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(os.path.join(paths.STAGING_DIR, 'main.py')).st_mode & 0o777, 0o600)

    def test_harden_puts_the_x_bit_back(self):
        target = os.path.join(paths.ROOT, NAME)
        with open(target, 'w') as f:
            f.write('#!/bin/bash\n')
        self.addCleanup(os.remove, target)
        os.chmod(target, 0o644)     # a 4.0.12 updater, or an unzip tool, did this
        self.assertEqual(perms.harden(), [])
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o755)
        os.chmod(target, 0o600)
        perms.harden()
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o700)

    def test_harden_without_the_launcher_is_quiet(self):
        self.assertFalse(os.path.exists(os.path.join(paths.ROOT, NAME)))
        self.assertEqual(perms.harden(), [])


if __name__ == '__main__':
    unittest.main()
