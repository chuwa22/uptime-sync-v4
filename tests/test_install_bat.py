"""The .bat files must survive cmd.exe: ASCII only, CRLF line endings."""

import os
import unittest

from uptime_sync import paths

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(name):
    with open(os.path.join(HERE, name), 'rb') as f:
        return f.read()


class BatFilesTest(unittest.TestCase):
    NAMES = ('Launcher.bat',)

    def test_ascii(self):
        for name in self.NAMES:
            self.assertTrue(all(b < 128 for b in _read(name)), name)

    def test_crlf_only(self):
        for name in self.NAMES:
            data = _read(name)
            self.assertEqual(data.count(b'\n'), data.count(b'\r\n'), name)

    def test_shipped(self):
        for name in self.NAMES:
            self.assertIn(name, paths.SHIPPED)


class OldInstallerGoneTest(unittest.TestCase):
    def test_merged_into_launcher_and_bootstrap(self):
        for name in ('install.bat', 'install.py'):
            self.assertFalse(os.path.exists(os.path.join(HERE, name)), name)
            self.assertNotIn(name, paths.SHIPPED)


class LauncherBatTest(unittest.TestCase):
    def setUp(self):
        self.data = _read('Launcher.bat').decode('ascii')
        self.lines = [l.strip() for l in self.data.split('\r\n')]

    def test_runs_main_py_in_the_venv(self):
        self.assertIn('set "PY=%HERE%.venv\\Scripts\\python.exe"', self.data)
        self.assertIn('"%PY%" "%MAIN%" %*', self.data)

    def test_empty_answers_quit_instead_of_spinning(self):
        # set /p returns at once on a broken stdin; the 3.x Launcher spun at
        # full CPU there. The answer is reset before every prompt.
        i = self.lines.index('set /p "CHOICE=   Choose: "')
        self.assertEqual(self.lines[i - 1], 'set "CHOICE="')
        self.assertEqual(self.lines[i + 1:i + 5], ['if defined CHOICE goto chosen', 'set /a EMPTY+=1',
                                                   'if %EMPTY% geq 3 goto quit', 'goto menu'])

    def test_menu_starts_no_process(self):
        # Between :menu and the prompt only cmd built-ins run.
        start, end = self.lines.index(':menu'), self.lines.index('set /p "CHOICE=   Choose: "')
        builtins = ('echo', 'if', 'set', 'cls', 'title', 'rem', 'for')
        for line in self.lines[start + 1:end]:
            self.assertTrue(line.split(' ', 1)[0].split('.', 1)[0].lower() in builtins, line)

    def test_every_menu_target_exists(self):
        labels = set(l[1:] for l in self.lines if l.startswith(':') and not l.startswith('::'))
        for l in self.lines:
            if l.startswith('goto ') or ' goto ' in l:
                self.assertIn(l.split('goto ', 1)[1].split()[0], labels, l)
            if l.startswith('call :'):
                self.assertIn(l[6:].split()[0], labels, l)

    def test_copied_venv_is_spotted_and_sent_to_install(self):
        self.assertIn('if exist "%PY%" if defined VHOME if not exist "%VHOME%\\python.exe" set "BROKEN=1"',
                      self.data)
        run = self.lines.index(':run')
        self.assertIn('if defined BROKEN (', self.lines[run:run + 8])

    def test_uninstall_asks_first(self):
        i = self.lines.index(':do_uninstall')
        block = self.lines[i:self.lines.index('call :run uninstall')]
        self.assertIn('if /i not "%SURE%"=="YES" goto cancelled', block)

    def test_install_runs_main_py_on_the_system_python(self):
        # Never the .venv python: it may be missing, copied, or about to be
        # deleted by --recreate. bootstrap builds it, then hands over.
        i = self.lines.index(':install')
        block = self.lines[i:self.lines.index('exit /b %RC%', i)]
        self.assertIn('py -3 -c "%CHECK%" >nul 2>&1', block)
        self.assertIn('%SYSPY% "%MAIN%" install %*', block)
        self.assertFalse([l for l in block if '%PY%' in l], 'install must not use .venv')

    def test_direct_install_mode_survives_elevation(self):
        self.assertIn('if not defined MODE if not defined ARGS if /i "%~1"=="install" goto arg_install', self.lines)
        self.assertIn('if defined MODE set "PASS=/elevated install%ARGS%"', self.lines)
        self.assertIn("-ArgumentList '%PASS%' -Verb RunAs", self.data)
        i = self.lines.index(':admin')
        self.assertEqual(self.lines[i + 1:i + 4], ['if not defined MODE goto panel', 'title Uptime Sync 4 - install',
                                                   'call :install %ARGS%'])

    def test_rebuild_asks_first(self):
        i = self.lines.index(':do_rebuild')
        block = self.lines[i:self.lines.index('call :install --recreate')]
        self.assertIn('if /i not "%SURE%"=="YES" goto cancelled', block)

    def test_commands_exist_in_the_cli(self):
        from uptime_sync import cli
        subs = cli.build_parser()._uptime_subs
        for l in self.lines:
            if l.startswith('call :run '):
                self.assertIn(l.split()[2], subs, l)


if __name__ == '__main__':
    unittest.main()
