from tests import _env  # noqa: F401  (must be first)

import argparse
import contextlib
import io
import os
import shutil
import stat
import tempfile
import unittest
from unittest import mock

from uptime_sync import autostart, cli, paths, perms, settings


@unittest.skipIf(os.name == 'nt', 'POSIX modes')
class PosixPermsTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()

    def test_harden_fixes_hand_made_files(self):
        env = paths.ENV_FILE
        with open(env, 'w') as f:            # like `cp config/env.example data/.env`
            f.write('UPTIME_SECRET_KEY=x\n')
        os.chmod(env, 0o644)
        os.chmod(paths.DATA_DIR, 0o755)
        os.makedirs(os.path.join(paths.DATA_DIR, 'sub'))
        with open(os.path.join(paths.LOG_DIR, 'fallback-x.log'), 'w') as f:
            f.write('x')
        self.assertTrue(perms.check())
        self.assertEqual(perms.harden(), [])
        self.assertEqual(perms.check(), [])
        self.assertEqual(os.stat(env).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(paths.DATA_DIR).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(os.path.join(paths.DATA_DIR, 'sub')).st_mode & 0o777, 0o700)

    def test_settings_written_private(self):
        settings.update({'site_name': 'x'})
        self.assertEqual(os.stat(paths.SETTINGS_FILE).st_mode & 0o777, 0o600)


def _as_root(path):
    """os.lstat with the owner made root: the tests run as a user, and a
    real chown needs root."""
    st = os.lstat(path)
    return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, 0, 0,
                           st.st_size, int(st.st_atime), int(st.st_mtime), int(st.st_ctime)))


class RootReasonTests(unittest.TestCase):
    def test_reasons(self):
        r = perms.root_unsafe_reason
        d, f = stat.S_IFDIR, stat.S_IFREG
        self.assertEqual(r(d | 0o755, 0, 0), '')
        self.assertEqual(r(f | 0o644, 0, 0), '')
        self.assertTrue(r(f | 0o644, 501, 20).startswith('owned by '))
        self.assertEqual(r(f | 0o666, 0, 0), 'writable by everyone')
        self.assertEqual(r(d | 0o775, 0, 0), '')                 # root's own group
        self.assertTrue(r(d | 0o775, 0, 4242).startswith('writable by group '))
        self.assertEqual(r(stat.S_IFLNK | 0o777, 0, 0), '')      # its folder decides
        # /tmp: sticky, so others cannot rename root's folder inside it ...
        self.assertEqual(r(d | 0o1777, 0, 0, ancestor=True), '')
        # ... but anything inside the agent's own folders that others may write is out
        self.assertEqual(r(d | 0o1777, 0, 0), 'writable by everyone')
        self.assertTrue(r(d | 0o1777, 501, 20, ancestor=True).startswith('owned by '))

    def test_macos_admin_group_is_trusted(self):
        self.assertEqual(80 in perms.ROOT_GIDS, perms.sys.platform == 'darwin')

    def test_fix_lines(self):
        found = [('/opt/us4/uptime_sync', 'writable by everyone', 'folder'),
                 ('/opt/homebrew', 'owned by alice', 'python')]
        text = '\n'.join(perms.root_fix_lines(found, '/opt/us4'))
        self.assertIn('sudo chown -R root "/opt/us4" && sudo chmod -R go-w "/opt/us4"', text)
        self.assertIn('--recreate', text)
        self.assertIn('sudo python3 main.py install', text)   # or run as a user
        self.assertNotIn('/opt/uptime-sync', text)             # nothing found above the folder
        text = '\n'.join(perms.root_fix_lines([('/home/alice', 'owned by alice', 'above')], '/home/alice/us4'))
        self.assertIn('/opt/uptime-sync', text)
        self.assertNotIn('chown -R', text)
        self.assertNotIn('--recreate', text)


@unittest.skipIf(os.name == 'nt', 'POSIX modes')
class RootServiceScanTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        self.code = os.path.join(paths.ROOT, 'uptime_sync')
        os.makedirs(self.code)
        self.addCleanup(shutil.rmtree, self.code, True)
        p = mock.patch.object(perms, '_lstat', _as_root)
        p.start()
        self.addCleanup(p.stop)

    def test_root_owned_tree_is_clean(self):
        with open(os.path.join(self.code, 'a.py'), 'w') as f:
            f.write('x')
        os.chmod(os.path.join(self.code, 'a.py'), 0o644)
        self.assertEqual(perms.root_service_unsafe(), [])

    def test_lists_writable_paths_and_changes_nothing(self):
        bad = os.path.join(self.code, 'a.py')
        with open(bad, 'w') as f:
            f.write('x')
        os.chmod(bad, 0o666)
        sub = os.path.join(self.code, 'web')
        os.makedirs(os.path.join(sub, 'deep'))
        os.chmod(sub, 0o777)
        found = perms.root_service_unsafe()
        self.assertIn((bad, 'writable by everyone', 'folder'), found)
        self.assertIn((sub, 'writable by everyone', 'folder'), found)
        self.assertNotIn(os.path.join(sub, 'deep'), [p for p, _, _ in found])  # topmost only
        self.assertEqual(os.stat(bad).st_mode & 0o777, 0o666)                 # advice, no chmod
        self.assertEqual(os.stat(sub).st_mode & 0o777, 0o777)

    def test_base_python_and_owner(self):
        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home, True)
        os.chmod(home, 0o777)
        with mock.patch.object(perms, 'venv_base_home', return_value=home):
            found = perms.root_service_unsafe()
        self.assertIn((os.path.realpath(home), 'writable by everyone', 'python'), found)
        # Without the fake, the test user owns the temp folder: not root.
        with mock.patch.object(perms, '_lstat', os.lstat):
            found = perms.root_service_unsafe()
        self.assertIn(paths.ROOT, [p for p, _, _ in found])
        self.assertTrue(all(why.startswith('owned by ') for _, why, _ in found))

    def test_windows_has_its_own_check(self):
        with mock.patch.object(perms, 'IS_WINDOWS', True):
            self.assertEqual(perms.root_service_unsafe(), [])


@unittest.skipIf(os.name == 'nt', 'POSIX services')
class RootServiceTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)

    def _state(self, text, **state):
        path = os.path.join(self.dir, 'svc')
        with open(path, 'w') as f:
            f.write(text)
        state['path'] = path
        return state

    def test_systemd(self):
        runs = autostart.service_runs_as_root
        self.assertTrue(runs(self._state(autostart.systemd_unit('/p', '/r', 'root'), kind='systemd', scope=[])))
        self.assertTrue(runs(self._state(autostart.systemd_unit('/p', '/r', ''), kind='systemd', scope=[])))
        self.assertFalse(runs(self._state(autostart.systemd_unit('/p', '/r', 'alice'), kind='systemd', scope=[])))
        self.assertFalse(runs(self._state(autostart.systemd_unit('/p', '/r'), kind='systemd', scope=['--user'])))

    def test_launchd(self):
        runs = autostart.service_runs_as_root
        self.assertTrue(runs(self._state(autostart.launchd_plist('/p', '/r'), kind='launchd', domain='system')))
        self.assertFalse(runs(self._state(autostart.launchd_plist('/p', '/r', 'alice'), kind='launchd',
                                          domain='system')))
        self.assertFalse(runs(self._state(autostart.launchd_plist('/p', '/r'), kind='launchd', domain='gui/501')))

    def test_not_installed_or_unreadable(self):
        self.assertFalse(autostart.service_runs_as_root({}))
        self.assertFalse(autostart.service_runs_as_root({'kind': 'systemd', 'scope': [],
                                                         'path': os.path.join(self.dir, 'gone')}))

    def test_will_run_as_root(self):
        with mock.patch.object(autostart, 'is_admin', return_value=True):
            for sudo_user, want in (('', True), ('root', True), ('alice', False)):
                with mock.patch.dict(os.environ, {'SUDO_USER': sudo_user}):
                    self.assertEqual(autostart.will_run_as_root(), want, sudo_user)
        with mock.patch.object(autostart, 'is_admin', return_value=False), \
                mock.patch.dict(os.environ, {'SUDO_USER': ''}):
            self.assertFalse(autostart.will_run_as_root())

    def test_install_warns_and_status_reports(self):
        found = [('/opt/homebrew', 'owned by alice', 'python')]
        out = io.StringIO()
        with mock.patch.object(perms, 'root_service_unsafe', return_value=found), \
                contextlib.redirect_stdout(out):
            cli._warn_root_unsafe()
        text = out.getvalue()
        self.assertIn('[WARN] The agent will run as root', text)
        self.assertIn('/opt/homebrew (owned by alice)', text)
        self.assertIn('--recreate', text)
        self.assertIn('Nothing was changed.', text)
        text.encode('ascii')
        out = io.StringIO()
        with mock.patch.object(perms, 'root_service_unsafe', return_value=found), \
                mock.patch.object(autostart, 'service_runs_as_root', return_value=True), \
                mock.patch('uptime_sync.cli._running', return_value=(None, False)), \
                contextlib.redirect_stdout(out):
            cli.cmd_status(argparse.Namespace(json=False))
        self.assertIn('[SECURITY] the service runs as root, but other users can change: '
                      '/opt/homebrew (owned by alice)', out.getvalue())
        out = io.StringIO()
        with mock.patch.object(perms, 'root_service_unsafe', return_value=found), \
                contextlib.redirect_stdout(out):
            cli.cmd_status(argparse.Namespace(json=False))
        self.assertNotIn('runs as root', out.getvalue())     # not installed: no root service


class WindowsCommandTests(unittest.TestCase):
    def test_icacls_uses_sids_and_drops_inheritance(self):
        first, second = perms.icacls_commands(r'C:\US4\data', ('*S-1-5-21-1-2-3-1001',))
        self.assertEqual(first[:3], ['icacls', r'C:\US4\data', '/inheritance:r'])
        self.assertIn('*S-1-5-18:(OI)(CI)F', first)       # SYSTEM
        self.assertIn('*S-1-5-32-544:(OI)(CI)F', first)   # Administrators
        self.assertIn('*S-1-5-21-1-2-3-1001:(OI)(CI)F', first)
        self.assertNotIn('Users', ' '.join(first))
        self.assertIn('/reset', second)
        self.assertIn('/T', second)


if __name__ == '__main__':
    unittest.main()
