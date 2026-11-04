from tests import _env  # noqa: F401  (must be first)

import os
import unittest

from uptime_sync import paths, perms, settings


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
