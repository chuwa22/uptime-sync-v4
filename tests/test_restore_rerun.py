"""4.0.11 audit fixes: files that are not UTF-8 are healed instead of
stopping every process, and a restore (rollback / interrupted install) that
is cut off half-way can run again without deleting the install."""

from tests import _env  # noqa: F401  (must be first)

import codecs
import hashlib
import io
import logging
import os
import shutil
import unittest
import zipfile
from unittest import mock

from uptime_sync import paths, settings, updater, util
from tests.test_selfheal import _FakeInstall, read
from tests.test_updater import NEXT, REPO, FakeResponse, _read


def write_bytes(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(data)


def quiet(test, *names):
    for name in names:
        logger = logging.getLogger(name)
        test.addCleanup(setattr, logger, 'disabled', logger.disabled)
        logger.disabled = True


class EncodingTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        self.path = os.path.join(paths.DATA_DIR, 'thing.json')

    def test_invalid_utf8_is_quarantined_and_restored(self):
        util.atomic_write_json(self.path, {'v': 1}, backup=True)
        util.atomic_write_json(self.path, {'v': 2}, backup=True)   # .bak = v1
        write_bytes(self.path, b'{"site_name": "Caf\xe9"}')         # cp1252 hand edit
        with self.assertLogs('heal', 'CRITICAL') as cm:
            self.assertEqual(util.read_json(self.path, {}), {'v': 1})
        self.assertIn('restored', cm.output[0])
        self.assertEqual(len(util.corrupt_copies(self.path)), 1)

    def test_invalid_utf8_without_heal_is_the_default(self):
        write_bytes(self.path, b'\xff\xfe\xfa')
        self.assertEqual(util.read_json(self.path, {'d': 1}, heal=False), {'d': 1})
        self.assertTrue(os.path.exists(self.path))

    def test_utf16_with_bom_is_read(self):
        for bom, codec in ((codecs.BOM_UTF16_LE, 'utf-16-le'), (codecs.BOM_UTF16_BE, 'utf-16-be')):
            write_bytes(self.path, bom + '{"site_name": "\u0e44\u0e17\u0e22"}'.encode(codec))
            self.assertEqual(util.read_json(self.path, {}), {'site_name': '\u0e44\u0e17\u0e22'})
        self.assertEqual(util.corrupt_copies(self.path), [])

    def test_env_saved_as_ansi_still_loads(self):
        # Notepad "ANSI" on a Thai Windows: cp874 bytes in a comment.
        write_bytes(paths.ENV_FILE, b'# \xc3\xcB\xd1\xca\nUPTIME_API_KEY=key12345678\n')
        settings._env_warned.clear()
        with self.assertLogs('settings', 'WARNING') as cm:
            s = settings.load()
        self.assertEqual(s['remote']['api_key'], 'key12345678')
        self.assertIn('not UTF-8', cm.output[0])
        with mock.patch.object(settings.log, 'warning') as w:   # once per content
            settings.load()
        w.assert_not_called()

    def test_env_with_bom_and_an_ansi_byte_keeps_the_first_name(self):
        write_bytes(paths.ENV_FILE, codecs.BOM_UTF8 + b'UPTIME_API_KEY=key13572468\n# caf\xe9\n')
        quiet(self, 'settings')
        self.assertEqual(settings.load()['remote']['api_key'], 'key13572468')

    def test_env_saved_as_unicode_loads(self):
        write_bytes(paths.ENV_FILE, codecs.BOM_UTF16_LE + 'UPTIME_API_KEY=key87654321\r\n'.encode('utf-16-le'))
        self.assertEqual(settings.load()['remote']['api_key'], 'key87654321')

    def test_settings_json_with_bad_bytes_does_not_raise(self):
        write_bytes(paths.SETTINGS_FILE, b'{"site_name": "\xe9"}')
        quiet(self, 'heal')
        self.assertIsInstance(settings.load(), dict)


def zip_with(requirements):
    """make_zip(NEXT), but with a requirements.txt of its own."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        for name, data in {'VERSION': NEXT + '\n2026-01-01\n', 'main.py': '# new\n',
                           'uptime_sync/__init__.py': '# new\n',
                           'config/defaults.json': _read('config/defaults.json'),
                           'requirements.txt': requirements}.items():
            z.writestr(name, data)
    return buf.getvalue()


class RestoreRerunTests(_FakeInstall):
    """A restore writes its final state right after the swap and before pip,
    and a second run never moves the restored code out of ROOT."""

    def setUp(self):
        super().setUp()
        quiet(self, 'update')

    def stage_zip(self, data):
        with mock.patch.object(updater, '_open', return_value=FakeResponse(data)):
            updater.download_and_stage(updater.github_url(REPO, NEXT), NEXT,
                                       hashlib.sha256(data).hexdigest(), self.settings)

    def applied(self, new_requirements=True):
        req = _read('requirements.txt') + ('# changed\n' if new_requirements else '')
        self.stage_zip(zip_with(req))
        with mock.patch.object(updater, '_pip_install', return_value=(True, '')):
            self.assertEqual(updater.apply(), NEXT)
        self.assertEqual(read(os.path.join(paths.ROOT, 'main.py')), '# new\n')
        updater.set_state(crashes=3)
        return updater.state()['backup']

    def interrupted_install(self, requirements_changed=False):
        self.stage()
        with mock.patch.object(updater, '_smoke_test', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                updater.apply()
        updater.set_state(requirements_changed=requirements_changed)
        return updater.state()['backup']

    def fail_final_state(self):
        """set_state, except that writing the final 'Failed' record fails."""
        real = updater.set_state

        def flaky(**fields):
            if fields.get('status') == 'Failed':
                raise OSError(28, 'No space left on device')
            return real(**fields)
        return mock.patch.object(updater, 'set_state', flaky)

    def assert_cleaned(self, backup):
        self.assertFalse(os.path.exists(backup))
        left = [d for d in os.listdir(paths.BACKUP_DIR) if not d.startswith('v')]
        self.assertEqual(left, [])
        s = updater.state()
        self.assertEqual((s.get('leftovers'), s.get('pip_pending'), s.get('rolling_back')), ([], False, None))

    # -- rollback() ---------------------------------------------------------------

    def test_rollback_killed_during_pip_is_finished_not_repeated(self):
        backup = self.applied()
        with mock.patch.object(updater, '_pip_install', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                updater.rollback('crashed')
        self.assert_old_code()
        s = updater.state()
        self.assertEqual((s['status'], s['pip_pending'], s['backup']), ('Failed', True, ''))
        # next supervisor start: pip once more, folders cleaned, files untouched
        with mock.patch.object(updater, '_pip_install', return_value=(True, '')) as pip:
            self.assertFalse(updater.recover_interrupted())
            self.assertFalse(updater.recover_interrupted())
        self.assertEqual(pip.call_count, 1)
        self.assert_old_code()
        self.assert_cleaned(backup)

    def test_rollback_rerun_when_the_state_could_not_be_written(self):
        backup = self.applied()
        with self.fail_final_state(), \
                mock.patch.object(updater, '_pip_install', return_value=(True, '')):
            self.assertTrue(updater.rollback('crashed'))
        self.assertEqual(updater.state()['status'], 'Applied')   # not recorded
        self.assertTrue(os.path.isdir(backup))                    # so nothing was cleaned
        self.assert_old_code()
        with mock.patch.object(updater, '_pip_install', return_value=(True, '')):
            self.assertTrue(updater.rollback('crashed'))          # 4.0.10: ROOT emptied here
        self.assert_old_code()
        self.assertEqual(updater.state()['status'], 'Failed')     # the version is not retried
        self.assert_cleaned(backup)

    def test_rollback_killed_while_moving_back(self):
        backup = self.applied(new_requirements=False)
        real, calls = updater._move, []

        def partial(names, src, dst, done):
            calls.append(1)
            if len(calls) == 1:
                return real(names, src, dst, done)   # all new code out
            real(names[:1], src, dst, done)           # one old name back
            raise KeyboardInterrupt
        with mock.patch.object(updater, '_move', partial):
            with self.assertRaises(KeyboardInterrupt):
                updater.rollback('crashed')
        self.assertIn('rolling_back', updater.state())
        self.assertTrue(updater.rollback('crashed'))
        self.assert_old_code()
        self.assertEqual(updater.state()['status'], 'Failed')
        self.assert_cleaned(backup)

    def test_rollback_killed_while_moving_out(self):
        backup = self.applied(new_requirements=False)
        real = updater._move

        def partial(names, src, dst, done):
            real(names[:1], src, dst, done)
            raise KeyboardInterrupt
        with mock.patch.object(updater, '_move', partial):
            with self.assertRaises(KeyboardInterrupt):
                updater.rollback('crashed')
        self.assertTrue(updater.rollback('crashed'))
        self.assert_old_code()
        self.assert_cleaned(backup)

    def test_empty_backup_with_new_code_is_left_alone(self):
        backup = self.applied(new_requirements=False)
        shutil.rmtree(backup)                    # backup lost (deleted by hand)
        os.makedirs(backup)
        self.assertFalse(updater.rollback('crashed'))
        self.assertEqual(updater.state()['status'], 'RollbackFailed')
        self.assertEqual(read(os.path.join(paths.ROOT, 'main.py')), '# new\n')   # not deleted

    def test_stale_record_is_cleared_by_apply_and_ignored(self):
        stale = {'backup': os.path.join(paths.BACKUP_DIR, 'v-old'), 'out': [],
                 'trash': os.path.join(paths.BACKUP_DIR, 'failed-v-old'), 'back': ['main.py']}
        updater.set_state(status='RollbackFailed', rolling_back=stale, pip_pending=True, leftovers=[])
        backup = self.applied(new_requirements=False)
        s = updater.state()
        self.assertEqual((s['rolling_back'], s['pip_pending']), (None, False))
        updater.set_state(rolling_back=stale)    # one for another backup is never used
        self.assertTrue(updater.rollback('crashed'))
        self.assert_old_code()
        self.assertFalse(os.path.exists(stale['trash']))
        self.assert_cleaned(backup)

    # -- recover_interrupted() ----------------------------------------------------------

    def test_interrupted_install_restore_killed_during_pip(self):
        backup = self.interrupted_install(requirements_changed=True)
        with mock.patch.object(updater, '_pip_install', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                updater.recover_interrupted()
        self.assert_old_code()
        self.assertEqual(updater.state()['status'], 'Failed')
        with mock.patch.object(updater, '_pip_install', return_value=(True, '')):
            self.assertFalse(updater.recover_interrupted())
        self.assert_old_code()
        self.assert_cleaned(backup)
        self.assertFalse(os.path.exists(paths.STAGING_DIR))

    def test_interrupted_install_restore_rerun_without_state(self):
        backup = self.interrupted_install(requirements_changed=True)
        with self.fail_final_state(), \
                mock.patch.object(updater, '_pip_install', return_value=(True, '')):
            self.assertTrue(updater.recover_interrupted())
        self.assertEqual(updater.state()['status'], 'Applying')   # could not be recorded
        self.assert_old_code()
        with mock.patch.object(updater, '_pip_install', return_value=(True, '')):
            self.assertTrue(updater.recover_interrupted())         # 4.0.10: ROOT emptied here
        self.assert_old_code()
        self.assertEqual(updater.state()['status'], 'Failed')
        self.assert_cleaned(backup)

    def test_interrupted_install_restore_killed_while_moving_back(self):
        backup = self.interrupted_install()
        real, calls = updater._move, []

        def partial(names, src, dst, done):
            calls.append(1)
            if len(calls) == 1:
                return real(names, src, dst, done)   # new code out to the trash
            real(names[:2], src, dst, done)           # two old names back
            raise KeyboardInterrupt
        with mock.patch.object(updater, '_move', partial):
            with self.assertRaises(KeyboardInterrupt):
                updater.recover_interrupted()
        self.assertTrue(updater.recover_interrupted())
        self.assert_old_code()
        self.assertEqual(sorted(os.listdir(paths.ROOT)).count('uptime_sync'), 1)
        self.assert_cleaned(backup)



class BootOrderTests(_FakeInstall):
    """main.py and uptime_sync are out of ROOT for as few moves as possible:
    they leave last and come back first, in an update and in a rollback."""

    def setUp(self):
        super().setUp()
        quiet(self, 'update')

    stage_zip = RestoreRerunTests.stage_zip
    applied = RestoreRerunTests.applied

    def moves(self):
        real = os.replace
        seen = []

        def spy(src, dst):
            seen.append((src, dst))
            return real(src, dst)
        return seen, mock.patch('os.replace', spy)

    def check(self, seen):
        root = os.path.normcase(os.path.abspath(paths.ROOT))

        def parent(path):
            return os.path.normcase(os.path.dirname(os.path.abspath(path)))
        out = [os.path.basename(src) for src, dst in seen if parent(src) == root]
        came = [os.path.basename(dst) for src, dst in seen if parent(dst) == root]
        boot = [n for n in updater._BOOT if n in out]
        self.assertIn('main.py', boot)
        self.assertEqual(out[-len(boot):], boot)
        self.assertEqual(came[:len(boot)], list(reversed(boot)))

    def test_update_moves_boot_files_last_out_first_in(self):
        self.stage_zip(zip_with(_read('requirements.txt')))
        seen, spy = self.moves()
        with spy, mock.patch.object(updater, '_smoke_test', return_value=(True, '')):
            self.assertEqual(updater.apply(), NEXT)
        self.check(seen)

    def test_rollback_moves_boot_files_last_out_first_in(self):
        self.applied(new_requirements=False)
        seen, spy = self.moves()
        with spy:
            self.assertTrue(updater.rollback('test'))
        self.check(seen)
        self.assertEqual(read(os.path.join(paths.ROOT, 'main.py')), '# old\n')

    def test_launcher_names_a_cut_off_update(self):
        with open(os.path.join(_env.REPO, 'Launcher.bat'), 'rb') as f:
            bat = f.read().decode('ascii')
        self.assertIn('if not exist "%MAIN%" set "NOCODE=1"', bat)
        self.assertIn('backups\\', bat)
        # The Launcher itself must still be there in that state.
        names = sorted(paths.SHIPPED)
        self.assertEqual(updater._boot_last(names)[-3:], ['uptime_sync', 'main.py', 'Launcher.bat'])
        self.assertEqual(updater._boot_first(names)[:3], ['Launcher.bat', 'main.py', 'uptime_sync'])
        self.assertEqual(sorted(updater._boot_last(names)), names)


class VenvCfgEncodingTests(unittest.TestCase):
    def test_non_ascii_home_read_as_utf8(self):
        # venv writes pyvenv.cfg as UTF-8; a home with a Thai name must
        # still be found (it was read with the locale codec).
        _env.reset()
        home = os.path.join(paths.DATA_DIR, 'Python \u0e17\u0e14\u0e2a\u0e2d\u0e1a')
        os.makedirs(home)
        cfg = os.path.join(paths.VENV_DIR, 'pyvenv.cfg')
        self.addCleanup(shutil.rmtree, paths.VENV_DIR, True)
        write_bytes(cfg, ('home = %s\n' % home).encode('utf-8'))
        self.assertEqual(paths.venv_home_missing(), '')
        write_bytes(cfg, b'home = \xff\xfe broken\n')
        self.assertEqual(paths.venv_home_missing(), '')


if __name__ == '__main__':
    unittest.main()
