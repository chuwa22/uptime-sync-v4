from tests import _env  # noqa: F401  (must be first)

import hashlib
import io
import os
import unittest
import zipfile
from unittest import mock

from uptime_sync import __version__, paths, updater
from uptime_sync.updater import UpdateRefused

REPO = 'chuwa22/uptime-sync-v4'
SERVER = 'https://mon.example.com/api/heartbeat.php'
NEXT = '99.0.0'


class PolicyTests(unittest.TestCase):
    def test_github_exact_asset_only(self):
        url = updater.github_url(REPO, NEXT)
        self.assertEqual(updater.resolve(url, SERVER, REPO, NEXT), (url, 'github'))
        for bad in (url.replace(NEXT, '98.0.0'),
                    url.replace(REPO, 'evil/uptime-sync-v4'),
                    url.replace('https://', 'http://'),
                    url + '?x=1'):
            with self.assertRaises(UpdateRefused, msg=bad):
                updater.resolve(bad, SERVER, REPO, NEXT)

    def test_server_same_host_https(self):
        self.assertEqual(updater.resolve('/dist/download.php?v=1', SERVER, REPO, NEXT)[1], 'server')
        for bad in ('https://other.example.com/x.zip', 'http://mon.example.com/x.zip',
                    'https://user:pw@mon.example.com/x.zip', 'ftp://mon.example.com/x',
                    'https://mon.example.com/a b.zip', 'https://mon.example.com\\x.zip', ''):
            with self.assertRaises(UpdateRefused, msg=bad):
                updater.resolve(bad, SERVER, REPO, NEXT)

    def test_redirects(self):
        gh = updater.github_url(REPO, NEXT)
        ok = 'https://objects.githubusercontent.com/abc?sig=1'
        self.assertEqual(updater.check_redirect(ok, gh, 'github', SERVER), ok)
        for bad in ('https://evil.com/x', 'http://objects.githubusercontent.com/x',
                    'https://githubusercontent.com.evil.com/x'):
            with self.assertRaises(UpdateRefused, msg=bad):
                updater.check_redirect(bad, gh, 'github', SERVER)
        with self.assertRaises(UpdateRefused):
            updater.check_redirect('http://mon.example.com/x', SERVER, 'server', SERVER)

    def test_signed_url_has_no_secret(self):
        url = updater.signed_server_url('https://mon.example.com/d.php?v=1', 'KEY', 'SECRETVALUE')
        self.assertIn('api_key=KEY', url)
        self.assertNotIn('SECRETVALUE', url)


def _read(rel):
    with open(os.path.join(_env.REPO, rel)) as f:
        return f.read()


def make_zip(version, extra=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        for name, data in {'VERSION': version + '\n2026-01-01\n', 'main.py': '# new\n',
                           'uptime_sync/__init__.py': '# new\n',
                           'config/defaults.json': _read('config/defaults.json'),
                           'requirements.txt': _read('requirements.txt')}.items():
            z.writestr(name, data)
        for name, data in (extra or {}).items():
            z.writestr(name, data)
    return buf.getvalue()


class FakeResponse:
    def __init__(self, data):
        self.data = data

    def iter_content(self, n):
        for i in range(0, len(self.data), n):
            yield self.data[i:i + n]


class StageAndApplyTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        root = paths.ROOT
        # a fake "current install" to be swapped out
        os.makedirs(os.path.join(root, 'uptime_sync'), exist_ok=True)
        with open(os.path.join(root, 'uptime_sync', '__init__.py'), 'w') as f:
            f.write('# old\n')
        with open(os.path.join(root, 'main.py'), 'w') as f:
            f.write('# old\n')
        with open(os.path.join(root, 'requirements.txt'), 'w') as f:
            f.write(_read('requirements.txt'))
        self.settings = {'remote': {'url': SERVER, 'api_key': 'k', 'secret_key': 's'},
                         'update': {'github_repo': REPO}}
        # The fake build cannot really be imported; SmokeTests runs the real one.
        p = mock.patch.object(updater, '_smoke_test', return_value=(True, ''))
        p.start()
        self.addCleanup(p.stop)

    def tearDown(self):
        # put the real VERSION and config back for the other tests
        import shutil
        shutil.rmtree(os.path.join(paths.ROOT, 'config'), ignore_errors=True)
        shutil.copytree(os.path.join(_env.REPO, 'config'), os.path.join(paths.ROOT, 'config'))
        with open(os.path.join(paths.ROOT, 'VERSION'), 'w') as dst:
            dst.write(_read('VERSION'))

    def stage(self, data, sha=None, version=NEXT):
        sha = hashlib.sha256(data).hexdigest() if sha is None else sha
        with mock.patch.object(updater, '_open', return_value=FakeResponse(data)):
            return updater.download_and_stage(updater.github_url(REPO, version), version, sha,
                                              self.settings)

    def test_requires_sha(self):
        with self.assertRaises(UpdateRefused):
            self.stage(make_zip(NEXT), sha='')

    def test_sha_mismatch(self):
        with self.assertRaises(UpdateRefused):
            self.stage(make_zip(NEXT), sha='0' * 64)
        self.assertFalse(os.path.exists(paths.UPDATE_READY))

    def test_not_newer(self):
        with self.assertRaises(UpdateRefused):
            self.stage(make_zip(__version__), version=__version__)

    def test_zip_slip(self):
        with self.assertRaises(UpdateRefused):
            self.stage(make_zip(NEXT, extra={'../evil.txt': 'x'}))
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(paths.ROOT), 'evil.txt')))

    def test_wrong_version_inside(self):
        with self.assertRaises(UpdateRefused):
            self.stage(make_zip('98.0.0'))

    def test_apply_then_rollback(self):
        self.assertTrue(self.stage(make_zip(NEXT)))
        self.assertEqual(updater.apply(), NEXT)
        with open(os.path.join(paths.ROOT, 'main.py')) as f:
            self.assertEqual(f.read(), '# new\n')
        s = updater.state()
        self.assertEqual((s['status'], s['previous']), ('Applied', __version__))
        self.assertEqual(updater.heartbeat_fields()[0], 'Installing')
        self.assertTrue(os.path.isdir(s['backup']))
        self.assertTrue(updater.rollback('test'))
        with open(os.path.join(paths.ROOT, 'main.py')) as f:
            self.assertEqual(f.read(), '# old\n')
        self.assertEqual(updater.state()['status'], 'Failed')

    def test_data_untouched(self):
        with open(os.path.join(paths.DATA_DIR, 'monitors.json'), 'w') as f:
            f.write('{"monitors": []}')
        self.stage(make_zip(NEXT, extra={'data/monitors.json': 'PWNED'}))
        updater.apply()
        with open(os.path.join(paths.DATA_DIR, 'monitors.json')) as f:
            self.assertEqual(f.read(), '{"monitors": []}')


    def _old(self):
        with open(os.path.join(paths.ROOT, 'main.py')) as f, \
                open(os.path.join(paths.ROOT, 'uptime_sync', '__init__.py')) as g:
            return f.read(), g.read()

    def test_code_that_cannot_start_is_put_back(self):
        self.stage(make_zip(NEXT))
        with mock.patch.object(updater, '_smoke_test', return_value=(False, 'ImportError: x')):
            self.assertIsNone(updater.apply())
        self.assertEqual(self._old(), ('# old\n', '# old\n'))
        s = updater.state()
        self.assertEqual(s['status'], 'Failed')
        self.assertIn('does not start', s['detail'])
        # no empty backup folder left to count towards KEEP_BACKUPS, no bad staging
        self.assertEqual(os.listdir(paths.BACKUP_DIR), [])
        self.assertFalse(os.path.exists(paths.STAGING_DIR))

    def test_swap_failing_half_way_is_undone(self):
        self.stage(make_zip(NEXT))
        real = os.replace

        def flaky(src, dst):
            # moving the new main.py in fails (a file held open by AV, say)
            if src.startswith(paths.STAGING_DIR) and dst == os.path.join(paths.ROOT, 'main.py'):
                raise PermissionError(13, 'in use')
            return real(src, dst)
        with mock.patch.object(updater.os, 'replace', side_effect=flaky):
            self.assertIsNone(updater.apply())
        self.assertEqual(self._old(), ('# old\n', '# old\n'))
        self.assertIn('swap failed', updater.state()['detail'])
        self.assertEqual(os.listdir(paths.BACKUP_DIR), [])

    def test_rollback_without_backup_stops_retrying(self):
        updater.set_state(status='Applied', version=NEXT, previous=__version__, backup='', crashes=3)
        self.assertFalse(updater.rollback('test'))
        self.assertEqual(updater.state()['status'], 'RollbackFailed')
        self.assertEqual(updater.heartbeat_fields()[0], 'Failed')
        from uptime_sync import supervisor
        self.assertFalse(supervisor.Supervisor()._check_rollback_needed())   # no loop

    def test_bad_version_never_staged(self):
        for bad in ('99.0.0/../../x', '99.0.0-evil', ' 99.0.0', 'v99.0.0'):
            with self.assertRaises(UpdateRefused, msg=bad):
                self.stage(make_zip(NEXT), version=bad)


class SmokeTests(unittest.TestCase):
    def test_real_code_imports(self):
        with mock.patch.object(paths, 'ROOT', _env.REPO):
            self.assertEqual(updater._smoke_test(__version__), (True, ''))
            ok, detail = updater._smoke_test('99.0.0')
        self.assertFalse(ok)
        self.assertIn('reports version', detail)

if __name__ == '__main__':
    unittest.main()
