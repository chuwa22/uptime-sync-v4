"""`main.py install` on the system Python builds .venv first
(uptime_sync/bootstrap.py, the former install.py), then runs on .venv."""

from tests import _env  # noqa: F401  (must be first)

import argparse
import os
import runpy
import unittest
from unittest import mock

from uptime_sync import bootstrap, cli

MAIN = os.path.join(_env.REPO, 'main.py')


class RoutingTest(unittest.TestCase):
    def run_main(self, argv):
        env = dict(os.environ)
        env.pop('UPTIME_SYNC_REEXEC', None)
        env.pop(bootstrap.DONE_FLAG, None)
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch('sys.argv', ['main.py'] + argv), \
                mock.patch('uptime_sync.paths.in_venv', return_value=False), \
                mock.patch.object(bootstrap, 'prepare', return_value=7) as prepare:
            with self.assertRaises(SystemExit) as cm:
                runpy.run_path(MAIN, run_name='__main__')
        return cm.exception.code, prepare

    def test_install_outside_the_venv_runs_bootstrap_with_its_options(self):
        code, prepare = self.run_main(['install', '--recreate', '--no-autostart'])
        self.assertEqual(code, 7)                 # a failed .venv step stops here
        prepare.assert_called_once_with(['--recreate', '--no-autostart'])

    def test_dash_spellings_count(self):
        for word in ('-install', '/INSTALL'):
            code, prepare = self.run_main([word])
            self.assertEqual(code, 7, word)

    def test_bootstrap_parses_only_its_own_options(self):
        a = bootstrap.parse(['--wheels', 'w', '--no-autostart', '--recreate'])
        self.assertEqual((a.wheels, a.recreate), ('w', True))


class InstallGuardTest(unittest.TestCase):
    def args(self, **kw):
        base = dict(recreate=False, wheels=None, no_autostart=True)
        base.update(kw)
        return argparse.Namespace(**base)

    def test_recreate_on_the_venv_python_is_refused(self):
        # .venv's own python cannot delete and rebuild .venv.
        env = dict(os.environ)
        env.pop(bootstrap.DONE_FLAG, None)
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(cli, '_say') as say:
            self.assertEqual(cli.cmd_install(self.args(recreate=True)), 2)
            self.assertEqual(cli.cmd_install(self.args(wheels='C:\\w')), 2)
        self.assertIn('main.py install --recreate', ' '.join(c[0][0] for c in say.call_args_list))

    def test_parser_knows_the_bootstrap_options(self):
        a = cli.build_parser().parse_args(['install', '--recreate', '--wheels', 'w', '--no-autostart'])
        self.assertEqual((a.recreate, a.wheels, a.no_autostart), (True, 'w', True))


if __name__ == '__main__':
    unittest.main()
