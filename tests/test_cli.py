from tests import _env  # must be first: it points UPTIME_SYNC_ROOT at a temp copy
_env  # imported for that alone; naming it keeps pyflakes quiet (it ignores noqa)

import contextlib
import io
import unittest
from unittest import mock

from uptime_sync import cli


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = cli.main(list(argv))
        except SystemExit as e:
            rc = e.code
    return rc, out.getvalue(), err.getvalue()


class HelpTests(unittest.TestCase):
    def test_every_way_of_asking_shows_the_grouped_list(self):
        for argv in (('help',), ('?',), ('-?',), ('/?',), ('-h',), ('--help',)):
            rc, out, _ = run(*argv)
            self.assertEqual(rc, 0, argv)
            for word in ('Run it', 'Set it up', 'Look at it', 'Examples', 'reset-password', 'logs'):
                self.assertIn(word, out, argv)

    def test_no_arguments_shows_the_list_and_fails(self):
        rc, out, _ = run()
        self.assertEqual(rc, 2)
        self.assertIn('Run it', out)

    def test_hidden_roles_never_listed(self):
        _, out, _ = run('help')
        self.assertNotIn('SUPPRESS', out)
        self.assertNotIn('  engine', out)
        self.assertNotIn('  web ', out)
        # ...but the supervisor can still start them
        self.assertIn('engine', cli.build_parser()._uptime_subs)

    def test_every_listed_command_exists_and_every_command_is_listed(self):
        subs = cli.build_parser()._uptime_subs
        listed = [n for _, names in cli.HELP_GROUPS for n in names]
        self.assertEqual(sorted(listed + list(cli.HIDDEN_COMMANDS)), sorted(subs))

    def test_help_for_one_command(self):
        for argv in (('help', 'logs'), ('logs', '--help')):
            rc, out, _ = run(*argv)
            self.assertEqual(rc, 0, argv)
            self.assertIn('usage: main.py logs', out, argv)
            self.assertIn('--grep TEXT', out, argv)
            self.assertIn('examples:', out, argv)
            self.assertNotIn('Look at it', out, argv)   # not the overview

    def test_unknown_command_suggests_the_closest(self):
        rc, _, err = run('lgos')
        self.assertEqual(rc, 2)
        self.assertIn('Did you mean "logs"?', err)
        rc, _, err = run('help', 'engine')
        self.assertEqual(rc, 2)
        self.assertIn('Unknown command "engine"', err)

    def test_bad_option_points_at_that_commands_help(self):
        rc, _, err = run('logs', '-n')
        self.assertEqual(rc, 2)
        self.assertIn('main.py help logs', err)

    @mock.patch('uptime_sync.cli.perms.return_to_sudo_user')
    @mock.patch('uptime_sync.cli.logsetup.setup_console')   # keeps the root logger untouched for other tests
    def test_version_flags(self, *_):
        for argv in (('version',), ('--version',), ('-version',), ('-v',), ('-V',), ('/version',)):
            rc, out, _ = run(*argv)
            self.assertEqual(rc, 0, argv)
            self.assertIn('Uptime Sync %s' % cli.__version__, out, argv)

    def test_dashed_command_names_work(self):
        for argv in (('-version',), ('--version',), ('/version',), ('-help',), ('--help',)):
            self.assertEqual(run(*argv)[0], 0, argv)
        with mock.patch('uptime_sync.cli.cmd_restart', return_value=0) as restart, \
                mock.patch('uptime_sync.cli.logsetup.setup_console'), \
                mock.patch('uptime_sync.cli.perms.return_to_sudo_user'):
            for argv in (('-restart',), ('--restart',), ('/restart',)):
                self.assertEqual(run(*argv)[0], 0, argv)
            self.assertEqual(restart.call_count, 3)

    def test_dashed_unknown_word_suggests_and_hidden_roles_stay_hidden(self):
        rc, _, err = run('-restrat')
        self.assertEqual(rc, 2)
        self.assertIn('Unknown command "-restrat". Did you mean "restart"?', err)
        rc, _, err = run('--engine')
        self.assertEqual(rc, 2)
        self.assertIn('Unknown command "--engine"', err)

    def test_options_work_with_dash_double_dash_or_slash(self):
        sp = cli.build_parser()._uptime_subs
        norm = cli._normalize_options
        want = ['-n', '50', '--level', 'WARNING', '--proc', 'engine', '--grep', 'x']
        for args in (['-n', '50', '--level', 'WARNING', '--proc', 'engine', '--grep', 'x'],
                     ['/n', '50', '/level', 'WARNING', '/proc', 'engine', '/grep', 'x'],
                     ['--n', '50', '-level', 'WARNING', '-proc', 'engine', '-grep', 'x']):
            self.assertEqual(norm(sp['logs'], args), want, args)
        self.assertEqual(norm(sp['logs'], ['/lines', '20']), ['--lines', '20'])
        self.assertEqual(norm(sp['logs'], ['/lines=20']), ['--lines=20'])
        self.assertEqual(norm(sp['status'], ['/json']), ['--json'])
        self.assertEqual(norm(sp['import'], ['/old', '-dry-run', '/force']), ['/old', '--dry-run', '--force'])
        self.assertEqual(norm(sp['install'], ['/no-autostart']), ['--no-autostart'])
        for h in ('/?', '-?', '?', '-h', '/h', '--help'):
            self.assertEqual(norm(sp['logs'], [h]), ['--help'], h)

    def test_values_and_paths_are_never_rewritten(self):
        sp = cli.build_parser()._uptime_subs
        norm = cli._normalize_options
        self.assertEqual(norm(sp['logs'], ['--grep', '/json']), ['--grep', '/json'])
        self.assertEqual(norm(sp['logs'], ['/grep', '-n']), ['--grep', '-n'])
        self.assertEqual(norm(sp['import'], ['/Users/me/Uptime Sync']), ['/Users/me/Uptime Sync'])
        self.assertEqual(norm(sp['import'], ['--', '/force']), ['--', '/force'])

    def test_help_topic_may_carry_a_prefix(self):
        for t in ('-logs', '--logs', '/logs'):
            rc, out, _ = run('help', t)
            self.assertEqual(rc, 0, t)
            self.assertIn('usage: main.py logs', out, t)

    def test_slash_options_reach_the_command(self):
        with mock.patch('uptime_sync.cli.cmd_logs', return_value=0) as logs, \
                mock.patch('uptime_sync.cli.logsetup.setup_console'), \
                mock.patch('uptime_sync.cli.perms.return_to_sudo_user'):
            self.assertEqual(run('/logs', '/n', '7', '/proc', 'engine', '-grep', 'push')[0], 0)
        a = logs.call_args[0][0]
        self.assertEqual((a.lines, a.proc, a.grep), (7, 'engine', 'push'))

    def test_output_is_ascii(self):
        _, out, _ = run('help')
        out.encode('ascii')
        for name in cli.build_parser()._uptime_subs:
            if name not in cli.HIDDEN_COMMANDS:
                run('help', name)[1].encode('ascii')


if __name__ == '__main__':
    unittest.main()


class StatusPythonTests(unittest.TestCase):
    """`main.py status` says which Python runs: this one, the .venv one the
    agent runs on, and the base install .venv was made from (4.0.13)."""

    def test_status_names_the_interpreters(self):
        import argparse
        import json
        import sys
        from uptime_sync import procs

        def status(as_json):
            # cmd_status itself: cli.main would also set up console logging.
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = cli.cmd_status(argparse.Namespace(json=as_json))
            return rc, out.getvalue()
        with mock.patch('uptime_sync.cli._running', return_value=(None, False)):
            rc, out = status(False)
            self.assertEqual(rc, 3)
            self.assertIn('  python      %s' % sys.executable, out)
            self.assertIn('  base        %s' % sys.base_prefix, out)
            self.assertIn('-bit)', out.splitlines()[0])
            rc, out = status(True)
        info = json.loads(out)
        self.assertEqual(info['python_exe'], sys.executable)
        self.assertEqual(info['agent_python'], procs.background_python())
        self.assertEqual(info['python_base'], sys.base_prefix)
        self.assertIn(info['python_bits'], (32, 64))
        self.assertIn('python', info)   # the 4.0.0 field stays
