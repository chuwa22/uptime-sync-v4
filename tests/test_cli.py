from tests import _env  # noqa: F401  (must be first)

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

    def test_output_is_ascii(self):
        _, out, _ = run('help')
        out.encode('ascii')
        for name in cli.build_parser()._uptime_subs:
            if name not in cli.HIDDEN_COMMANDS:
                run('help', name)[1].encode('ascii')


if __name__ == '__main__':
    unittest.main()
