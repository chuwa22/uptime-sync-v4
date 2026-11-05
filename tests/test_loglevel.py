from tests import _env  # noqa: F401  (must be first)

import logging
import os
import re
import unittest
from unittest import mock

from uptime_sync import engine, log as logsetup, loglevel, paths, settings
from uptime_sync.util import atomic_write_json, read_json

PKG = os.path.join(_env.REPO, 'uptime_sync')


def _restore_loggers():
    loglevel.reset()
    logging.getLogger().setLevel(logging.WARNING)
    for part in loglevel.NAMES:
        logging.getLogger(part).setLevel(logging.NOTSET)
    for lib in loglevel.LIBRARIES:
        logging.getLogger(lib).setLevel(logging.NOTSET)


class Capture(logging.Handler):
    def __init__(self):
        logging.Handler.__init__(self)
        self.records = []

    def emit(self, record):
        self.records.append(record)


class LogLevelTests(unittest.TestCase):
    """loglevel.py: one global log_level, optional per-part log_levels,
    applied the same way in every process."""

    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        _restore_loggers()
        settings._warned.clear()

    def tearDown(self):
        _restore_loggers()

    def test_normalize(self):
        self.assertEqual(loglevel.normalize(' debug '), 'DEBUG')
        self.assertEqual(loglevel.normalize('warn'), 'WARNING')
        for bad in ('CRITICAL', 'loud', '', None, 10):
            self.assertIsNone(loglevel.normalize(bad), bad)

    def test_load_cleans_bad_values(self):
        atomic_write_json(paths.SETTINGS_FILE, {'log_level': 'loud', 'log_levels': {
            'checks': 'debug', 'nope': 'DEBUG', 'web': 'x', 'engine': ''}})
        with self.assertLogs('settings', 'WARNING') as cm:
            s = settings.load()
        self.assertEqual(s['log_level'], 'INFO')
        self.assertEqual(s['log_levels'], {'checks': 'DEBUG'})
        self.assertEqual(len(cm.output), 3)     # log_level, nope, web
        with self.assertRaises(AssertionError):  # warned once, not on every load
            with self.assertLogs('settings', 'WARNING'):
                settings.load()
        atomic_write_json(paths.SETTINGS_FILE, {'log_levels': 'DEBUG'})
        with self.assertLogs('settings', 'WARNING'):
            self.assertEqual(settings.load()['log_levels'], {})

    def test_apply_sets_root_parts_and_libraries(self):
        loglevel.apply({'log_level': 'WARNING', 'log_levels': {'checks': 'DEBUG'}})
        self.assertEqual(logging.getLogger().level, logging.WARNING)
        self.assertEqual(logging.getLogger('checks').getEffectiveLevel(), logging.DEBUG)
        self.assertEqual(logging.getLogger('engine').getEffectiveLevel(), logging.WARNING)
        self.assertEqual(logging.getLogger('urllib3').level, logging.WARNING)   # its own default
        loglevel.apply({'log_level': 'DEBUG', 'log_levels': {'libraries': 'ERROR'}})
        self.assertEqual(logging.getLogger('checks').getEffectiveLevel(), logging.DEBUG)
        self.assertEqual(logging.getLogger('checks').level, logging.NOTSET)     # override removed
        self.assertEqual(logging.getLogger('waitress').level, logging.ERROR)

    def test_a_part_below_the_global_level_reaches_the_handlers(self):
        cap = Capture()
        root = logging.getLogger()
        root.addHandler(cap)
        try:
            loglevel.apply({'log_level': 'ERROR', 'log_levels': {'checks': 'DEBUG'}})
            logging.getLogger('checks').debug('probe detail')
            logging.getLogger('engine').info('hidden')
        finally:
            root.removeHandler(cap)
        self.assertEqual([r.getMessage() for r in cap.records], ['probe detail'])

    def test_apply_logs_only_a_change(self):
        s = {'log_level': 'INFO', 'log_levels': {}}
        self.assertTrue(loglevel.apply(s))
        self.assertFalse(loglevel.apply(dict(s)))
        with self.assertLogs('log', 'INFO') as cm:
            loglevel.apply({'log_level': 'INFO', 'log_levels': {'web': 'DEBUG'}})
        self.assertIn('Log levels now INFO (web=DEBUG)', cm.output[0])

    def test_refresh_follows_the_settings_file(self):
        loglevel.apply(settings.load())
        loglevel.refresh(every=0)
        s = settings.load()
        s['log_levels'] = {'heartbeat': 'DEBUG'}
        settings.save(s)
        os.utime(paths.SETTINGS_FILE, (1, 1))   # a new mtime even within one clock tick
        self.assertTrue(loglevel.refresh(every=0))
        self.assertEqual(logging.getLogger('heartbeat').level, logging.DEBUG)
        self.assertFalse(loglevel.refresh(every=0))        # unchanged file: no reload
        with mock.patch.object(settings, 'load') as load:
            loglevel.refresh(every=3600)
            loglevel.refresh(every=3600)                  # throttled
        load.assert_not_called()

    def test_refresh_never_raises(self):
        with mock.patch.object(loglevel, '_files_stamp', side_effect=OSError('gone')):
            self.assertFalse(loglevel.refresh(every=0))

    def test_setup_applies_settings(self):
        root = logging.getLogger()
        saved = list(root.handlers)
        try:
            logsetup.setup('engine', {'log_level': 'ERROR', 'log_levels': {'update': 'DEBUG'}}, console=False)
            self.assertEqual(root.level, logging.ERROR)
            self.assertEqual(logging.getLogger('update').level, logging.DEBUG)
            logsetup.setup('engine', 'warning', console=False)    # a bare level still works
            self.assertEqual(root.level, logging.WARNING)
        finally:
            for h in list(root.handlers):
                root.removeHandler(h)
                h.close()
            for h in saved:
                root.addHandler(h)

    def test_cli_console_uses_the_same_levels(self):
        root = logging.getLogger()
        before = list(root.handlers)
        try:
            logsetup.setup_console({'log_level': 'INFO', 'log_levels': {'checks': 'DEBUG'}})
            logsetup.setup_console({'log_level': 'INFO'})
            added = [h for h in root.handlers if h not in before]
            self.assertEqual(len(added), 1)                 # one console handler, not one per call
            self.assertEqual(logging.getLogger('checks').level, logging.NOTSET)
        finally:
            for h in list(root.handlers):
                if h not in before:
                    root.removeHandler(h)

    def test_server_sets_the_global_level_and_keeps_parts(self):
        settings.update({'log_levels': {'checks': 'DEBUG'}})
        e = engine.Engine.__new__(engine.Engine)
        with self.assertLogs('engine', 'WARNING'):
            e._act_on({'settings': {'log_level': 'warn'}}, settings.load())
        site = read_json(paths.SETTINGS_FILE)
        self.assertEqual((site['log_level'], site['log_levels']), ('WARNING', {'checks': 'DEBUG'}))
        self.assertEqual(logging.getLogger().level, logging.WARNING)
        self.assertEqual(logging.getLogger('checks').level, logging.DEBUG)

    def test_every_logger_in_the_code_is_a_part(self):
        for dirpath, _, files in os.walk(PKG):
            for name in files:
                if name.endswith('.py'):
                    with open(os.path.join(dirpath, name), encoding='utf-8') as f:
                        for logger in re.findall(r"getLogger\('([^']+)'\)", f.read()):
                            self.assertTrue(logger in loglevel.NAMES or logger in loglevel.LIBRARIES,
                                            '%s: add %r to loglevel.COMPONENTS' % (name, logger))

    def test_no_other_list_of_levels(self):
        pattern = re.compile(r"""['"]DEBUG['"],\s*['"]INFO['"]""")
        for dirpath, _, files in os.walk(PKG):
            for name in files:
                if name.endswith(('.py', '.html')) and name != 'loglevel.py':
                    with open(os.path.join(dirpath, name), encoding='utf-8') as f:
                        self.assertIsNone(pattern.search(f.read()), '%s: use loglevel.LEVELS' % name)


if __name__ == '__main__':
    unittest.main()
