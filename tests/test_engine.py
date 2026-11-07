from tests import _env  # noqa: F401  (must be first)

import time
import unittest
from unittest import mock

from uptime_sync import engine, paths, updater

REPLY = {'update_available': True, 'latest_version': '99.0.0',
         'update_url': 'https://github.com/x/y/releases/download/v99.0.0/uptime-sync-v99.0.0.zip',
         'update_sha256': 'a' * 64}


class ConsiderUpdateTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        self.e = engine.Engine(supervised=True)
        self.e._start_mono = time.monotonic() - 3600     # past the grace period
        self.s = {'update': {'enabled': True}}

    def test_installs_when_auto(self):
        with mock.patch.object(self.e, '_start_install') as inst:
            self.e._consider_update(dict(REPLY), self.s)
        inst.assert_called_once()

    def test_failed_version_not_retried_unless_forced(self):
        updater.set_state(status='Failed', version='99.0.0', detail='rolled back')
        with mock.patch.object(self.e, '_start_install') as inst:
            self.e._consider_update(dict(REPLY), self.s)
            inst.assert_not_called()
            self.e._consider_update(dict(REPLY, force_install=True), self.s)
            inst.assert_called_once()

    def test_grace_manual_and_kill_switch(self):
        with mock.patch.object(self.e, '_start_install') as inst:
            self.e._consider_update(dict(REPLY), {'update': {'enabled': False}})
            self.e._consider_update(dict(REPLY, update_mode='manual'), self.s)
            self.assertEqual(updater.pending()['version'], '99.0.0')
            self.e._start_mono = time.monotonic()
            self.e._consider_update(dict(REPLY), self.s)
            inst.assert_not_called()

    def test_deferred_offer_logged_once(self):
        # The heartbeat repeats the offer every minute: INFO once, then DEBUG.
        reply = dict(REPLY, update_mode='scheduled', update_window={'start': '02:00', 'end': '04:00'})
        with mock.patch.object(updater, 'in_window', return_value=False), \
                mock.patch.object(self.e, '_start_install') as inst, \
                mock.patch.object(engine, 'log') as log:
            for _ in range(3):
                self.e._consider_update(dict(reply), self.s)
        inst.assert_not_called()
        self.assertEqual(log.info.call_count, 1)
        self.assertEqual(log.debug.call_count, 2)


if __name__ == '__main__':
    unittest.main()
