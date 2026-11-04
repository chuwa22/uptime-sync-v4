from tests import _env  # noqa: F401  (must be first)

import json
import os
import shutil
import tempfile
import unittest

from uptime_sync import importer, monitors, paths, settings
from uptime_sync.util import read_json

HASH = 'ab' * 16 + '$600000$' + 'cd' * 32


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(data if isinstance(data, str) else json.dumps(data))


class ImportTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        self.old = tempfile.mkdtemp(prefix='uptime-sync-3x-')
        write(os.path.join(self.old, 'VERSION'), '3.6.24\n')
        write(os.path.join(self.old, 'config', 'defaults.json'),
              {'service': {'check_interval': 30}, 'logging': {'level': 'INFO', 'retention_days': 7},
               'web': {'port': 5000}, 'remote_reporting': {'heartbeat_interval': 30,
                                                           'require_signed_response': 'auto'}})
        write(os.path.join(self.old, 'data', 'local.json'),
              {'web': {'site_name': 'Branch 7'},
               'remote_reporting': {'enabled': True, 'api_key': '', 'secret_key': 'OLDSECRET',
                                    'remote_url': 'https://mon.example.com/api/heartbeat.php'}})
        write(os.path.join(self.old, 'data', '.env'), 'UPTIME_API_KEY=envkey\nKUMA_GW=tok\n')
        write(os.path.join(self.old, 'data', 'monitors.json'), {'monitors': [
            {'id': 'gw', 'name': 'Gateway', 'type': 'PING', 'target': '10.0.0.1',
             'push_url': 'https://kuma/api/push/${KUMA_GW}', 'tags': ['x']},
            {'id': 'web', 'name': 'Web', 'type': 'HTTPS', 'target': 'example.com',
             'push_url': 'http://kuma/api/push/plain'}]})
        write(os.path.join(self.old, 'data', 'users.json'),
              {'admin': {'password': HASH}, 'bob': {'password': HASH, 'role': 'viewer'},
               'eve': {'password': HASH, 'role': 'superuser'}})
        write(os.path.join(self.old, 'data', 'response_signing.json'), {'fingerprint': 'f', 'since': 'x'})
        self.lines = []

    def tearDown(self):
        shutil.rmtree(self.old, ignore_errors=True)

    def run_import(self, **kw):
        return importer.run(self.old, out=self.lines.append, **kw)

    def test_dry_run_writes_nothing(self):
        self.assertEqual(self.run_import(dry_run=True), 0)
        self.assertFalse(os.path.exists(paths.SETTINGS_FILE))

    def test_import(self):
        self.assertEqual(self.run_import(), 0)
        s = settings.load()
        self.assertEqual(s['site_name'], 'Branch 7')
        self.assertEqual(s['check_interval'], 30)
        self.assertEqual(s['remote']['url'], 'https://mon.example.com/api/heartbeat.php')
        self.assertEqual(s['remote']['api_key'], 'envkey')          # from .env
        self.assertEqual(s['remote']['secret_key'], 'OLDSECRET')
        site = read_json(paths.SETTINGS_FILE, {})
        self.assertNotIn('api_key', site.get('remote', {}))           # .env-managed stays out
        mons = {m['id']: m for m in monitors.load()}
        self.assertEqual(mons['gw']['push_url'], 'https://kuma/api/push/${KUMA_GW}')
        users = read_json(paths.USERS_FILE, {})
        self.assertEqual({k: v['role'] for k, v in users.items()},
                         {'admin': 'admin', 'bob': 'viewer', 'eve': 'viewer'})
        self.assertEqual(users['admin']['password'], HASH)
        self.assertTrue(os.path.exists(paths.LATCH_FILE))
        out = '\n'.join(self.lines)
        self.assertNotIn('OLDSECRET', out)
        self.assertNotIn('envkey', out)
        self.assertIn('plain http', out)
        if os.name != 'nt':
            self.assertEqual(os.stat(paths.USERS_FILE).st_mode & 0o777, 0o600)

    def test_existing_data_is_kept_without_force(self):
        write(paths.MONITORS_FILE, {'monitors': []})
        self.run_import()
        self.assertEqual(monitors.load(), [])
        self.assertTrue(any('[SKIP] monitors' in line for line in self.lines))
        self.run_import(force=True)
        self.assertEqual(len(monitors.load()), 2)
        backups = [f for f in os.listdir(paths.DATA_DIR) if f.startswith('monitors.json.before-import-')]
        self.assertEqual(len(backups), 1)


if __name__ == '__main__':
    unittest.main()
