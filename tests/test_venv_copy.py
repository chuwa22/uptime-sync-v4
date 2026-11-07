"""A .venv copied from another machine (the folder synced Mac -> Windows)
points at that machine's Python and fails before any Python code runs.
It must be named as such, and `main.py install` (uptime_sync/bootstrap.py)
must be able to rebuild it even with the agent still running from it."""

from tests import _env  # noqa: F401  (must be first)

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from uptime_sync import bootstrap, paths, procs


class VenvCopyTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        paths.ensure_dirs()
        shutil.rmtree(paths.VENV_DIR, ignore_errors=True)
        self.addCleanup(shutil.rmtree, paths.VENV_DIR, True)

    def cfg(self, home):
        os.makedirs(paths.VENV_DIR, exist_ok=True)
        with open(os.path.join(paths.VENV_DIR, 'pyvenv.cfg'), 'w') as f:
            f.write('home = %s\ninclude-system-site-packages = false\nversion = 3.12.4\n' % home)

    def test_home_missing(self):
        self.assertEqual(paths.venv_home_missing(), '')                 # no .venv at all
        here = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, here, True)
        self.cfg(here)
        self.assertEqual(paths.venv_home_missing(), '')                 # home exists here
        mac = '/Library/Frameworks/Python.framework/Versions/3.14/bin-not-here'
        self.cfg(mac)
        self.assertEqual(paths.venv_home_missing(), mac)
        self.cfg(r'C:\Users\x\AppData\Local\Programs\Python\Python312-not-here')
        self.assertTrue(paths.venv_home_missing().endswith('Python312-not-here'))

    def test_main_py_names_the_copied_venv(self):
        py = paths.venv_python()
        os.makedirs(os.path.dirname(py), exist_ok=True)
        open(py, 'w').close()
        self.cfg('/nowhere/python-from-another-machine')
        env = dict(os.environ, UPTIME_SYNC_ROOT=paths.ROOT)
        env.pop('UPTIME_SYNC_REEXEC', None)
        r = subprocess.run([sys.executable, os.path.join(_env.REPO, 'main.py'), 'status'], env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, timeout=60)
        self.assertEqual(r.returncode, 1)
        self.assertIn('.venv was made on another machine', r.stdout)
        self.assertIn('/nowhere/python-from-another-machine', r.stdout)
        self.assertIn('main.py install', r.stdout)

    def test_install_stops_an_agent_that_runs_from_a_broken_venv(self):
        with mock.patch('time.sleep'):
            self.assertTrue(bootstrap.stop_agent(timeout=5))
        self.assertTrue(os.path.exists(paths.STOPPED_FLAG))      # `main.py install` -> start clears it
        self.assertFalse(os.path.exists(paths.SHUTDOWN_FLAG))
        with mock.patch.object(procs.InstanceLock, 'held_by_other', return_value=True):
            self.assertFalse(bootstrap.stop_agent(timeout=0.2))
        self.assertTrue(os.path.exists(paths.SHUTDOWN_FLAG))     # still asked to stop


if __name__ == '__main__':
    unittest.main()
