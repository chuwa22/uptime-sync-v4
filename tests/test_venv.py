from tests import _env  # noqa: F401  (must be first)

import os
import subprocess
import sys
import unittest

from uptime_sync import paths, procs


class VenvTests(unittest.TestCase):
    def test_paths(self):
        self.assertEqual(paths.VENV_DIR, os.path.join(paths.ROOT, '.venv'))
        if os.name == 'nt':
            self.assertTrue(paths.venv_python(True).endswith(os.path.join('Scripts', 'pythonw.exe')))
        else:
            self.assertEqual(paths.venv_python(True), paths.venv_python())
        # the test interpreter is not <test root>/.venv
        self.assertFalse(paths.in_venv())

    def test_agent_never_uses_the_current_interpreter(self):
        self.assertTrue(procs.background_python().startswith(paths.VENV_DIR))

    def test_main_refuses_without_venv(self):
        import shutil
        import tempfile
        root = tempfile.mkdtemp(prefix='uptime-sync-novenv-')
        try:
            shutil.copy(os.path.join(_env.REPO, 'main.py'), root)
            shutil.copy(os.path.join(_env.REPO, 'VERSION'), root)
            shutil.copytree(os.path.join(_env.REPO, 'uptime_sync'), os.path.join(root, 'uptime_sync'))
            env = dict(os.environ)
            env.pop('UPTIME_SYNC_ROOT', None)       # main.py must find its own folder
            p = subprocess.run([sys.executable, os.path.join(root, 'main.py'), 'version'],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, timeout=60)
        finally:
            shutil.rmtree(root, ignore_errors=True)
        self.assertEqual(p.returncode, 1, p.stdout)
        self.assertIn(b'no .venv', p.stdout)
        self.assertIn(b'install.py', p.stdout)

if __name__ == '__main__':
    unittest.main()
