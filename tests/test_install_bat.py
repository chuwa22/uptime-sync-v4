"""install.bat must survive cmd.exe: ASCII only, CRLF line endings."""

import os
import unittest

from uptime_sync import paths

BAT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'install.bat')


class InstallBatTest(unittest.TestCase):
    def setUp(self):
        with open(BAT, 'rb') as f:
            self.data = f.read()

    def test_ascii(self):
        self.assertTrue(all(b < 128 for b in self.data))

    def test_crlf_only(self):
        self.assertEqual(self.data.count(b'\n'), self.data.count(b'\r\n'))

    def test_shipped(self):
        self.assertIn('install.bat', paths.SHIPPED)

    def test_runs_install_py(self):
        self.assertIn(b'install.py"%ARGS%', self.data)


if __name__ == '__main__':
    unittest.main()
