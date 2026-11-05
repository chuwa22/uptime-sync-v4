"""requirements.txt stays in pip's hash-checking mode (4.0.9)."""

from tests import _env  # noqa: F401  (must be first)

import importlib.util
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _tool():
    spec = importlib.util.spec_from_file_location('pin_hashes', os.path.join(ROOT, 'tools', 'pin-hashes.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class RequirementsTests(unittest.TestCase):
    def setUp(self):
        _env.reset()
        with open(os.path.join(ROOT, 'requirements.txt'), encoding='ascii') as f:
            self.text = f.read()
        self.tool = _tool()

    def logical_lines(self):
        """pip's view: comments dropped, backslash continuations joined."""
        text = re.sub(r'(?m)^\s*#.*$', '', self.text).replace('\\\n', ' ')
        return [line.strip() for line in text.splitlines() if line.strip()]

    def test_every_requirement_is_pinned_and_hashed(self):
        lines = self.logical_lines()
        self.assertEqual(len(lines), len(self.tool.read_pins(self.text)))
        for line in lines:
            self.assertRegex(line, r'^[A-Za-z0-9._-]+==[0-9][^ ;]*(;[^-]+)?\s+--hash=sha256:[0-9a-f]{64}', line)
            for h in re.findall(r'--hash=(\S+)', line):
                self.assertRegex(h, r'^sha256:[0-9a-f]{64}$', line)

    def test_one_pin_per_package_and_python(self):
        seen = {}
        for name, version, marker in self.tool.read_pins(self.text):
            key = (self.tool.norm(name), marker)
            self.assertNotIn(key, seen, 'two pins for %s %s' % key)
            seen[key] = version

    def test_windows_needs_colorama(self):
        # click imports it on Windows: unpinned, hash mode refuses to install
        self.assertIn(('colorama', 'platform_system == "Windows"'),
                      [(self.tool.norm(n), m) for n, _, m in self.tool.read_pins(self.text)])


if __name__ == '__main__':
    unittest.main()
