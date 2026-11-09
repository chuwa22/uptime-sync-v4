from tests import _env  # noqa: F401  (must be first)

import importlib.util
import os
import unittest

_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools', 'semver_check.py')
_spec = importlib.util.spec_from_file_location('semver_check', _PATH)
semver_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(semver_check)


def version_file(top_version, *top_lines):
    """A VERSION text: a new block on top of 4.0.13 and 4.0.12."""
    top = '%s\n2026-11-09\n%s\n' % (top_version, '\n'.join(top_lines))
    return top + ('\n4.0.13\n2026-11-08\n- Feature (macOS): Launcher.command\n'
                  '  - Fixed in passing: an indented line is not a label\n'
                  '\n4.0.12\n2026-11-07\n- Improvement (Settings): Generate\n')


class SemverCheckTests(unittest.TestCase):
    """MAJOR.MINOR.PATCH: the release script refuses a top VERSION block whose
    number is not one step up, or too small a step for its labels."""

    def test_fixes_only_take_a_patch(self):
        self.assertEqual(semver_check.check(version_file('4.0.14', '- Fixed (engine): x', '- Security: y')), [])

    def test_a_feature_needs_minor(self):
        problems = semver_check.check(version_file('4.0.14', '- Fixed: x', '- Feature (web): y'))
        self.assertEqual(len(problems), 1)
        self.assertIn('make it 4.1.0', problems[0])
        for label in ('Improvement', 'New', 'Change'):
            self.assertTrue(semver_check.check(version_file('4.0.14', '- %s: y' % label)), label)
            self.assertEqual(semver_check.check(version_file('4.1.0', '- %s: y' % label)), [], label)

    def test_a_break_needs_major(self):
        problems = semver_check.check(version_file('4.1.0', '- Breaking (protocol): API_VERSION 2'))
        self.assertIn('make it 5.0.0', problems[0])
        self.assertEqual(semver_check.check(version_file('5.0.0', '- Breaking: x', '- Fixed: y')), [])

    def test_a_bigger_step_than_needed_is_fine(self):
        self.assertEqual(semver_check.check(version_file('4.1.0', '- Fixed: x')), [])

    def test_only_one_step_up(self):
        for bad in ('4.0.15', '4.0.13', '4.0.12', '4.1.1', '4.2.0', '5.1.0', '5.0.1', '3.9.9'):
            problems = semver_check.check(version_file(bad, '- Fixed: x'))
            self.assertEqual(len(problems), 1, bad)
            self.assertIn('4.0.14 (PATCH), 4.1.0 (MINOR) or 5.0.0 (MAJOR)', problems[0], bad)

    def test_unknown_label_is_named(self):
        problems = semver_check.check(version_file('4.0.14', '- Tweak: x'))
        self.assertIn('Tweak', problems[0])

    def test_indented_lines_and_older_blocks_are_not_checked(self):
        # 4.0.13 itself (a Feature in a PATCH) is history: only the top counts.
        self.assertEqual(semver_check.check(version_file('4.0.14', '- Fixed: x', '  - Feature: sub-point')), [])

    def test_the_real_history_parses(self):
        with open(os.path.join(os.path.dirname(_PATH), '..', 'VERSION'), encoding='utf-8') as f:
            found = semver_check.versions(f.read())
        self.assertGreater(len(found), 10)
        self.assertEqual(found, sorted(found, reverse=True))   # newest first, no repeats
        self.assertEqual(len(found), len(set(found)))

    def test_first_release_has_nothing_to_follow(self):
        self.assertEqual(semver_check.check('4.0.0\n2026-01-01\n- Feature: first\n'), [])
        self.assertTrue(semver_check.check('no version here\n'))
