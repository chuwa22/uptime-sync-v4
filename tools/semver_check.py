"""Semantic Versioning for the VERSION file: MAJOR.MINOR.PATCH (since 4.0.13).

tools/build-release.py runs check() on the top block before it builds, so a
release cannot ship with the wrong number. Standard library only and no
side effects on import: the tests load this file directly.

    MAJOR  a break: heartbeat API_VERSION bump, a dropped OS or Python
           (the 3.8 floor, Windows 7), data an older version cannot read
           after a rollback, or an update that needs a step by hand.
           Label: "Breaking".
    MINOR  something new that stays compatible: a feature, a new setting or
           page, a behaviour change. Labels: Feature, New, Improvement, Change.
    PATCH  fixes only. Labels: Fix, Fixed, Security, Performance, Docs, Tests,
           Code.

Each top-level line of a block starts "- <Label> (<area>): ..." or
"- <Label>: ...". The label decides the smallest bump the block needs. The
number goes up by exactly one step from the previous block: 4.0.13 may be
followed by 4.0.14, 4.1.0 or 5.0.0, nothing else.
"""

import re

MAJOR_LABELS = ('Breaking',)
MINOR_LABELS = ('Feature', 'New', 'Improvement', 'Change')
PATCH_LABELS = ('Fix', 'Fixed', 'Security', 'Performance', 'Docs', 'Tests', 'Code')
LEVELS = ('PATCH', 'MINOR', 'MAJOR')

_VERSION_LINE = re.compile(r'^(\d+)\.(\d+)\.(\d+)$')
_DATE_LINE = re.compile(r'^\d{4}-\d{2}-\d{2}$')
_LABEL = re.compile(r'^- ([A-Za-z]+)\b')


def versions(text):
    """Every version heading in a VERSION file, newest first: a line that is
    exactly x.y.z with a YYYY-MM-DD line under it."""
    lines = [l.strip() for l in text.splitlines()]
    found = []
    for i, line in enumerate(lines[:-1]):
        m = _VERSION_LINE.match(line)
        if m and _DATE_LINE.match(lines[i + 1]):
            found.append(tuple(int(x) for x in m.groups()))
    return found


def labels(block):
    """The label of each top-level line ("- Label ...") of one block."""
    return [m.group(1) for m in (_LABEL.match(l) for l in block.splitlines()) if m]


def needed_level(block):
    """('PATCH'|'MINOR'|'MAJOR', [unknown labels]) for one block."""
    level, unknown = 'PATCH', []
    for name in labels(block):
        if name in MAJOR_LABELS:
            level = 'MAJOR'
        elif name in MINOR_LABELS:
            if level == 'PATCH':
                level = 'MINOR'
        elif name not in PATCH_LABELS:
            unknown.append(name)
    return level, unknown


def bump_level(new, old):
    """'MAJOR'|'MINOR'|'PATCH' for a one-step bump from old to new, else None."""
    if new == (old[0] + 1, 0, 0):
        return 'MAJOR'
    if new == (old[0], old[1] + 1, 0):
        return 'MINOR'
    if new == (old[0], old[1], old[2] + 1):
        return 'PATCH'
    return None


def fmt(v):
    return '%d.%d.%d' % v


def check(text):
    """Problems with the top block of a VERSION file, as a list of strings
    (empty = fine)."""
    found = versions(text)
    if not found:
        return ['VERSION has no "x.y.z" line followed by a "YYYY-MM-DD" line']
    new = found[0]
    block = text.strip().split('\n\n', 1)[0]
    level, unknown = needed_level(block)
    problems = []
    if unknown:
        problems.append('unknown label(s) %s; use one of: %s' % (
            ', '.join(sorted(set(unknown))), ', '.join(MAJOR_LABELS + MINOR_LABELS + PATCH_LABELS)))
    if len(found) < 2:
        return problems
    old = found[1]
    bump = bump_level(new, old)
    if bump is None:
        problems.append('%s does not follow %s: the next version is %s (PATCH), %s (MINOR) or %s (MAJOR)' % (
            fmt(new), fmt(old), fmt((old[0], old[1], old[2] + 1)), fmt((old[0], old[1] + 1, 0)),
            fmt((old[0] + 1, 0, 0))))
    elif LEVELS.index(bump) < LEVELS.index(level):
        want = (old[0] + 1, 0, 0) if level == 'MAJOR' else (old[0], old[1] + 1, 0)
        problems.append('%s is a %s release, but its notes need %s (%s): make it %s' % (
            fmt(new), bump, level, ', '.join(sorted(set(
                l for l in labels(block) if l in (MAJOR_LABELS if level == 'MAJOR' else MINOR_LABELS)))),
            fmt(want)))
    return problems
