"""Keep requirements.txt in pip's hash-checking mode.

    python tools/pin-hashes.py           rewrite every pin's --hash lines from PyPI
    python tools/pin-hashes.py --check   verify the pins are a complete set

The hashes are the SHA-256 PyPI publishes for every file of each pinned
release (all wheels and the sdist), so any box can install whichever file
fits it. --check resolves requirements.txt with uv for each kind of box the
agent runs on and fails when the result has a package or version that is
not pinned here: in hash-checking mode pip refuses to install anything
unpinned, and a dependency needed only on one platform (colorama on
Windows) would otherwise be found only when that box updates.
"""

import json
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REQ = os.path.join(ROOT, 'requirements.txt')
PIN = re.compile(r'^([A-Za-z0-9][A-Za-z0-9._-]*)==([^;\s\\]+)\s*(?:;\s*([^\\]*?))?\s*\\?\s*$')
TARGETS = (    # (uv --python-platform, --python-version)
    ('i686-pc-windows-msvc', '3.8'),       # Windows 7 32-bit
    ('x86_64-pc-windows-msvc', '3.8'),
    ('x86_64-pc-windows-msvc', '3.12'),    # Windows 10/11
    ('x86_64-unknown-linux-gnu', '3.9'),
    ('x86_64-unknown-linux-gnu', '3.12'),
    ('aarch64-apple-darwin', '3.14'),
)


def norm(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def read_pins(text):
    """[(name, version, marker)] in file order."""
    out = []
    for line in text.splitlines():
        m = PIN.match(line.strip())
        if m:
            out.append((m.group(1), m.group(2), (m.group(3) or '').strip()))
    return out


def fetch_hashes(name, version):
    url = 'https://pypi.org/pypi/%s/%s/json' % (name, version)
    try:
        import requests
        data = requests.get(url, timeout=30).json()
    except ImportError:
        import ssl
        import urllib.request
        try:
            import certifi
            ctx = ssl.create_default_context(cafile=certifi.where())
        except ImportError:
            ctx = ssl.create_default_context()
        with urllib.request.urlopen(url, timeout=30, context=ctx) as r:
            data = json.loads(r.read().decode('utf-8'))
    hashes = sorted(set(f['digests']['sha256'] for f in data.get('urls', [])))
    if not hashes:
        raise SystemExit('[ERROR] PyPI lists no files for %s==%s' % (name, version))
    return hashes


def rewrite(text):
    lines, out = text.splitlines(), []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('--hash='):
            continue                       # replaced below
        m = PIN.match(stripped)
        if not m:
            out.append(line)
            continue
        name, version, marker = m.group(1), m.group(2), (m.group(3) or '').strip()
        hashes = fetch_hashes(name, version)
        out.append('%s==%s%s \\' % (name, version, '; ' + marker if marker else ''))
        for i, h in enumerate(hashes):
            out.append('    --hash=sha256:%s%s' % (h, ' \\' if i < len(hashes) - 1 else ''))
        print('[OK] %s==%s: %d file(s)' % (name, version, len(hashes)))
    return '\n'.join(out) + '\n'


def check(text):
    uv = shutil.which('uv')
    if not uv:
        print('[ERROR] --check needs uv (https://docs.astral.sh/uv/) to resolve for other platforms')
        return 2
    pins = set((norm(n), v) for n, v, _ in read_pins(text))
    unhashed = [n for n, v, _ in read_pins(text) if not _has_hash(text, n, v)]
    bad = 0
    if unhashed:
        print('[ERROR] pins without --hash lines: %s (run tools/pin-hashes.py)' % ', '.join(unhashed))
        bad += 1
    for platform, version in TARGETS:
        r = subprocess.run([uv, 'pip', 'compile', REQ, '--python-platform', platform, '--python-version',
                            version, '--no-header', '--no-annotate', '--quiet'],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        if r.returncode != 0:
            print('[ERROR] %s / %s does not resolve:\n%s' % (platform, version, r.stdout.strip()))
            bad += 1
            continue
        got = [(norm(n), v) for n, v, _ in read_pins(r.stdout)]
        missing = ['%s==%s' % p for p in got if p not in pins]
        if missing:
            print('[ERROR] %s / %s needs packages not pinned here: %s' % (platform, version, ', '.join(missing)))
            bad += 1
        else:
            print('[OK] %s / Python %s: %d packages, all pinned' % (platform, version, len(got)))
    return 1 if bad else 0


def _has_hash(text, name, version):
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = PIN.match(line.strip())
        if m and m.group(1) == name and m.group(2) == version:
            return i + 1 < len(lines) and lines[i + 1].strip().startswith('--hash=sha256:')
    return False


def main(argv):
    with open(REQ, encoding='utf-8') as f:
        text = f.read()
    if argv[1:] == ['--check']:
        return check(text)
    if argv[1:]:
        sys.stderr.write(__doc__)
        return 2
    new = rewrite(text)
    with open(REQ, 'w', encoding='ascii', newline='\n') as f:
        f.write(new)
    print('[OK] Wrote %s' % REQ)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
