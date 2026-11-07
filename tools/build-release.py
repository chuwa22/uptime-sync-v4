#!/usr/bin/env python3
"""Build the release zip agents install -- no CI needed.

    python tools/build-release.py              # dist/uptime-sync-v<ver>.zip + .sha256
    python tools/build-release.py --publish    # ... and create GitHub release v<ver>
    python tools/build-release.py --allow-dirty

Only git-tracked files under paths.SHIPPED go in (the same tuple the
updater swaps), so data/, logs/, .venv/ and anything gitignored can never
ship; a regex block-list on top catches site files committed by mistake.
Files sit at the zip root: VERSION, main.py, uptime_sync/__init__.py --
what updater.validate_staging() requires.

Agents download from the GitHub release
    https://github.com/<repo>/releases/download/v<ver>/uptime-sync-v<ver>.zip
but only when uptime-monitor tells them to, with the SHA-256 in its signed
reply. The server reads that hash from the release's .sha256 asset, so the
.sha256 file is part of the release contract: "<64 hex>  <zip name>".
"""

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import zipfile

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
os.environ.pop('UPTIME_SYNC_ROOT', None)
from uptime_sync.paths import SHIPPED  # noqa: E402

FORBIDDEN = re.compile(
    r'(^|/)(data|logs|run|backups|update_staging|dist|\.venv[^/]*)(/|$)'
    r'|(^|/)\.env$|\.env\.[^/]*$(?<!\.example)'
    r'|(^|/)(settings|monitors|users|history|local|sessions|response_signing|update_state)\.json$'
    r'|(^|/)secret\.key$|\.db$|\.log$|\.pem$|\.pfx$|\.p12$'
    r'|__pycache__|\.pyc$|\.DS_Store$'
)
REQUIRED = ('VERSION', 'main.py', 'Launcher.bat', 'requirements.txt', 'uptime_sync/__init__.py',
            'uptime_sync/bootstrap.py',
            'config/defaults.json',
            'uptime_sync/supervisor.py', 'uptime_sync/updater.py')


def git(*args):
    return subprocess.check_output(('git',) + args, cwd=PROJECT_ROOT).decode('utf-8')


def top_version_block():
    with open(os.path.join(PROJECT_ROOT, 'VERSION'), 'r', encoding='utf-8') as f:
        block = f.read().split('\n\n', 1)[0].strip()
    return block.splitlines()[0].strip(), block


def main():
    ap = argparse.ArgumentParser(description='Build the Uptime Sync 4 release zip')
    ap.add_argument('--allow-dirty', action='store_true',
                    help='build even if shipped files have uncommitted changes')
    ap.add_argument('--publish', action='store_true',
                    help='also create GitHub release v<ver> with the zip and its .sha256 (needs gh)')
    args = ap.parse_args()
    if args.publish and args.allow_dirty:
        print('[ERROR] --publish cannot be combined with --allow-dirty: a release must match a commit')
        return 1

    version, notes = top_version_block()
    if not re.match(r'^\d+\.\d+\.\d+$', version):
        print('[ERROR] VERSION first line is not x.y.z: %r' % version)
        return 1

    dirty = git('status', '--porcelain', '--', *SHIPPED).strip()
    if dirty and not args.allow_dirty:
        print('[ERROR] Uncommitted changes in shipped files (commit first, or --allow-dirty):')
        print(dirty)
        return 1

    files = [f for f in git('ls-files', '--', *SHIPPED).splitlines() if f]
    blocked = [f for f in files if FORBIDDEN.search(f)]
    if blocked:
        print('[ERROR] Refusing to ship site data / secrets / build junk:')
        for f in blocked:
            print('  ' + f)
        return 1
    missing = [f for f in REQUIRED if f not in files]
    if missing:
        print('[ERROR] Not tracked, the updater would reject this zip: ' + ', '.join(missing))
        return 1
    gone = [f for f in files if not os.path.isfile(os.path.join(PROJECT_ROOT, f))]
    if gone:
        print('[ERROR] Tracked but missing on disk: ' + ', '.join(gone))
        return 1

    head = git('rev-parse', 'HEAD').strip()
    if args.publish:
        if not shutil.which('gh'):
            print('[ERROR] --publish needs the GitHub CLI (gh), logged in')
            return 1
        if not git('branch', '-r', '--contains', head).strip():
            print('[ERROR] HEAD is not on any remote branch -- git push first')
            return 1

    dist = os.path.join(PROJECT_ROOT, 'dist')
    os.makedirs(dist, exist_ok=True)
    name = 'uptime-sync-v%s.zip' % version
    zip_path = os.path.join(dist, name)
    with zipfile.ZipFile(zip_path + '.tmp', 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(files):
            zf.write(os.path.join(PROJECT_ROOT, f), arcname=f)
    os.replace(zip_path + '.tmp', zip_path)

    sha = hashlib.sha256()
    with open(zip_path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            sha.update(chunk)
    digest = sha.hexdigest()
    with open(zip_path + '.sha256', 'w', encoding='ascii', newline='\n') as f:
        f.write('%s  %s\n' % (digest, name))
    notes_path = os.path.join(dist, 'release-notes-v%s.md' % version)
    with open(notes_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(notes + '\n')

    print('[OK] %s: %d files, %d KB, from commit %s%s' % (
        name, len(files), os.path.getsize(zip_path) // 1024, head[:7],
        ' + uncommitted changes' if dirty else ''))
    print('[OK] SHA-256 ' + digest)
    if not args.publish:
        print('[INFO] Next: python tools/build-release.py --publish')
        return 0

    rc = subprocess.call(['gh', 'release', 'create', 'v' + version, zip_path, zip_path + '.sha256',
                          '--title', 'v' + version, '--notes-file', notes_path, '--target', head],
                         cwd=PROJECT_ROOT)
    if rc != 0:
        print('[ERROR] gh release create failed (exit %d) -- does tag v%s already exist?' % (rc, version))
        return 1
    print('[OK] Published GitHub release v' + version)
    print('[INFO] Next: set the v4 latest version to %s in uptime-monitor Update Manager.' % version)
    return 0


if __name__ == '__main__':
    sys.exit(main())
