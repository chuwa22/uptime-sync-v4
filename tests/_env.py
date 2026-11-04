"""Import first in every test module: points UPTIME_SYNC_ROOT at a
throwaway copy so tests never touch this checkout's data/ or logs/."""

import os
import shutil
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if not os.environ.get('UPTIME_SYNC_TEST_ROOT'):
    root = tempfile.mkdtemp(prefix='uptime-sync-test-')
    shutil.copytree(os.path.join(REPO, 'config'), os.path.join(root, 'config'))
    shutil.copy(os.path.join(REPO, 'VERSION'), os.path.join(root, 'VERSION'))
    os.environ['UPTIME_SYNC_TEST_ROOT'] = root
ROOT = os.environ['UPTIME_SYNC_TEST_ROOT']
os.environ['UPTIME_SYNC_ROOT'] = ROOT
for name in ('UPTIME_API_KEY', 'UPTIME_SECRET_KEY', 'UPTIME_REMOTE_URL'):
    os.environ.pop(name, None)


def reset():
    """Empty data/, run/ and logs/ between tests."""
    for d in ('data', 'run', 'logs', 'backups', 'update_staging'):
        shutil.rmtree(os.path.join(ROOT, d), ignore_errors=True)
