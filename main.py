"""Uptime Sync 4 entry point. `python main.py` lists the commands."""

import sys

if sys.version_info < (3, 8):
    sys.stderr.write('Uptime Sync needs Python 3.8 or newer (this is %s)\n' % sys.version.split()[0])
    sys.exit(1)

from uptime_sync.cli import main  # noqa: E402

if __name__ == '__main__':
    sys.exit(main())
