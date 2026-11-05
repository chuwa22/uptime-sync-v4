"""Logging setup. Every process logs into logs/logs.db (see logstore.py);
plain-text files exist only as fallbacks:

    logs/fallback-<date>.log   lines the database could not take
    logs/<proc>-stderr.log     a child's stderr (crashes before logging starts)

Messages must be ASCII: the Windows console is cp1252 and pythonw has no
console at all, so a stray em-dash or emoji either raises or vanishes.
"""

import glob
import logging
import os
import sys
import time

from . import logstore, paths

FORMAT = '[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s'
DATEFMT = '%Y-%m-%d %H:%M:%S'
PROCS = ('supervisor', 'engine', 'web', 'cli')


def setup(proc, level='INFO', console=None):
    """Configure the root logger for process `proc` and return its logger."""
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
        h.close()
    root.addHandler(_store_handler(proc))
    if console is None:
        console = bool(sys.stdout) and hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
    if console:
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(logging.Formatter(FORMAT, DATEFMT))
        root.addHandler(sh)
    set_level(level)
    for noisy in ('urllib3', 'waitress', 'werkzeug'):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    def excepthook(kind, value, tb):
        logging.getLogger(proc).critical('Unhandled exception', exc_info=(kind, value, tb))
    sys.excepthook = excepthook
    return logging.getLogger(proc)


def _store_handler(proc):
    """logs.db; else the fallback text file; else stderr; else nothing.
    Never raises: a full or read-only disk must not stop the process that
    is supposed to report it."""
    try:
        logstore.init_db()
        return logstore.SQLiteHandler(proc)
    except Exception as e:
        logstore.write_fallback([(time.time(), proc, logging.ERROR, 'log',
                                  'cannot open logs.db, logging to this file: %s' % e)], 'setup')
    try:
        os.makedirs(paths.LOG_DIR, exist_ok=True)
        fh = logging.FileHandler(os.path.join(paths.LOG_DIR, 'fallback-%s.log' % time.strftime('%Y-%m-%d')),
                                 encoding='utf-8')
    except Exception:
        fh = logging.StreamHandler(sys.stderr) if sys.stderr else logging.NullHandler()
    fh.setFormatter(logging.Formatter(FORMAT, DATEFMT))
    return fh


def set_level(level):
    value = getattr(logging, str(level or 'INFO').upper(), None)
    logging.getLogger().setLevel(value if isinstance(value, int) else logging.INFO)


def prune(retention_days):
    """Apply retention to logs.db and the fallback text files."""
    removed = logstore.prune(retention_days)
    cutoff = time.time() - max(1, int(retention_days)) * 86400
    for path in glob.glob(os.path.join(paths.LOG_DIR, '*.log')):
        try:
            if os.path.getmtime(path) < cutoff:
                os.remove(path)
        except OSError:
            pass
    return removed


def text_files():
    """Fallback / stderr text files that are not empty: [(name, size, mtime)]."""
    out = []
    for path in glob.glob(os.path.join(paths.LOG_DIR, '*.log')):
        try:
            st = os.stat(path)
        except OSError:
            continue
        if st.st_size:
            out.append((os.path.basename(path), st.st_size, st.st_mtime))
    return sorted(out, key=lambda x: x[2], reverse=True)


def tail(name, lines=300):
    """Last lines of a text log in LOG_DIR; None if `name` is not one."""
    if os.path.basename(name) != name or not name.endswith('.log'):
        return None
    path = os.path.join(paths.LOG_DIR, name)
    if not os.path.isfile(path):
        return None
    with open(path, 'rb') as f:
        f.seek(0, os.SEEK_END)
        f.seek(max(0, f.tell() - 512 * 1024))
        data = f.read().decode('utf-8', errors='replace')
    return data.splitlines()[-lines:]
