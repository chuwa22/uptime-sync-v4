"""Log storage in SQLite (logs/logs.db), shared by all three processes.

Why SQLite: the Logs Center filters by level, process, time and text
without parsing files, and retention is one DELETE. sqlite3 is in the
stdlib on every Python we support, Windows 7 32-bit included.

Concurrency: WAL journal + busy_timeout, and each process writes from ONE
background thread in batches, so a caller of logging never waits on the
database lock. If the database cannot be written (locked for too long,
corrupt, disk full) the batch goes to logs/fallback-<date>.log instead --
the log must never be lost exactly when something is going wrong.

Self-healing: a corrupt logs.db ("database disk image is malformed", "file
is not a database") is moved aside as logs.db.corrupt-<ts> and a fresh one
is created -- by init_db(), by the writer thread and by prune() -- instead
of every line going to the fallback file forever. The file is also capped
at LOG_DB_MAX_BYTES: past it, prune() deletes the oldest rows down to
LOG_DB_TARGET_BYTES whatever their age, so a log storm cannot fill the disk.
"""

import datetime
import logging
import os
import queue
import sqlite3
import threading
import time

from . import loglevel, paths

DB_FILE = os.path.join(paths.LOG_DIR, 'logs.db')
LEVELS = loglevel.VALUES   # name -> number, for filtering
QUEUE_MAX = 20000
BATCH_MAX = 500
LOG_DB_MAX_BYTES = 200 * 1024 * 1024
LOG_DB_TARGET_BYTES = 150 * 1024 * 1024
CORRUPT_KEEP = 1               # quarantined copies kept (they can be large)
RECOVER_GAP_SECONDS = 600      # writer: at most one quarantine attempt per 10 min

SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id     INTEGER PRIMARY KEY,
    ts     REAL    NOT NULL,
    proc   TEXT    NOT NULL,
    level  INTEGER NOT NULL,
    logger TEXT    NOT NULL,
    msg    TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS logs_ts ON logs (ts);
CREATE INDEX IF NOT EXISTS logs_level_id ON logs (level, id);
CREATE INDEX IF NOT EXISTS logs_proc_id ON logs (proc, id);
DROP INDEX IF EXISTS logs_level_ts;
"""
_CORRUPT_MARKERS = ('malformed', 'not a database', 'file is encrypted')


def connect(timeout=5.0):
    os.makedirs(paths.LOG_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_FILE, timeout=timeout)
    conn.execute('PRAGMA busy_timeout=%d' % int(timeout * 1000))
    return conn


def is_corrupt_error(exc):
    return isinstance(exc, sqlite3.DatabaseError) and \
        any(m in str(exc).lower() for m in _CORRUPT_MARKERS)


def _init_db():
    # 30 s: three processes start together, and the first one to open a
    # database from before 4.0.8 builds the new indexes while holding the lock.
    conn = connect(timeout=30)
    try:
        # auto_vacuum must be chosen before the first table exists.
        conn.execute('PRAGMA auto_vacuum=INCREMENTAL')
        conn.execute('PRAGMA journal_mode=WAL')
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def init_db():
    """Create logs.db or bring its schema up to date; a corrupt file is
    quarantined and replaced by an empty one."""
    try:
        _init_db()
    except sqlite3.DatabaseError as e:
        if not is_corrupt_error(e) or not quarantine(str(e)):
            raise
        _init_db()


def quarantine(why=''):
    """Move a corrupt logs.db (+ its -wal/-shm) to logs.db.corrupt-<ts>.

    False when it cannot be moved -- on Windows another process still has
    it open; the caller tries again later. Never leaves the old -wal beside
    a new database: SQLite would replay its frames into the fresh file."""
    target = '%s.corrupt-%s' % (DB_FILE, time.strftime('%Y%m%d-%H%M%S'))
    try:
        os.replace(DB_FILE, target)
    except FileNotFoundError:
        pass     # another process got there first
    except OSError:
        return False
    for ext in ('-wal', '-shm'):
        try:
            os.replace(DB_FILE + ext, target + ext)
        except FileNotFoundError:
            pass
        except OSError:
            try:
                os.remove(DB_FILE + ext)
            except FileNotFoundError:
                pass
            except OSError:
                return False
    old = sorted(n for n in os.listdir(paths.LOG_DIR)
                 if n.startswith('logs.db.corrupt-') and not n.endswith(('-wal', '-shm')))
    for name in old[:-CORRUPT_KEEP]:
        for ext in ('', '-wal', '-shm'):
            try:
                os.remove(os.path.join(paths.LOG_DIR, name + ext))
            except OSError:
                pass
    write_fallback([(time.time(), 'log', logging.CRITICAL, 'log',
                     'logs.db was corrupt (%s); moved to %s, starting a new one'
                     % (why, os.path.basename(target)))], 'self-heal')
    return True


class SQLiteHandler(logging.Handler):
    def __init__(self, proc):
        super().__init__()
        self.proc = proc
        self.q = queue.Queue(QUEUE_MAX)
        self.dropped = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._writer, name='log-writer', daemon=True)
        self._thread.start()

    def emit(self, record):
        try:
            msg = record.getMessage()
            if record.exc_info:
                msg += '\n' + logging.Formatter().formatException(record.exc_info)
            self.q.put_nowait((record.created, self.proc, record.levelno, record.name, msg))
        except queue.Full:
            self.dropped += 1
        except Exception:
            self.handleError(record)

    def _drain(self, first=None):
        rows = [first] if first else []
        while len(rows) < BATCH_MAX:
            try:
                rows.append(self.q.get_nowait())
            except queue.Empty:
                break
        return rows

    def _writer(self):
        conn = None
        last_recover = None
        while True:
            try:
                first = self.q.get(timeout=0.5)
            except queue.Empty:
                if self._stop.is_set():
                    break
                continue
            rows = self._drain(first)
            if self.dropped:
                rows.append((time.time(), self.proc, logging.WARNING, 'log',
                             '%d log line(s) dropped: logging queue was full' % self.dropped))
                self.dropped = 0
            try:
                if conn is None:
                    conn = connect()
                with conn:
                    conn.executemany('INSERT INTO logs (ts, proc, level, logger, msg) '
                                     'VALUES (?, ?, ?, ?, ?)', rows)
            except Exception as e:
                write_fallback(rows, 'database write failed: %s' % e)
                try:
                    if conn is not None:
                        conn.close()
                except Exception:
                    pass
                conn = None
                now = time.monotonic()
                if is_corrupt_error(e) and (last_recover is None or
                                            now - last_recover > RECOVER_GAP_SECONDS):
                    last_recover = now
                    try:
                        init_db()   # quarantines the corrupt file and starts afresh
                    except Exception:
                        pass
                time.sleep(1)
        if conn is not None:
            conn.close()

    def close(self):
        self._stop.set()
        self._thread.join(10)
        rest = self._drain()
        if rest:
            write_fallback(rest, 'written at shutdown')
        super().close()


def _fmt(row):
    ts, proc, level, name, msg = row
    stamp = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    return '[%s] [%s] [%s/%s] %s' % (stamp, logging.getLevelName(level), proc, name, msg)


def write_fallback(rows, why):
    path = os.path.join(paths.LOG_DIR, 'fallback-%s.log' % datetime.date.today().isoformat())
    try:
        with open(path, 'a', encoding='utf-8', errors='replace') as f:
            f.write('# %s\n' % why)
            for row in rows:
                f.write(_fmt(row) + '\n')
    except OSError:
        pass


# -- reading (web UI, CLI) ---------------------------------------------------

def _index_for(min_level, proc):
    """Index that serves `ORDER BY id DESC` for this filter. WARNING+ rows are
    rare, so walking the primary key for them reads the whole table; the
    planner does not know that and has to be told."""
    if int(min_level) >= LEVELS['WARNING']:
        return 'logs_level_id'
    if proc:
        return 'logs_proc_id'
    return None


def query(min_level=0, proc='', text='', before_id=None, limit=200):
    """Newest-first rows as dicts. Read-only connection per call."""
    index = _index_for(min_level, proc)
    sql = 'SELECT id, ts, proc, level, logger, msg FROM logs%s WHERE level >= ?' % (
        ' INDEXED BY ' + index if index else '')
    args = [int(min_level)]
    if proc:
        sql += ' AND proc = ?'
        args.append(proc)
    if text:
        sql += " AND msg LIKE ? ESCAPE '\\'"
        args.append('%' + text.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%')
    if before_id:
        sql += ' AND id < ?'
        args.append(int(before_id))
    sql += ' ORDER BY id DESC LIMIT ?'
    args.append(max(1, min(int(limit), 1000)))
    if not os.path.exists(DB_FILE):
        return []
    conn = connect()
    try:
        try:
            rows = conn.execute(sql, args).fetchall()
        except sqlite3.OperationalError as e:
            if not index or 'no such index' not in str(e):
                raise
            rows = conn.execute(sql.replace(' INDEXED BY ' + index, ''), args).fetchall()
    except sqlite3.DatabaseError as e:
        if is_corrupt_error(e):
            return []    # the writer / engine quarantines it
        raise
    finally:
        conn.close()
    return [{'id': r[0], 'time': datetime.datetime.fromtimestamp(r[1]).strftime('%Y-%m-%d %H:%M:%S'),
             'proc': r[2], 'level': logging.getLevelName(r[3]), 'logger': r[4], 'msg': r[5]}
            for r in rows]


def _used_bytes(conn):
    """Bytes the rows occupy (pages in use; free pages do not count)."""
    pages = conn.execute('PRAGMA page_count').fetchone()[0]
    free = conn.execute('PRAGMA freelist_count').fetchone()[0]
    return (pages - free) * conn.execute('PRAGMA page_size').fetchone()[0]


def prune(retention_days, max_bytes=LOG_DB_MAX_BYTES, target_bytes=LOG_DB_TARGET_BYTES):
    """Delete rows older than retention_days, then the oldest rows while the
    database is over max_bytes (down to about target_bytes), and give the
    space back. A corrupt database is quarantined. Returns rows removed."""
    if not os.path.exists(DB_FILE):
        return 0
    cutoff = time.time() - max(1, int(retention_days)) * 86400
    try:
        conn = connect(timeout=30)
        try:
            with conn:
                n = conn.execute('DELETE FROM logs WHERE ts < ?', (cutoff,)).rowcount
            used = _used_bytes(conn)
            if used > max_bytes:
                rows = conn.execute('SELECT COUNT(*) FROM logs').fetchone()[0]
                drop = int(rows * (1.0 - float(target_bytes) / used)) + 1
                with conn:
                    n += conn.execute('DELETE FROM logs WHERE id <= (SELECT id FROM logs '
                                      'ORDER BY id LIMIT 1 OFFSET ?)', (max(0, drop - 1),)).rowcount
                logging.getLogger('log').warning(
                    'logs.db reached %d MB (cap %d MB) - removed the oldest %d line(s)',
                    used // (1024 * 1024), max_bytes // (1024 * 1024), drop)
            if n:
                # A PRAGMA that returns rows does its work only as they are
                # read: without fetchall() nothing is given back to the disk.
                conn.execute('PRAGMA incremental_vacuum').fetchall()
                conn.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchall()
            return n
        finally:
            conn.close()
    except sqlite3.DatabaseError as e:
        if not is_corrupt_error(e):
            raise
        quarantine(str(e))
        init_db()
        return 0


def stats():
    if not os.path.exists(DB_FILE):
        return {'rows': 0, 'bytes': 0}
    conn = connect()
    try:
        rows = conn.execute('SELECT COUNT(*) FROM logs').fetchone()[0]
    except sqlite3.DatabaseError:
        rows = 0
    finally:
        conn.close()
    size = sum(os.path.getsize(p) for p in (DB_FILE, DB_FILE + '-wal') if os.path.exists(p))
    return {'rows': rows, 'bytes': size}
