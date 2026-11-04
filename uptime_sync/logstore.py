"""Log storage in SQLite (logs/logs.db), shared by all three processes.

Why SQLite: the Logs Center filters by level, process, time and text
without parsing files, and retention is one DELETE. sqlite3 is in the
stdlib on every Python we support, Windows 7 32-bit included.

Concurrency: WAL journal + busy_timeout, and each process writes from ONE
background thread in batches, so a caller of logging never waits on the
database lock. If the database cannot be written (locked for too long,
corrupt, disk full) the batch goes to logs/fallback-<date>.log instead --
the log must never be lost exactly when something is going wrong.
"""

import datetime
import logging
import os
import queue
import sqlite3
import threading
import time

from . import paths

DB_FILE = os.path.join(paths.LOG_DIR, 'logs.db')
LEVELS = {'DEBUG': 10, 'INFO': 20, 'WARNING': 30, 'ERROR': 40, 'CRITICAL': 50}
QUEUE_MAX = 20000
BATCH_MAX = 500

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
CREATE INDEX IF NOT EXISTS logs_level_ts ON logs (level, ts);
"""


def connect(timeout=5.0):
    os.makedirs(paths.LOG_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_FILE, timeout=timeout)
    conn.execute('PRAGMA busy_timeout=%d' % int(timeout * 1000))
    return conn


def init_db():
    conn = connect()
    try:
        # auto_vacuum must be chosen before the first table exists.
        conn.execute('PRAGMA auto_vacuum=INCREMENTAL')
        conn.execute('PRAGMA journal_mode=WAL')
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


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

def query(min_level=0, proc='', text='', before_id=None, limit=200):
    """Newest-first rows as dicts. Read-only connection per call."""
    sql = 'SELECT id, ts, proc, level, logger, msg FROM logs WHERE level >= ?'
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
        rows = conn.execute(sql, args).fetchall()
    finally:
        conn.close()
    return [{'id': r[0], 'time': datetime.datetime.fromtimestamp(r[1]).strftime('%Y-%m-%d %H:%M:%S'),
             'proc': r[2], 'level': logging.getLevelName(r[3]), 'logger': r[4], 'msg': r[5]}
            for r in rows]


def prune(retention_days):
    """Delete rows older than retention_days and give the space back."""
    if not os.path.exists(DB_FILE):
        return 0
    cutoff = time.time() - max(1, int(retention_days)) * 86400
    conn = connect(timeout=30)
    try:
        with conn:
            n = conn.execute('DELETE FROM logs WHERE ts < ?', (cutoff,)).rowcount
        if n:
            conn.execute('PRAGMA incremental_vacuum')
            conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        return n
    finally:
        conn.close()


def stats():
    if not os.path.exists(DB_FILE):
        return {'rows': 0, 'bytes': 0}
    conn = connect()
    try:
        rows = conn.execute('SELECT COUNT(*) FROM logs').fetchone()[0]
    finally:
        conn.close()
    size = sum(os.path.getsize(p) for p in (DB_FILE, DB_FILE + '-wal') if os.path.exists(p))
    return {'rows': rows, 'bytes': size}
