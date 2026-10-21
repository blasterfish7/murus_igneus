"""Bounded persistent policy/DNAT history and management audit. SPDX-License-Identifier: MIT."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import threading
import time
try:
    from . import traffic
except ImportError:
    import traffic

ERROR = ''


def connect(state):
    root = Path(state) / 'logs'; root.mkdir(mode=0o700, parents=True, exist_ok=True); root.chmod(0o700)
    path = root / 'events.sqlite'
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600); os.close(fd); path.chmod(0o600)
    db = sqlite3.connect(path, timeout=3)
    db.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, time REAL NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL, fingerprint TEXT UNIQUE)')
    return db


def append(state, kind, detail, fingerprint=None):
    with closing(connect(state)) as db, db:
        db.execute('INSERT OR IGNORE INTO events(time,kind,detail,fingerprint) VALUES (?,?,?,?)',
                   (time.time(), kind, json.dumps(detail, ensure_ascii=False)[:6000], fingerprint))
        db.execute('DELETE FROM events WHERE time < ?', (time.time() - 30 * 86400,))
        db.execute('DELETE FROM events WHERE id <= COALESCE((SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET 19999),0) AND id != (SELECT max(id) FROM events)')


def history(state):
    with closing(connect(state)) as db, db:
        rows = db.execute('SELECT id,time,kind,detail FROM events ORDER BY id DESC LIMIT 1000').fetchall()
    return {'events': [{'id': r[0], 'time': r[1], 'kind': r[2], 'detail': json.loads(r[3])} for r in rows],
            'error': ERROR, 'retention_days': 30, 'max_events': 20000}


def collect(state):
    raw, _ = traffic.capture(['dmesg', '--color=never'], tail=True)
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    for row in traffic.events(raw):
        fingerprint = hashlib.sha256((boot + row['raw']).encode()).hexdigest()
        append(state, 'packet', row, fingerprint)


def start(state):
    def worker():
        global ERROR
        while True:
            try:
                collect(state); ERROR = ''
            except Exception as exc:
                ERROR = str(exc)[:300]
            time.sleep(5)
    threading.Thread(target=worker, daemon=True, name='murus-eventlog').start()
