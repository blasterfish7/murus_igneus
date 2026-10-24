"""Local, bounded parental counters and DNS aggregates. SPDX-License-Identifier: MIT."""
from contextlib import closing
import csv
from datetime import datetime, timezone
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import threading
import time
try:
    from . import security
except ImportError:
    import security

LOCK = threading.RLock()
MAX_ROWS = 50000
RETENTION = 7 * 86400
STATUS = {'collecting': False, 'error': '', 'last_sample': None, 'discarded_dns': 0}


def entities(settings, interfaces):
    ports = {r['name']: r['device'] for r in interfaces}
    result = []
    for p in settings['profiles']:
        if not settings['enabled'] or not p['enabled']:
            continue
        identity = json.dumps([p['id'], p['interface'], p['clients']], sort_keys=True)
        for client in p['clients']:
            key = hashlib.sha256((identity + client).encode()).hexdigest()[:20]
            result.append({'entity': key, 'profile': p['id'], 'name': p['name'],
                           'client': client, 'device': ports[p['interface']]})
    return result


def counter(entity, direction):
    return 'pcr_' + entity['entity'] + '_' + direction


def rules(settings, interfaces):
    if not settings.get('reporting', False):
        return []
    rows = entities(settings, interfaces)
    if not rows:
        return []
    lines = ['add chain inet murus_igneus pc_report { type filter hook forward priority 20; policy accept; }']
    for row in rows:
        for direction in ('up', 'down', 'blocked'):
            lines.append('add counter inet murus_igneus ' + counter(row, direction))
        dev = json.dumps(row['device'])
        lines += [f'add rule inet murus_igneus pc_report iifname {dev} ip saddr {row["client"]} counter name {counter(row, "up")}',
                  f'add rule inet murus_igneus pc_report oifname {dev} ip daddr {row["client"]} counter name {counter(row, "down")}']
    return lines


def path(state):
    return Path(state) / 'logs' / 'parental.sqlite'


def connect(state):
    target = path(state); target.parent.mkdir(parents=True, exist_ok=True, mode=0o700); target.parent.chmod(0o700)
    fd = os.open(target, os.O_CREAT | os.O_RDWR, 0o600); os.close(fd); target.chmod(0o600)
    db = sqlite3.connect(target, timeout=3)
    db.execute('PRAGMA max_page_count=8192')  # At most 32 MiB with the default 4 KiB pages.
    db.execute('''CREATE TABLE IF NOT EXISTS samples (
        bucket INTEGER, entity TEXT, profile INTEGER, name TEXT, client TEXT, domain TEXT,
        up INTEGER DEFAULT 0, down INTEGER DEFAULT 0, packets INTEGER DEFAULT 0,
        blocked INTEGER DEFAULT 0, queries INTEGER DEFAULT 0, filtered INTEGER DEFAULT 0,
        PRIMARY KEY (bucket, entity, domain))''')
    return db


def prune(db, now):
    db.execute('DELETE FROM samples WHERE bucket < ?', (int(now - RETENTION),))
    db.execute('DELETE FROM samples WHERE rowid IN (SELECT rowid FROM samples ORDER BY bucket DESC, rowid DESC LIMIT -1 OFFSET ?)', (MAX_ROWS,))


def write(state, rows, now):
    with LOCK, closing(connect(state)) as db, db:
        for bucket, row, domain, values in rows:
            db.execute('''INSERT INTO samples VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(bucket,entity,domain) DO UPDATE SET
                up=up+excluded.up, down=down+excluded.down, packets=packets+excluded.packets,
                blocked=blocked+excluded.blocked, queries=queries+excluded.queries, filtered=filtered+excluded.filtered''',
                       (bucket, row['entity'], row['profile'], row['name'], row['client'], domain, *values))
        prune(db, now)


def decode_counters(raw):
    result = {}
    for item in json.loads(raw)['nftables']:
        c = item.get('counter', {})
        if c.get('name', '').startswith('pcr_') and c.get('table') == 'murus_igneus':
            result[c['name']] = (int(c['bytes']), int(c['packets']))
    return result


class Collector:
    def __init__(self, settings, interfaces, state):
        self.state = state; self.rows = entities(settings, interfaces); self.pending = {}; self.previous = {}
        self.lock = threading.RLock(); self.readers = []; self.halt = threading.Event(); self.thread = None
        self.previous = self.read_counters()  # New activation: never recount existing kernel totals.
        expected = {counter(r, d) for r in self.rows for d in ('up', 'down', 'blocked')}
        if not expected.issubset(self.previous):
            raise ValueError('Contatori parental assenti: reporting non avviato')
        self.networks = [(r, ipaddress.IPv4Network(r['client'])) for r in self.rows]
        with LOCK:
            STATUS.update(collecting=True, error='', discarded_dns=0, last_sample=None)

    def read_counters(self):
        return decode_counters(security.command(['nft', '-j', 'list', 'counters', 'table', 'inet', 'murus_igneus']))

    def spawn(self, profile, name, args):
        # No raw DNS logfile: drain the pipe continuously into bounded in-memory aggregates.
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, close_fds=True)
        security.PROCESSES[name] = process
        def read():
            pending = {}
            try:
                for raw in iter(lambda: process.stdout.readline(4096), b''):
                    self.dns_line(profile, raw.decode(errors='replace'), pending)
            finally:
                process.stdout.close()
        thread = threading.Thread(target=read, daemon=True, name='murus-parental-dns'); thread.start(); self.readers.append(thread)

    def dns_line(self, profile, line, pending, now=None):
        # dnsmasq log-queries=extra prefixes each event with serial and requester IP/port.
        match = re.search(r'(\d+) ([0-9.]+)/\d+ (query\[[A-Za-z0-9-]+\]|config) (\S+) (?:from \S+|is NXDOMAIN)\s*$', line)
        if not match:
            if 'log queue' in line.lower():
                with LOCK:
                    STATUS['error'] = 'dnsmasq segnala perdita di log DNS: riepilogo incompleto'
            return
        serial, source, action, domain = match.groups(); domain = domain.lower().rstrip('.')
        if len(domain) > 253 or not re.fullmatch(r'[a-z0-9_-]+(?:\.[a-z0-9_-]+)*', domain):
            return
        try:
            address = ipaddress.IPv4Address(source)
        except ValueError:
            return
        row = next((r for r, network in self.networks if r['profile'] == profile and address in network), None)
        if row is None:
            return
        key = (serial, source)
        query = action.startswith('query[')
        if query:
            if len(pending) >= 512:
                pending.clear()
            pending[key] = domain
        elif pending.pop(key, None) != domain:
            return
        stamp = time.time() if now is None else now
        aggregate = (int(stamp) // 3600 * 3600, row['entity'], domain)
        with self.lock:
            if aggregate not in self.pending and len(self.pending) >= 2048:
                with LOCK:
                    STATUS['discarded_dns'] += 1
                return
            value = self.pending.setdefault(aggregate, [row, 0, 0])
            value[1] += int(query); value[2] += int(not query)

    def collect(self, now=None):
        with self.lock:
            self._collect(now)

    def _collect(self, now=None):
        stamp = time.time() if now is None else now; bucket = int(stamp) // 3600 * 3600
        current = self.read_counters(); records = []
        for row in self.rows:
            totals = {}
            for direction in ('up', 'down', 'blocked'):
                name = counter(row, direction)
                if name not in current:
                    raise ValueError('Contatori parental assenti: campione non disponibile')
                value = current[name]; old = self.previous.get(name, value)
                totals[direction] = tuple(v - o if v >= o else v for v, o in zip(value, old))
            values = (totals['up'][0], totals['down'][0], totals['up'][1] + totals['down'][1], totals['blocked'][1], 0, 0)
            if any(values):
                records.append((bucket, row, '', values))
        with self.lock:
            dns = self.pending; self.pending = {}
        for (b, _, domain), (row, queries, filtered) in dns.items():
            records.append((b, row, domain, (0, 0, 0, 0, queries, filtered)))
        try:
            write(self.state, records, stamp)
        except Exception:
            with self.lock:
                # Keep a bounded retry buffer without double counting successful transactions.
                for key, (row, queries, filtered) in dns.items():
                    if key in self.pending:
                        self.pending[key][1] += queries; self.pending[key][2] += filtered
                    elif len(self.pending) < 2048:
                        self.pending[key] = [row, queries, filtered]
            raise
        self.previous = current
        with LOCK:
            STATUS['last_sample'] = stamp

    def start(self):
        def worker():
            while not self.halt.wait(10):
                try:
                    self.collect()
                except Exception as exc:
                    with LOCK:
                        STATUS['error'] = str(exc)[:300]
        self.thread = threading.Thread(target=worker, daemon=True, name='murus-parental-report'); self.thread.start()

    def stop(self):
        self.halt.set()
        if self.thread:
            self.thread.join(timeout=10)
        for thread in self.readers:
            thread.join(timeout=1)
        try:
            self.collect()
        except Exception:
            pass  # Reload may already have replaced the table; at most the last interval is lost.
        with LOCK:
            STATUS['collecting'] = False

    def clear(self):
        with self.lock:
            self.previous = self.read_counters(); self.pending.clear()
            erase(self.state)


def erase(state):
    with LOCK:
        if path(state).exists():
            with closing(connect(state)) as db:
                db.execute('DELETE FROM samples'); db.commit(); db.execute('VACUUM')


def report(state, days=7, now=None):
    if type(days) is not int or days not in (1, 7):
        raise ValueError('Periodo consentito: 1 o 7 giorni')
    stamp = time.time() if now is None else now; since = (int(stamp) - days * 86400) // 3600 * 3600
    with LOCK:
        status = dict(STATUS)
        if path(state).exists():
            with closing(connect(state)) as db, db:
                prune(db, stamp)
                data = db.execute('SELECT * FROM samples WHERE bucket >= ? AND bucket <= ? ORDER BY bucket', (since, stamp)).fetchall()
        else:
            data = []
    totals = {}; hourly = {}; domains = {}
    for b, entity, profile, name, client, domain, up, down, packets, blocked, queries, filtered in data:
        row = totals.setdefault(entity, {'entity': entity, 'profile': profile, 'name': name, 'client': client,
                                        'upload_bytes': 0, 'download_bytes': 0, 'packets': 0, 'blocked_packets': 0, 'dns_queries': 0, 'dns_filtered': 0})
        for key, value in zip(('upload_bytes', 'download_bytes', 'packets', 'blocked_packets', 'dns_queries', 'dns_filtered'), (up, down, packets, blocked, queries, filtered)):
            row[key] += value
        h = hourly.setdefault((b, entity), {'time': b, 'entity': entity, 'name': name, 'client': client, 'upload_bytes': 0, 'download_bytes': 0, 'blocked_packets': 0, 'dns_queries': 0, 'dns_filtered': 0})
        for key, value in zip(('upload_bytes', 'download_bytes', 'blocked_packets', 'dns_queries', 'dns_filtered'), (up, down, blocked, queries, filtered)):
            h[key] += value
        if domain:
            d = domains.setdefault((entity, domain), {'entity': entity, 'name': name, 'client': client, 'domain': domain, 'queries': 0, 'filtered': 0})
            d['queries'] += queries; d['filtered'] += filtered
    ranked = sorted(domains.values(), key=lambda r: (-r['queries'], r['domain']))
    return {**status, 'days': days, 'since': since, 'until': stamp, 'retention_days': 7, 'max_rows': MAX_ROWS,
            'devices': list(totals.values()), 'hourly': list(hourly.values()), 'domains': ranked[:100],
            'domains_truncated': len(ranked) > 100,
            'note': 'Byte IPv4 inoltrati dopo le policy (proxy HTTP locale escluso); non sono byte per sito. DNS = richieste al resolver, non pagine viste o tempo nelle app. Subnet aggregate. Campioni ogni 10 s, fasce UTC di un’ora; ultimo intervallo o log DNS possono andare persi. Massimo 7 giorni/50.000 righe/32 MiB: con molto traffico lo storico può essere più breve. Senza persistenza i report si perdono al riavvio.'}


def export_csv(data):
    output = io.StringIO(); writer = csv.writer(output)
    writer.writerow(['tipo', 'ora_utc', 'profilo', 'ip_o_subnet', 'dominio', 'upload_byte', 'download_byte', 'pacchetti_bloccati', 'richieste_dns', 'dns_filtrati'])
    def cell(value):
        value = str(value)
        return "'" + value if value.startswith(('=', '+', '-', '@', '\t', '\r', '\n')) else value
    for row in data['devices']:
        writer.writerow(['totale', '', cell(row['name']), row['client'], '', row['upload_bytes'], row['download_bytes'], row['blocked_packets'], row['dns_queries'], row['dns_filtered']])
    for row in data['hourly']:
        writer.writerow(['ora', datetime.fromtimestamp(row['time'], timezone.utc).isoformat(), cell(row['name']), row['client'], '', row['upload_bytes'], row['download_bytes'], row['blocked_packets'], row['dns_queries'], row['dns_filtered']])
    for row in data['domains']:
        writer.writerow(['dns_top100', '', cell(row['name']), row['client'], cell(row['domain']), '', '', '', row['queries'], row['filtered']])
    return output.getvalue()


def start_retention(state):
    def worker():
        while True:
            try:
                with LOCK:
                    if path(state).exists():
                        with closing(connect(state)) as db, db:
                            prune(db, time.time())
            except Exception as exc:
                with LOCK:
                    STATUS['error'] = str(exc)[:300]
            time.sleep(3600)
    threading.Thread(target=worker, daemon=True, name='murus-parental-retention').start()
