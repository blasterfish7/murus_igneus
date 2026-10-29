"""Bounded, read-only connection and policy event snapshots. SPDX-License-Identifier: MIT."""
import re
from pathlib import Path
import subprocess
import tempfile
import time

MAX_BYTES = 262144
MAX_ROWS = 500


def capture(args, tail=False):
    # Kernel output can be large. Spool to a temporary file, cap the API response,
    # and never accept command arguments from a request.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
        result = subprocess.run(args, stdout=output, stderr=error, timeout=5)
        size = output.tell()
        output.seek(max(0, size - MAX_BYTES) if tail else 0); data = output.read(MAX_BYTES + 1)
        error.seek(0); detail = error.read(1000).decode(errors='replace')
    if result.returncode:
        raise ValueError(detail.strip() or 'Telemetria non disponibile')
    if tail and size > MAX_BYTES:
        data = data.split(b'\n', 1)[-1]
    return data[:MAX_BYTES].decode(errors='replace'), size > MAX_BYTES


def connections(text):
    rows = []
    for line in text.splitlines():
        words = line.split()
        # -o extended starts with "ipv4 2 tcp 6 timeout ...".
        protocol = next((v for v in words[:5] if v in ('tcp', 'udp', 'icmp')), None)
        if not protocol:
            continue
        pairs = re.findall(r'\b(src|dst|sport|dport|bytes|packets)=(\S+)', line)
        values = {}
        for key, value in pairs:
            values.setdefault(key, []).append(value)
        if len(values.get('src', [])) < 2 or len(values.get('dst', [])) < 2:
            continue
        row = {'protocol': protocol, 'source': values['src'][0], 'destination': values['dst'][0],
               'reply_source': values['src'][1], 'reply_destination': values['dst'][1],
               'state': next((v for v in words if v in ('ESTABLISHED', 'SYN_SENT', 'SYN_RECV', 'TIME_WAIT', 'CLOSE', 'CLOSE_WAIT', 'FIN_WAIT', 'LAST_ACK')), 'UNREPLIED' if '[UNREPLIED]' in words else 'TRACKED')}
        for key in ('sport', 'dport', 'bytes', 'packets'):
            row[key] = values.get(key, [''])[0]
            row['reply_' + key] = values.get(key, ['', ''])[1] if len(values.get(key, [])) > 1 else ''
        rows.append(row)
        if len(rows) >= MAX_ROWS:
            break
    return rows


def events(text):
    rows = []
    for line in text.splitlines():
        match = re.search(r'OW (policy|dnat) ([0-9]+) ', line)
        if not match:
            continue
        values = dict(re.findall(r'\b(IN|OUT|SRC|DST|PROTO|SPT|DPT)=(\S*)', line))
        rows.append({'kind': match[1], 'id': match[2], **values, 'raw': line[:1500]})
    return rows[-MAX_ROWS:]


def snapshot():
    result = {'time': time.time(), 'connections': [], 'events': [], 'errors': [], 'truncated': False,
              'note': 'Campione IPv4 conntrack, massimo 500 sessioni. Log del buffer kernel limitati per frequenza; nessuno storico persistente.'}
    for name, args, parser in (('connections', ['conntrack', '-L', '-f', 'ipv4', '-o', 'extended'], connections),
                               ('events', ['dmesg', '--color=never', '--notime'], events)):
        try:
            data, truncated = capture(args, tail=name == 'events')
            if name == 'connections' and truncated:
                data = data.rsplit('\n', 1)[0]
            result[name] = parser(data)
            result['truncated'] |= truncated or len(result[name]) >= MAX_ROWS
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            result['errors'].append(name + ': ' + str(error)[:1000])
    return result


def system_snapshot(proc=Path('/proc')):
    """Read kernel counters only; rate calculation belongs to the sampling client."""
    result = {'sampled_at': time.monotonic(), 'cpu': None, 'memory': None,
              'uptime': None, 'interfaces': [], 'errors': []}
    for name in ('stat', 'meminfo', 'uptime', 'net/dev'):
        try:
            data = (proc / name).read_text()
            if name == 'stat':
                values = [int(v) for v in data.splitlines()[0].split()[1:9]]
                if len(values) < 4:
                    raise ValueError('Incomplete CPU counters')
                result['cpu'] = {'total': sum(values), 'idle': values[3] + (values[4] if len(values) > 4 else 0)}
            elif name == 'meminfo':
                values = {line.split(':')[0]: int(line.split()[1]) * 1024 for line in data.splitlines() if ':' in line}
                total, available = values['MemTotal'], values['MemAvailable']
                result['memory'] = {'total': total, 'used': max(0, total - available)}
            elif name == 'uptime':
                result['uptime'] = float(data.split()[0])
            else:
                for line in data.splitlines()[2:]:
                    device, counters = line.rsplit(':', 1)
                    values = counters.split()
                    if device.strip() != 'lo':
                        result['interfaces'].append({'device': device.strip(), 'rx': int(values[0]), 'tx': int(values[8])})
        except (OSError, ValueError, KeyError, IndexError):
            result['errors'].append(name + ': dati non disponibili')
    return result
