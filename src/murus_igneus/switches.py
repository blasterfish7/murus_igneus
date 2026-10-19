"""Vendor-neutral IF-MIB/LLDP management via Net-SNMP. SPDX-License-Identifier: MIT."""
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
try:
    from .tasks import Task
except ImportError:
    from tasks import Task

LOCK = threading.RLock()
TASK = Task()
CACHE = {}
PLANS = {}
PRIVATE = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
ROOT = '.1.3.6.1.2.1'
SYSTEM = ROOT + '.1'
IFACE = ROOT + '.2.2.1'
IFNAME = ROOT + '.31.1.1.1.1'
ALIAS = ROOT + '.31.1.1.1.18'
LLDP = '.1.0.8802.1.1.2.1.4.1.1.9'
SECRET_FIELDS = ('community', 'auth_pass', 'priv_pass')


def validate(row):
    allowed = {'id', 'name', 'host', 'version', 'community', 'username', 'auth_pass', 'priv_pass', 'write_enabled', 'protected_ports', 'port'}
    if not isinstance(row, dict) or set(row) - allowed:
        raise ValueError('Campi switch non validi')
    result = copy.deepcopy(row)
    if not re.fullmatch(r'[a-f0-9]{16}', result.get('id', '')):
        raise ValueError('ID switch non valido')
    if not isinstance(result.get('name'), str) or not 1 <= len(result['name']) <= 80 or any(ord(c) < 32 for c in result['name']):
        raise ValueError('Nome switch non valido')
    try:
        addr = ipaddress.IPv4Address(result['host'])
    except (ValueError, KeyError, TypeError):
        raise ValueError('IPv4 dello switch non valido') from None
    if not any(addr in n for n in PRIVATE):
        raise ValueError('Lo switch deve avere un indirizzo IPv4 privato')
    result['host'] = str(addr)
    result.setdefault('port', 161)
    if type(result['port']) is not int or not 1 <= result['port'] <= 65535:
        raise ValueError('Porta UDP SNMP non valida')
    if result.get('version') not in ('2c', '3') or type(result.get('write_enabled', False)) is not bool:
        raise ValueError('Versione SNMP o abilitazione scrittura non valida')
    ports = result.get('protected_ports', [])
    if not isinstance(ports, list) or len(ports) > 1024 or any(type(p) is not int or not 1 <= p <= 2147483647 for p in ports):
        raise ValueError('Indici delle porte protette non validi')
    result['protected_ports'] = sorted(set(ports))
    result.setdefault('write_enabled', False)
    needed = ('community',) if result['version'] == '2c' else ('username', 'auth_pass', 'priv_pass')
    for k in needed:
        value = result.get(k)
        if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.@!%+=:?,\-]{1,64}', value):
            raise ValueError('Credenziale SNMP non valida: ' + k + ' (usare lettere, numeri, _.@!%+=:?,-)')
        if k.endswith('_pass') and len(value) < 8:
            raise ValueError('Le password SNMPv3 richiedono almeno 8 caratteri')
    for k in set(SECRET_FIELDS + ('username',)) - set(needed):
        result.pop(k, None)
    return result


def load(state):
    p = Path(state) / 'switches.json'
    rows = json.loads(p.read_text()) if p.exists() else []
    if not isinstance(rows, list) or len(rows) > 32:
        raise ValueError('Inventario switch non valido')
    return [validate(r) for r in rows]


def public(row):
    return {**{k: v for k, v in row.items() if k not in SECRET_FIELDS},
            'credentials_saved': True}


def inventory(state):
    with LOCK:
        return {'devices': [dict(public(r), telemetry=copy.deepcopy(CACHE.get(r['id']))) for r in load(state)],
                'snmp_available': bool(shutil.which('snmpbulkwalk') and shutil.which('snmpget') and shutil.which('snmpset')),
                'task': TASK.status()}


def idle():
    if (TASK.status() or {}).get('state') == 'running':
        raise ValueError('Attendere l’operazione switch in corso')


def write(state, rows):
    p = Path(state) / 'switches.json'
    p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = p.with_suffix('.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(rows, f)
    tmp.chmod(0o600)
    tmp.replace(p)


def save(state, data):
    if not isinstance(data, dict):
        raise ValueError('Switch non valido')
    with LOCK:
        idle()
        rows = load(state)
        row = copy.deepcopy(data)
        ident = row.setdefault('id', secrets.token_hex(8))
        old = next((x for x in rows if x['id'] == ident), None)
        if old:
            for k in SECRET_FIELDS:
                if row.get(k, '') == '':
                    row[k] = old.get(k, '')
        row = validate(row)
        if any(r['host'] == row['host'] and r['id'] != ident for r in rows):
            raise ValueError('Indirizzo switch già presente')
        rows = [r for r in rows if r['id'] != ident] + [row]
        if len(rows) > 32:
            raise ValueError('Massimo 32 switch')
        write(state, rows)
        CACHE.pop(ident, None)
        PLANS.clear()
        return public(row)


def delete(state, ident):
    with LOCK:
        idle()
        rows = load(state)
        write(state, [r for r in rows if r['id'] != ident])
        CACHE.pop(ident, None)
        PLANS.clear()
        return {'ok': True}


def get(state, ident):
    row = next((r for r in load(state) if r['id'] == ident), None)
    if not row:
        raise ValueError('Switch non presente')
    return row


def snmp(row, oid, value=None, walk=False):
    """Secrets stay in a private snmp.conf, never argv or returned errors."""
    program = 'snmpset' if value is not None else 'snmpbulkwalk' if walk else 'snmpget'
    if not shutil.which(program):
        raise ValueError('Installare il pacchetto Devuan snmp')
    with tempfile.TemporaryDirectory(prefix='murus-snmp-') as directory:
        cfg = Path(directory) / 'snmp.conf'
        lines = ['defVersion ' + ('2c' if row['version'] == '2c' else '3')]
        if row['version'] == '2c':
            lines.append('defCommunity ' + row['community'])
        else:
            lines += ['defSecurityName ' + row['username'], 'defSecurityLevel authPriv',
                      'defAuthType SHA', 'defPrivType AES',
                      'defAuthPassphrase ' + row['auth_pass'], 'defPrivPassphrase ' + row['priv_pass']]
        cfg.write_text('\n'.join(lines) + '\n')
        cfg.chmod(0o600)
        args = [program, '-On', '-Oe', '-Ot', '-t', '1', '-r', '0']
        if walk:
            args += ['-Cr20']
        args += ['udp:' + row['host'] + ':' + str(row.get('port', 161)), oid]
        if value is not None:
            args += ['i', str(value)]
        env = {**os.environ, 'SNMPCONFPATH': directory, 'MIBS': ''}
        with tempfile.TemporaryFile() as output:
            try:
                p = subprocess.run(args, stdout=output, stderr=subprocess.DEVNULL, timeout=6, env=env)
            except subprocess.TimeoutExpired:
                raise ValueError('Timeout SNMP sullo switch') from None
            if p.returncode:
                raise ValueError('Richiesta SNMP fallita: controllare credenziali, ACL e raggiungibilità')
            output.seek(0)
            raw = output.read(524289)
            if len(raw) > 524288:
                raise ValueError('Tabella SNMP troppo grande')
    return parse(raw.decode(errors='replace'))


def parse(raw):
    result = {}
    for line in raw.splitlines():
        m = re.match(r'^(\.[0-9.]+)\s*=\s*(.*)$', line)
        if not m:
            continue
        oid, v = m.groups()
        if v.startswith(('No Such', 'No more')):
            continue
        v = re.sub(r'^[A-Za-z0-9 -]+:\s*', '', v).strip()
        if len(v) >= 2 and v[0] == v[-1] == '"':
            v = v[1:-1]
        result[oid] = v[:512]
    return result


def integer(table, oid):
    try:
        return int(table[oid])
    except (KeyError, ValueError):
        return None


def telemetry(row):
    system = snmp(row, SYSTEM, walk=True)
    interfaces = snmp(row, IFACE, walk=True)
    names = snmp(row, IFNAME, walk=True)
    aliases = snmp(row, ALIAS, walk=True)
    warnings = []
    try:
        neighbors = snmp(row, LLDP, walk=True)
    except ValueError:
        neighbors = {}
        warnings.append('LLDP non disponibile o non autorizzato')
    ports = []
    for oid in interfaces:
        if not oid.startswith(IFACE + '.1.'):
            continue
        idx = int(oid.rsplit('.', 1)[1])
        key = '.' + str(idx)
        ports.append({'index': idx, 'name': names.get(IFNAME + key, interfaces.get(IFACE + '.2' + key, str(idx))),
                      'alias': aliases.get(ALIAS + key, ''), 'type': integer(interfaces, IFACE + '.3' + key),
                      'admin': integer(interfaces, IFACE + '.7' + key), 'oper': integer(interfaces, IFACE + '.8' + key),
                      'speed_bps': integer(interfaces, IFACE + '.5' + key),
                      'in_octets32': integer(interfaces, IFACE + '.10' + key),
                      'out_octets32': integer(interfaces, IFACE + '.16' + key),
                      'protected': idx in row['protected_ports']})
    ports.sort(key=lambda p: p['index'])
    if not system.get(SYSTEM + '.2.0') or not ports:
        raise ValueError('Lo switch non espone SYSTEM e IF-MIB; verificare le viste SNMP')
    return {'polled': time.time(), 'name': system.get(SYSTEM + '.5.0', ''),
            'description': system.get(SYSTEM + '.1.0', ''), 'object_id': system[SYSTEM + '.2.0'],
            'ports': ports, 'lldp': [{'index': k[len(LLDP)+1:], 'remote_name': v} for k, v in neighbors.items()],
            'warnings': warnings}


def poll(state, ident):
    with LOCK:
        row = get(state, ident)
        def action():
            try:
                result = telemetry(row)
            except Exception:
                with LOCK:
                    CACHE[ident] = {'polled': time.time(), 'error': 'Lettura fallita; dati precedenti non disponibili'}
                raise
            with LOCK:
                CACHE[ident] = result
            return {'id': ident, 'telemetry': result}
        return TASK.start(action)


def fingerprint(row):
    return hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()


def preview(state, data):
    with LOCK:
        row = get(state, data.get('id'))
        index, desired = data.get('port'), data.get('admin')
        if (not row['write_enabled'] or type(index) is not int or not 1 <= index <= 2147483647 or
                type(desired) is not int or desired not in (1, 2)):
            raise ValueError('Abilitare la scrittura e scegliere una porta e lo stato up/down')
        if index in row['protected_ports']:
            raise ValueError('Porta protetta: modifica bloccata')
        def action():
            t = telemetry(row)
            port = next((p for p in t['ports'] if p['index'] == index), None)
            if not port or port['type'] != 6 or port['admin'] not in (1, 2):
                raise ValueError('La scrittura è supportata solo sulle porte Ethernet IF-MIB')
            if desired == port['admin']:
                raise ValueError('La porta è già nello stato richiesto')
            token = secrets.token_hex(16)
            phrase = f"PORTA {row['host']} {index} {'UP' if desired == 1 else 'DOWN'}"
            plan = {'id': row['id'], 'port': index, 'admin': desired, 'previous': port['admin'],
                    'name': port['name'], 'object_id': t['object_id'], 'system_name': t['name'],
                    'fingerprint': fingerprint(row), 'expires': time.monotonic() + 120, 'confirmation': phrase}
            with LOCK:
                PLANS.clear()
                PLANS[token] = plan
            return {'token': token, 'confirmation': phrase, 'port': port, 'admin': desired,
                    'warning': 'La modifica può interrompere collegamenti. Nessun rollback automatico; il salvataggio permanente dipende dallo switch.'}
        return TASK.start(action)


def apply(state, data):
    with LOCK:
        idle()
        plan = PLANS.pop(data.get('token'), None)
        if not plan or time.monotonic() >= plan['expires'] or data.get('confirmation') != plan['confirmation']:
            raise ValueError('Anteprima scaduta o conferma non valida')
        row = get(state, plan['id'])
        if fingerprint(row) != plan['fingerprint'] or not row['write_enabled'] or plan['port'] in row['protected_ports']:
            raise ValueError('Configurazione switch cambiata: ripetere l’anteprima')
        def action():
            # Re-read identity and administrative state before the single, fixed IF-MIB SET.
            current = telemetry(row)
            port = next((p for p in current['ports'] if p['index'] == plan['port']), None)
            oid = IFACE + '.7.' + str(plan['port'])
            if (current['object_id'] != plan['object_id'] or current['name'] != plan['system_name'] or
                    not port or port['name'] != plan['name'] or port['type'] != 6 or port['admin'] != plan['previous']):
                raise ValueError('Identità o stato della porta cambiati: operazione annullata')
            try:
                snmp(row, oid, value=plan['admin'])
            except ValueError:
                raise ValueError('Esito del SET incerto: verificare lo switch prima di riprovare') from None
            if integer(snmp(row, oid), oid) != plan['admin']:
                raise ValueError('SET inviato, stato finale non confermato: verificare lo switch')
            with LOCK:
                CACHE.pop(row['id'], None)
            return {'id': row['id'], 'port': plan['port'], 'admin': plan['admin'], 'verified': True,
                    'message': 'Stato amministrativo verificato; persistenza al riavvio dipendente dallo switch'}
        return TASK.start(action)
