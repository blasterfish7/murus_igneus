"""IPv4 IKEv2 selector VPN and static dual-WAN failover. SPDX-License-Identifier: MIT."""
import copy
import ipaddress as ip
import json
from pathlib import Path
import re
import subprocess
import threading
import time
try:
    from .migration import Error
except ImportError:
    from migration import Error

RUN = Path('/run/murus-igneus')
DAEMON = None
DAEMON_LOG = None
WAN_THREAD = None
WAN_STOP = threading.Event()
WAN_LOCK = threading.RLock()
WAN_STATE = {'enabled': False, 'active': None, 'links': [], 'error': ''}
OWN_RULES = []
OWN_TABLES = []
RP_FILTER = {}
WAN_OWNED = False


def defaults():
    return {'ipsec': [], 'wan': {'enabled': False, 'links': []}}


def run(args, check=True):
    result = subprocess.run(args, text=True, capture_output=True, timeout=8)
    if check and result.returncode:
        # Never include configuration contents or PSKs in API errors.
        raise Error('Comando di rete fallito: ' + args[0])
    return result.stdout


def fields(value, allowed):
    if not isinstance(value, dict) or set(value) - set(allowed.split()):
        raise Error('Campi IPsec/WAN non validi')


def host(value):
    address = ip.IPv4Address(value)
    if address.is_unspecified or address.is_multicast or address.is_loopback or int(address) == 0xffffffff:
        raise Error('IPv4 unicast richiesto')
    return str(address)


def validate(config, management):
    result = {**defaults(), **{k: copy.deepcopy(config[k]) for k in defaults() if k in config}}
    interfaces = config.get('interfaces', [])
    devices = {r['device']: r for r in interfaces if isinstance(r, dict) and 'device' in r}
    if not isinstance(result['ipsec'], list) or len(result['ipsec']) > 16:
        raise Error('Massimo 16 tunnel IPsec')
    remote_networks = []; ids = set()
    for row in result['ipsec']:
        fields(row, 'id enabled public_device remote_ip local_id remote_id local_network remote_network psk')
        if type(row.get('id')) is not int or not 1 <= row['id'] <= 16 or row['id'] in ids:
            raise Error('ID IPsec intero 1–16, univoco')
        ids.add(row['id'])
        if type(row.get('enabled')) is not bool:
            raise Error('Abilitazione IPsec non valida')
        dev = row.get('public_device')
        if dev not in devices or dev in (management, 'lo') or not devices[dev].get('address'):
            raise Error('IPsec richiede una WAN dati con IPv4 statico')
        row['remote_ip'] = host(row.get('remote_ip'))
        for name in ('local_id', 'remote_id'):
            if not isinstance(row.get(name), str) or not re.fullmatch(r'[A-Za-z0-9@_.:-]{1,100}', row[name]):
                raise Error('Identità IKE non valida')
        if not isinstance(row.get('psk'), str) or not re.fullmatch(r'[A-Za-z0-9_+/@.=-]{20,128}', row['psk']):
            raise Error('PSK: 20–128 caratteri alfanumerici o _+/@.=-')
        local = ip.IPv4Network(row['local_network'], strict=False)
        remote = ip.IPv4Network(row['remote_network'], strict=False)
        if any(n.prefixlen == 0 or n.is_multicast or n.is_loopback for n in (local, remote)) or local.overlaps(remote):
            raise Error('Selettori IPsec specifici e non sovrapposti richiesti')
        if not any(r.get('address') and r['device'] != dev and local.subnet_of(ip.IPv4Interface(r['address']).network) for r in interfaces):
            raise Error('La rete locale IPsec deve appartenere a una LAN dati dichiarata')
        if any(r.get('address') and remote.overlaps(ip.IPv4Interface(r['address']).network) for r in interfaces):
            raise Error('Rete remota IPsec sovrapposta a una rete locale')
        if row['enabled'] and any(remote.overlaps(n) for n in remote_networks):
            raise Error('Selettori remoti IPsec sovrapposti')
        if row['enabled']:
            remote_networks.append(remote)
        row['local_network'] = str(local); row['remote_network'] = str(remote)
    wan = result['wan']; fields(wan, 'enabled links')
    if type(wan.get('enabled')) is not bool or not isinstance(wan.get('links'), list) or len(wan['links']) > 2:
        raise Error('Configurazione doppia WAN non valida')
    if wan['enabled'] and len(wan['links']) != 2:
        raise Error('Configurare esattamente due WAN')
    used = set()
    for row in wan['links']:
        fields(row, 'device gateway targets')
        dev = row.get('device')
        if dev in used or dev not in devices or dev in (management, 'lo') or not devices[dev].get('address'):
            raise Error('WAN distinte con IPv4 statici richieste')
        used.add(dev); address = ip.IPv4Interface(devices[dev]['address'])
        row['gateway'] = host(row.get('gateway'))
        if ip.IPv4Address(row['gateway']) not in address.network or row['gateway'] == str(address.ip):
            raise Error('Gateway WAN fuori subnet o uguale al firewall')
        if not isinstance(row.get('targets'), list) or not 1 <= len(row['targets']) <= 2:
            raise Error('Specificare uno o due obiettivi ICMP per WAN')
        row['targets'] = [host(v) for v in row['targets']]
        if any(ip.IPv4Address(v) in address.network for v in row['targets']):
            raise Error('Usare obiettivi ICMP oltre il gateway, fuori dalla subnet WAN')
    if wan['enabled'] and any(r.get('enabled', True) and r.get('destination') == '0.0.0.0/0' for r in config.get('routes', [])):
        raise Error('Rimuovere le rotte default statiche quando il failover WAN è abilitato')
    return result


def decorate(script, settings, interfaces):
    tunnels = [r for r in settings['ipsec'] if r['enabled']]
    if not tunnels:
        return script
    commands = ['add chain inet murus_igneus ipsec_guard']
    for r in tunnels:
        dev = json.dumps(r['public_device']); peer = r['remote_ip']; reqid = 19000 + r['id']
        commands += [f'add rule inet murus_igneus input iifname {dev} ip saddr {peer} udp dport {{ 500, 4500 }} accept',
                     f'add rule inet murus_igneus input iifname {dev} ip saddr {peer} ip protocol esp accept']
        local = r['local_network']; remote = r['remote_network']
        lan = json.dumps(next(i['device'] for i in interfaces if i.get('address') and i['device'] != r['public_device'] and ip.IPv4Network(local).subnet_of(ip.IPv4Interface(i['address']).network)))
        for direction, src, dst in [('in', remote, local), ('out', local, remote)]:
            ports = f'iifname {dev} oifname {lan}' if direction == 'in' else f'iifname {lan} oifname {dev}'
            commands += [f'add rule inet murus_igneus ipsec_guard {ports} ip saddr {src} ip daddr {dst} ipsec {direction} reqid {reqid} accept',
                         f'add rule inet murus_igneus ipsec_guard ip saddr {src} ip daddr {dst} drop']
        commands.append(f'insert rule inet murus_igneus postrouting ip saddr {local} ip daddr {remote} return')
    commands.append('insert rule inet murus_igneus forward jump ipsec_guard')
    return script + '\n' + '\n'.join(commands) + '\n'


def swan_config(settings, interfaces):
    devices = {r['device']: r for r in interfaces}
    connections = []; secrets = []
    for r in settings['ipsec']:
        if not r['enabled']:
            continue
        name = 'murus' + str(r['id']); address = str(ip.IPv4Interface(devices[r['public_device']]['address']).ip)
        connections.append(f'''{name} {{
 version = 2
 local_addrs = {address}
 remote_addrs = {r['remote_ip']}
 proposals = aes256-sha256-modp2048
 mobike = no
 dpd_delay = 30s
 local {{
  auth = psk
  id = {r['local_id']}
 }}
 remote {{
  auth = psk
  id = {r['remote_id']}
 }}
 children {{
  {name} {{
   local_ts = {r['local_network']}
   remote_ts = {r['remote_network']}
   esp_proposals = aes256-sha256-modp2048
   reqid = {19000 + r['id']}
   start_action = trap
   dpd_action = trap
   close_action = trap
  }}
 }}
}}''')
        secrets.append(f'''ike-{name} {{
 id-1 = {r['local_id']}
 id-2 = {r['remote_id']}
 secret = {r['psk']}
}}''')
    return 'connections {\n' + '\n'.join(connections) + '\n}\nsecrets {\n' + '\n'.join(secrets) + '\n}\n'


def ipsec_stop():
    global DAEMON, DAEMON_LOG
    if DAEMON is not None:
        DAEMON.terminate()
        try:
            DAEMON.wait(timeout=8)
        except subprocess.TimeoutExpired:
            DAEMON.kill(); DAEMON.wait(timeout=5)
        DAEMON = None
    if DAEMON_LOG is not None:
        DAEMON_LOG.close(); DAEMON_LOG = None
    for name in ('swanctl.conf', 'charon.conf'):
        (RUN / name).unlink(missing_ok=True)


def ipsec_start(settings, interfaces):
    global DAEMON, DAEMON_LOG
    ipsec_stop()
    if not any(r['enabled'] for r in settings['ipsec']):
        return
    RUN.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name, content in [('swanctl.conf', swan_config(settings, interfaces)), ('charon.conf', '''charon {
 install_routes = no
 load_modular = yes
 pid_file = @RUN@/charon.pid
 plugins {
  include /etc/strongswan.d/charon/*.conf
  vici {
   socket = unix://@RUN@/charon.vici
  }
 }
}
''')]:
        path = RUN / name; path.write_text(content.replace('@RUN@',str(RUN))); path.chmod(0o600)
    import os
    environment = {**os.environ, 'STRONGSWAN_CONF': str(RUN / 'charon.conf')}
    DAEMON_LOG = (RUN / 'charon.log').open('a')
    DAEMON = subprocess.Popen(['/usr/lib/ipsec/charon'], stdout=DAEMON_LOG, stderr=DAEMON_LOG, env=environment)
    try:
        for _ in range(40):
            if DAEMON.poll() is not None:
                raise Error('Avvio IPsec fallito')
            if (RUN / 'charon.vici').exists():
                break
            time.sleep(0.1)
        run(['swanctl', '--load-all', '--file', str(RUN / 'swanctl.conf'), '--uri', 'unix://' + str(RUN / 'charon.vici')])
    except Exception:
        ipsec_stop(); raise


def wan_stop():
    global WAN_THREAD, OWN_RULES, WAN_OWNED
    WAN_STOP.set()
    if WAN_THREAD is not None:
        WAN_THREAD.join(); WAN_THREAD = None
    with WAN_LOCK:
        if WAN_OWNED:
            run(['ip', '-4', 'route', 'flush', 'table', 'main', 'proto', '186'], check=False)
        WAN_OWNED = False
        for rule in OWN_RULES:
            run(['ip', '-4', 'rule', 'del'] + rule, check=False)
        OWN_RULES = []
        for table in OWN_TABLES:
            run(['ip', '-4', 'route', 'flush', 'table', table, 'proto', '186'], check=False)
        OWN_TABLES.clear()
        for path, value in RP_FILTER.items():
            Path(path).write_text(value)
        RP_FILTER.clear()
        WAN_STATE.update(enabled=False, active=None, links=[], error='')


def wan_start(settings, interfaces):
    global WAN_THREAD, WAN_OWNED
    wan_stop()
    if not settings['wan']['enabled']:
        return
    links = settings['wan']['links']; devices = {r['device']: r for r in interfaces}
    if json.loads(run(['ip', '-j', '-4', 'route', 'show', 'default'])):
        raise Error('Default route esterna presente: failover bloccato per preservarla')
    # Refuse collisions with unrelated routing policy.
    rules = json.loads(run(['ip', '-j', '-4', 'rule', 'show']))
    if any(r.get('priority') in (18081, 18082) for r in rules):
        raise Error('Priorità ip rule 18081/18082 già utilizzata')
    try:
        for i, row in enumerate(links):
            table = str(18081 + i)
            if json.loads(run(['ip', '-j', '-4', 'route', 'show', 'table', table], check=False) or '[]'):
                raise Error('Tabella di routing WAN già utilizzata')
            source = str(ip.IPv4Interface(devices[row['device']]['address']).ip)
            rp = Path('/proc/sys/net/ipv4/conf') / row['device'] / 'rp_filter'
            RP_FILTER[str(rp)] = rp.read_text(); rp.write_text('2')
            run(['ip', '-4', 'route', 'add', 'table', table, 'default', 'via', row['gateway'], 'dev', row['device'], 'onlink', 'proto', '186'])
            OWN_TABLES.append(table)
            rule = ['priority', table, 'from', source + '/32', 'lookup', table]
            run(['ip', '-4', 'rule', 'add'] + rule); OWN_RULES.append(rule)
        # No healthy link initially: traffic must never escape to another default.
        run(['ip', '-4', 'route', 'add', 'unreachable', 'default', 'metric', '18080', 'proto', '186'])
        WAN_OWNED = True
        WAN_STOP.clear(); WAN_STATE.update(enabled=True, active=None, links=[], error='')
        def worker():
            counts = [0, 0]; healthy = [False, False]; active = None
            while not WAN_STOP.is_set():
                try:
                    for i, row in enumerate(links):
                        source = str(ip.IPv4Interface(devices[row['device']]['address']).ip)
                        ok = False
                        for target in row['targets']:
                            probe = subprocess.run(['ping', '-n', '-c', '1', '-W', '1', '-I', source, target], capture_output=True, timeout=3)
                            if probe.returncode == 0:
                                ok = True; break
                        counts[i] = max(1, counts[i] + 1) if ok else min(-1, counts[i] - 1)
                        if counts[i] >= 3:
                            healthy[i] = True
                        elif counts[i] <= -3:
                            healthy[i] = False
                    selected = next((i for i, ready in enumerate(healthy) if ready), None)
                    if selected != active:
                        args = ['default', 'via', links[selected]['gateway'], 'dev', links[selected]['device']] if selected is not None else ['unreachable', 'default']
                        # A new route type cannot always replace the old one; remove only our exact main default.
                        run(['ip', '-4', 'route', 'flush', 'table', 'main', 'proto', '186'])
                        run(['ip', '-4', 'route', 'add'] + args + ['metric', '18080', 'proto', '186'])
                        active = selected
                    with WAN_LOCK:
                        WAN_STATE.update(active=links[active]['device'] if active is not None else None,
                                         links=[{'device': r['device'], 'healthy': healthy[i], 'consecutive': counts[i]} for i, r in enumerate(links)], error='')
                except Exception as exc:
                    with WAN_LOCK:
                        WAN_STATE['error'] = str(exc)[:200]
                WAN_STOP.wait(5)
        WAN_THREAD = threading.Thread(target=worker, daemon=True, name='murus-wan'); WAN_THREAD.start()
    except Exception:
        wan_stop(); raise


def stop():
    wan_stop(); ipsec_stop()


def activate(settings, interfaces):
    stop()
    try:
        ipsec_start(settings, interfaces); wan_start(settings, interfaces)
    except Exception:
        stop(); raise


def health():
    with WAN_LOCK:
        return {'wan': copy.deepcopy(WAN_STATE), 'ipsec_running': DAEMON is not None and DAEMON.poll() is None}
