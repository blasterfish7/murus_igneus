"""Native VLAN, DHCP/DNS and explicit destination NAT. SPDX-License-Identifier: MIT."""
import copy
import ipaddress as ip
import json
from pathlib import Path
import re
import time

try:
    from .migration import Error
    from . import security
except ImportError:
    from migration import Error
    import security

EXTRA = ('dhcp', 'dns', 'port_forwards')
VLAN_ALIAS = 'murus-igneus-vlan'


def defaults():
    return {'dhcp': [], 'dns': {'enabled': False, 'interfaces': [], 'upstream_servers': [], 'domain': 'lan'}, 'port_forwards': []}


def fields(row, allowed):
    if not isinstance(row, dict) or set(row) - set(allowed.split()):
        raise Error('Campi di rete non validi')


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise Error('Intero di rete fuori intervallo')
    return value


def enabled(row):
    value = row.get('enabled', True)
    if type(value) is not bool:
        raise Error('Abilitazione non valida')
    return value


def device(value, management):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', value) or value in ('lo', management, security.WG):
        raise Error('Interfaccia dati non valida o riservata')
    return value


def host(value):
    if not isinstance(value, str):
        raise Error('IPv4 richiesto come stringa')
    a = ip.IPv4Address(value)
    if a.is_unspecified or a.is_multicast or a.is_loopback or a.is_link_local or int(a) == 0xffffffff:
        raise Error('Indirizzo IPv4 host non valido')
    return str(a)


def prepare(config, management):
    """Keep the conservative backup translator unchanged; extend only native input."""
    c = copy.deepcopy(config)
    settings = defaults()
    for key in EXTRA:
        if key in c:
            settings[key] = c.pop(key)
    interfaces = c.get('interfaces', [])
    if not isinstance(interfaces, list):
        raise Error('Interfacce non valide')
    original = copy.deepcopy(interfaces)
    physical = set()
    for row in interfaces:
        fields(row, 'name device address parent vlan_id')
        dev = row.get('device')
        if not row.get('parent') and row.get('vlan_id') is None:
            physical.add(dev)
    vlans = []; tags = set()
    for row in interfaces:
        parent = row.pop('parent', '')
        tag = row.pop('vlan_id', None)
        if not parent and tag is None:
            continue
        device(row.get('device'), management); device(parent, management); integer(tag, 1, 4094)
        if parent not in physical or row['device'] in physical or (parent, tag) in tags:
            raise Error('VLAN: dichiarare una porta fisica padre distinta; tag duplicati non ammessi')
        tags.add((parent, tag))
        vlans.append({'kind': 'vlan', 'interface': row['device'], 'parent': parent, 'vlan_id': tag})
    if len(vlans) > 64:
        raise Error('Massimo 64 VLAN')
    by_name = {r.get('name'): r for r in interfaces}

    def interface(name, address=True):
        if not isinstance(name, str) or name not in by_name:
            raise Error('Interfaccia di rete assente: ' + str(name))
        row = by_name[name]
        if address and not row.get('address'):
            raise Error('Serve un IPv4 statico su ' + name)
        return row

    def rows(key):
        value = settings[key]
        if not isinstance(value, list) or len(value) > 128:
            raise Error('Elenco di rete non valido: ' + key)
        return value

    dns = settings['dns']
    fields(dns, 'enabled interfaces upstream_servers domain')
    if set(dns) != set(defaults()['dns']) or type(dns['enabled']) is not bool:
        raise Error('Configurazione DNS incompleta')
    if not isinstance(dns['interfaces'], list) or len(dns['interfaces']) > 64 or not all(isinstance(n, str) for n in dns['interfaces']) or len(set(dns['interfaces'])) != len(dns['interfaces']):
        raise Error('Interfacce DNS non valide')
    if not isinstance(dns['upstream_servers'], list) or len(dns['upstream_servers']) > 8:
        raise Error('Resolver DNS non validi')
    dns['upstream_servers'] = list(dict.fromkeys(host(a) for a in dns['upstream_servers']))
    if not isinstance(dns['domain'], str) or not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*', dns['domain']) or len(dns['domain']) > 253:
        raise Error('Dominio DNS non valido')
    if dns['enabled']:
        if not dns['interfaces'] or not dns['upstream_servers']:
            raise Error('DNS: specificare interfacce e resolver IPv4 espliciti')
        local_ips = {str(ip.IPv4Interface(r['address']).ip) for r in interfaces if r.get('address')}
        if local_ips.intersection(dns['upstream_servers']):
            raise Error('Un resolver DNS punta al firewall stesso')
        for name in dns['interfaces']:
            interface(name)
    pools = set()
    for row in rows('dhcp'):
        fields(row, 'interface start end lease_hours dns_servers enabled')
        enabled(row)
        name = row.get('interface'); port = interface(name)
        if name in pools:
            raise Error('Un solo pool DHCP per interfaccia')
        pools.add(name)
        a = ip.IPv4Interface(port['address']); start = ip.IPv4Address(host(row['start'])); end = ip.IPv4Address(host(row['end']))
        if start not in a.network or end not in a.network or int(start) > int(end) or start == a.network.network_address or end == a.network.broadcast_address or int(start) <= int(a.ip) <= int(end):
            raise Error('Pool DHCP fuori subnet o comprendente gateway/indirizzi riservati')
        integer(row.get('lease_hours'), 1, 168)
        servers = row.get('dns_servers')
        if not isinstance(servers, list) or len(servers) > 4:
            raise Error('DNS del pool DHCP non validi')
        row['dns_servers'] = list(dict.fromkeys(host(s) for s in servers))
        if enabled(row) and not servers and not (dns['enabled'] and name in dns['interfaces']):
            raise Error('DHCP: indicare resolver oppure abilitare DNS sulla stessa interfaccia')
    ids = set(); bindings = set()
    for row in rows('port_forwards'):
        fields(row, 'id name interface public_ip protocol external_port target_interface target_ip target_port source enabled log')
        enabled(row)
        ident = row.get('id')
        if not isinstance(ident, str) or not ident.isascii() or not ident.isdecimal() or not 1 <= int(ident) <= 4294967295 or int(ident) in ids:
            raise Error('ID port forwarding non valido o duplicato')
        ids.add(int(ident))
        if not isinstance(row.get('name', ''), str) or len(row.get('name', '')) > 128 or any(ord(x) < 32 for x in row.get('name', '')):
            raise Error('Nome pubblicazione non valido')
        incoming = interface(row.get('interface'))
        target = interface(row.get('target_interface'))
        if incoming['device'] == target['device']:
            raise Error('Port forwarding: ingresso e destinazione devono essere distinti (hairpin non supportato)')
        row['public_ip'] = host(row['public_ip']); row['target_ip'] = host(row['target_ip'])
        # Initial implementation publishes only an address actually owned by the ingress interface.
        if row['public_ip'] != str(ip.IPv4Interface(incoming['address']).ip):
            raise Error('L’IP pubblico deve coincidere con l’IPv4 dell’interfaccia di ingresso')
        a = ip.IPv4Interface(target['address']); destination = ip.IPv4Address(row['target_ip'])
        if destination not in a.network or destination in (a.ip, a.network.network_address, a.network.broadcast_address):
            raise Error('Destinazione DNAT non valida nella subnet interna')
        if row.get('protocol') not in ('tcp', 'udp') or type(row.get('log', False)) is not bool:
            raise Error('Protocollo o log DNAT non validi')
        integer(row.get('external_port'), 1, 65535); integer(row.get('target_port'), 1, 65535)
        row['source'] = str(ip.IPv4Network(row['source'], strict=False))
        binding = (incoming['device'], row['public_ip'], row['protocol'], row['external_port'])
        if row.get('enabled', True) and binding in bindings:
            raise Error('Pubblicazione duplicata sulla stessa porta pubblica')
        if row.get('enabled', True):
            bindings.add(binding)
    return c, original, settings, vlans


def decorate(plan, original, settings, vlans):
    plan['configuration']['interfaces'] = original
    plan['configuration'].update(settings)
    plan['network_services'] = {'interfaces': original, **settings}
    plan['network_ops'] = vlans + plan['network_ops']
    script = plan['nftables']; inputs = []; forwards = []; nat = []
    ports = {r['name']: r for r in original}
    for row in settings['dhcp']:
        if enabled(row):
            dev = json.dumps(ports[row['interface']]['device'])
            inputs.append(f'add rule inet murus_igneus input iifname {dev} udp sport 68 udp dport 67 counter accept')
    dns = settings['dns']
    if dns['enabled']:
        for name in dns['interfaces']:
            row = ports[name]; a = ip.IPv4Interface(row['address'])
            for protocol in ('tcp', 'udp'):
                inputs.append(f'add rule inet murus_igneus input iifname {json.dumps(row["device"])} ip saddr {a.network} ip daddr {a.ip} {protocol} dport 53 counter accept')
    for row in settings['port_forwards']:
        if not enabled(row):
            continue
        dev = json.dumps(ports[row['interface']]['device']); out = json.dumps(ports[row['target_interface']]['device'])
        proto = row['protocol']; ident = row['id']
        match = f'iifname {dev} ip saddr {row["source"]} ip daddr {row["public_ip"]} {proto} dport {row["external_port"]}'
        nat.append(f'add rule inet murus_igneus prerouting {match} counter dnat ip to {row["target_ip"]}:{row["target_port"]} comment "dnat {ident}"')
        permit = f'iifname {dev} oifname {out} ct status dnat ip saddr {row["source"]} ip daddr {row["target_ip"]} {proto} dport {row["target_port"]} ct original ip daddr {row["public_ip"]} ct original proto-dst {row["external_port"]}'
        if row.get('log'):
            forwards.append(f'  {permit} limit rate 20/second log prefix "OW dnat {ident} "')
        forwards.append(f'  {permit} counter accept comment "dnat {ident}"')
    if forwards:
        marker = '  ct state established,related accept\n'
        # Insert only in forward: input also has an established rule.
        pos = script.index(' chain forward')
        script = script[:pos] + script[pos:].replace(marker, marker + '\n'.join(forwards) + '\n', 1)
        plan['warnings'].append('Le pubblicazioni DNAT autorizzano esplicitamente il traffico prima delle policy; IPS resta applicato. Nessun hairpin NAT.')
    if nat:
        inputs += ['add chain inet murus_igneus prerouting { type nat hook prerouting priority -100; policy accept; }'] + nat
    plan['nftables'] = script + ('\n'.join(inputs) + '\n' if inputs else '')
    return plan


def dnsmasq_config(settings, management):
    """Generate a standalone config; do not read /etc/dnsmasq.conf or resolver env."""
    dns = settings['dns']; pools = [r for r in settings['dhcp'] if enabled(r)]
    if not dns['enabled'] and not pools:
        return ''
    ports = {r['name']: r for r in settings['interfaces']}
    names = set(dns['interfaces'] if dns['enabled'] else []) | {r['interface'] for r in pools}
    lines = ['bind-interfaces', 'except-interface=lo', 'except-interface=' + management,
             'no-resolv', 'no-hosts', 'domain-needed', 'bogus-priv', 'no-poll',
             'dhcp-lease-max=4096', 'dhcp-leasefile=/var/lib/murus-igneus/dnsmasq.leases',
             'user=root', 'group=root', 'log-facility=-', 'domain=' + dns['domain'], 'local=/' + dns['domain'] + '/']
    if not dns['enabled']:
        lines.append('port=0')
    for name in sorted(names):
        row = ports[name]
        lines.append('interface=' + row['device'])
        if name not in {r['interface'] for r in pools}:
            lines.append('no-dhcp-interface=' + row['device'])
    if dns['enabled']:
        lines.extend('server=' + s for s in dns['upstream_servers'])
    for index, row in enumerate(pools):
        port = ports[row['interface']]; a = ip.IPv4Interface(port['address']); tag = 'mi' + str(index)
        lines.extend([
            f'dhcp-range=set:{tag},{row["start"]},{row["end"]},{a.netmask},{row["lease_hours"]}h',
            f'dhcp-option=tag:{tag},option:router,{a.ip}',
            f'dhcp-option=tag:{tag},option:dns-server,' + ','.join(row['dns_servers'] or [str(a.ip)])])
    return '\n'.join(lines) + '\n'


def stop():
    security.stop('dnsmasq')


def activate(settings, management):
    stop()
    text = dnsmasq_config(settings, management)
    if not text:
        return
    leases = Path('/var/lib/murus-igneus'); leases.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = security.RUN / 'dnsmasq.conf'; security.write(path, text)
    security.command(['dnsmasq', '--test', '--conf-file=' + str(path)])
    security.spawn('dnsmasq', ['dnsmasq', '--keep-in-foreground', '--conf-file=' + str(path), '--pid-file='])
    time.sleep(.25)
    if security.PROCESSES['dnsmasq'].poll() is not None:
        raise Error('DHCP/DNS non avviato: ' + (security.RUN / 'dnsmasq.log').read_text()[-1500:])


def health():
    process = security.PROCESSES.get('dnsmasq')
    leases = []
    try:
        with Path('/var/lib/murus-igneus/dnsmasq.leases').open() as file:
            for index, line in enumerate(file):
                if index >= 4096:
                    break
                values = line.split()
                if len(values) >= 4:
                    leases.append({'expires': values[0], 'mac': values[1], 'address': values[2], 'hostname': values[3]})
    except FileNotFoundError:
        pass
    return {'running': bool(process and process.poll() is None), 'leases': leases}
