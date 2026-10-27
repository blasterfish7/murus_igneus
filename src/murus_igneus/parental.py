"""Local DNS parental profiles and scheduled transit control. SPDX-License-Identifier: MIT."""
import copy
from datetime import datetime
import hashlib
import http.client
import ipaddress as ip
import json
from pathlib import Path
import re
import threading
import time
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
try:
    from . import security, parental_report as reporting
    from .tasks import Task
    from .migration import Error
except ImportError:
    import security
    import parental_report as reporting
    from tasks import Task
    from migration import Error

FEEDS = {
    'adult': ('Contenuti per adulti', 'nsfw-onlydomains.txt'),
    'gambling': ('Gioco d’azzardo', 'gambling.mini-onlydomains.txt'),
    'malware': ('Malware e phishing', 'tif.mini-onlydomains.txt'),
    'bypass': ('DNS cifrati e strumenti di aggiramento noti', 'doh-vpn-proxy-bypass-onlydomains.txt'),
}
SERVICES = {
    'instagram': ['instagram.com', 'cdninstagram.com', 'ig.me'],
    'tiktok': ['tiktok.com', 'tiktokv.com', 'tiktokcdn.com', 'musical.ly', 'byteoversea.com'],
    'facebook': ['facebook.com', 'facebook.net', 'fb.com', 'fbcdn.net', 'messenger.com'],
    'youtube': ['youtube.com', 'youtu.be', 'googlevideo.com', 'ytimg.com', 'youtubei.googleapis.com'],
    'snapchat': ['snapchat.com', 'snap.com', 'sc-cdn.net'],
    'discord': ['discord.com', 'discord.gg', 'discordapp.com', 'discordapp.net'],
    'twitch': ['twitch.tv', 'ttvnw.net', 'jtvnw.net'],
}
# Domain matching is best effort; arbitrary DoH and VPNs on HTTPS remain possible.
ENCRYPTED_DNS = ['dns.google', 'cloudflare-dns.com', 'mozilla.cloudflare-dns.com',
                 'dns.quad9.net', 'dns.adguard-dns.com', 'doh.opendns.com', 'dns.nextdns.io']
MAX_FEED_BYTES = 16 * 1024 * 1024
MAX_FEED_DOMAINS = 300000
STATE = Path('/etc/murus_igneus')
TASK = Task()
LOCK = threading.RLock()
STOP = threading.Event()
THREAD = None
CURRENT = None
GUARD = None
BLOCKED = {}
RUNTIME = {'running': False, 'profiles': [], 'error': ''}
LAST_RULES = None
REPORTER = None
DNS_MODES = {}
MANAGEMENT = 'eth0'
AUTO_NEXT = 0
AUTO_STATUS = {'last_success': None, 'error': ''}


def defaults():
    return {'parental': {'enabled': False, 'timezone': 'Europe/Rome',
                         'upstream_servers': ['1.1.1.1', '9.9.9.9'], 'profiles': [], 'reporting': False, 'auto_update': False}}


def fields(value, allowed):
    if not isinstance(value, dict) or set(value) - set(allowed.split()):
        raise Error('Campi parental control non validi')


def domain(value, allow_tld=False):
    if not isinstance(value, str):
        raise Error('Specificare un dominio senza URL, porta o percorso')
    value = value.strip().lower().rstrip('.')
    if value.startswith('*.'):
        value = value[2:]
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError:
        raise Error('Dominio non valido') from None
    if allow_tld and '.' not in value and re.fullmatch(r'[a-z][a-z0-9-]{1,61}[a-z0-9]', value):
        return value
    if len(value) > 253 or '.' not in value or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+', value):
        raise Error('Dominio non valido: usare esempio.it, senza URL o caratteri speciali')
    try:
        ip.ip_address(value)
    except ValueError:
        return value
    raise Error('Usare un dominio, non un indirizzo IP')


def names(value, limit=1000, allow_tld=False):
    if not isinstance(value, list) or len(value) > limit:
        raise Error('Elenco domini troppo grande o non valido')
    return sorted(set(domain(v, allow_tld) for v in value))


def minute(value):
    if not isinstance(value, str) or not re.fullmatch(r'(?:[01][0-9]|2[0-3]):[0-5][0-9]', value):
        raise Error('Orario richiesto in formato HH:MM, 00:00–23:59')
    hours, minutes = map(int, value.split(':'))
    return hours * 60 + minutes


def validate(config, management='eth0'):
    settings = copy.deepcopy(config.get('parental', defaults()['parental']))
    settings.setdefault('reporting', False)
    settings.setdefault('auto_update', False)
    fields(settings, 'enabled timezone upstream_servers profiles reporting auto_update')
    if set(settings) != set(defaults()['parental']) or type(settings['enabled']) is not bool or type(settings['reporting']) is not bool or type(settings['auto_update']) is not bool:
        raise Error('Configurazione parental control incompleta')
    if not isinstance(settings['timezone'], str) or len(settings['timezone']) > 80:
        raise Error('Fuso orario non valido')
    try:
        ZoneInfo(settings['timezone'])
    except (ZoneInfoNotFoundError, ValueError):
        raise Error('Fuso orario IANA non disponibile') from None
    servers = settings['upstream_servers']
    if not isinstance(servers, list) or not 1 <= len(servers) <= 4:
        raise Error('Specificare 1–4 resolver IPv4')
    settings['upstream_servers'] = [str(ip.IPv4Address(v)) for v in servers]
    if any(ip.IPv4Address(v).is_unspecified or ip.IPv4Address(v).is_multicast or ip.IPv4Address(v).is_loopback for v in settings['upstream_servers']):
        raise Error('Resolver IPv4 non valido')
    ports = {r.get('name'): r for r in config.get('interfaces', []) if isinstance(r, dict)}
    if any(str(ip.IPv4Interface(r['address']).ip) in settings['upstream_servers'] for r in ports.values() if r.get('address')):
        raise Error('I resolver parental non devono puntare al firewall stesso')
    profiles = settings['profiles']
    if not isinstance(profiles, list) or len(profiles) > 8:
        raise Error('Massimo 8 profili parental')
    ids = set(); used = []
    for row in profiles:
        if not isinstance(row, dict):
            raise Error('Profilo parental non valido')
        for key, value in {'devices': [], 'safe_search': False, 'youtube_restricted': 'off', 'study_windows': [], 'study_domains': [], 'night_windows': [], 'block_ipv6': False}.items():
            row.setdefault(key, value)
        fields(row, 'id name enabled interface clients categories services blocked_domains allowed_domains windows paused enforce_dns block_quic devices safe_search youtube_restricted study_windows study_domains night_windows block_ipv6')
        required = set('id name enabled interface clients categories services blocked_domains allowed_domains windows paused enforce_dns block_quic devices safe_search youtube_restricted study_windows study_domains night_windows block_ipv6'.split())
        if set(row) != required or type(row['id']) is not int or not 1 <= row['id'] <= 8 or row['id'] in ids:
            raise Error('Profilo incompleto o ID non univoco (1–8)')
        ids.add(row['id'])
        if not isinstance(row['name'], str) or not row['name'].strip() or len(row['name']) > 80 or any(ord(c) < 32 for c in row['name']):
            raise Error('Nome profilo non valido')
        if any(type(row[k]) is not bool for k in ('enabled', 'paused', 'enforce_dns', 'block_quic', 'safe_search', 'block_ipv6')):
            raise Error('Abilitazione parental non valida')
        port = ports.get(row['interface'])
        if not port or not port.get('address') or port['device'] in (management, 'lo', security.WG):
            raise Error('Il profilo richiede una LAN dati con IPv4 statico')
        subnet = ip.IPv4Interface(port['address']).network
        if not isinstance(row['clients'], list) or not 1 <= len(row['clients']) <= 64:
            raise Error('Specificare 1–64 IPv4 o subnet dei dispositivi')
        clients = [ip.IPv4Network(v, strict=False) for v in row['clients']]
        if any(not n.subnet_of(subnet) for n in clients):
            raise Error('I dispositivi devono appartenere alla LAN del profilo')
        if row['enabled']:
            for n in clients:
                if any(n.overlaps(old) for old in used):
                    raise Error('Dispositivi/subnet sovrapposti tra profili abilitati')
                used.append(n)
        row['clients'] = list(dict.fromkeys(str(n) for n in clients))
        for key, known in [('categories', FEEDS), ('services', SERVICES)]:
            if not isinstance(row[key], list) or not all(isinstance(v, str) and v in known for v in row[key]) or len(set(row[key])) != len(row[key]):
                raise Error('Categoria o servizio parental non valido')
        row['blocked_domains'] = names(row['blocked_domains']); row['allowed_domains'] = names(row['allowed_domains'])
        for key in ('windows', 'study_windows', 'night_windows'):
            validate_windows(row[key])
        if row['youtube_restricted'] not in ('off', 'strict', 'moderate'):
            raise Error('Modalità YouTube non valida')
        row['study_domains'] = names(row['study_domains'])
        if row['study_windows'] and (not row['study_domains'] or not row['enforce_dns']):
            raise Error('La modalità compiti richiede domini scolastici e DNS forzato')
        if (row['safe_search'] or row['youtube_restricted'] != 'off') and not row['enforce_dns']:
            raise Error('SafeSearch e YouTube con restrizioni richiedono DNS forzato')
        devices = row['devices']
        if not isinstance(devices, list) or len(devices) > 64:
            raise Error('Massimo 64 nomi di dispositivi per figlio')
        addresses = set()
        for device in devices:
            fields(device, 'address name')
            if set(device) != {'address', 'name'} or not isinstance(device['name'], str) or not device['name'].strip() or len(device['name']) > 80 or any(ord(c) < 32 for c in device['name']):
                raise Error('Nome dispositivo non valido')
            device['address'] = str(ip.IPv4Address(device['address']))
            if device['address'] in addresses or str(ip.IPv4Network(device['address'] + '/32')) not in row['clients']:
                raise Error('Il dispositivo deve avere un IPv4 singolo presente nel profilo, senza duplicati')
            addresses.add(device['address'])
    return settings


def validate_windows(windows):
    if not isinstance(windows, list) or len(windows) > 28:
        raise Error('Massimo 28 fasce orarie per modalità')
    for window in windows:
        fields(window, 'days start end')
        if set(window) != {'days', 'start', 'end'} or not isinstance(window['days'], list) or not window['days'] or any(type(d) is not int or not 0 <= d <= 6 for d in window['days']):
            raise Error('Giorni: lunedì=0, domenica=6')
        if minute(window['start']) == minute(window['end']):
            raise Error('Una fascia deve avere orari diversi')


def active_profiles(settings):
    return [p for p in settings['profiles'] if settings['enabled'] and p['enabled']]


def decorate(plan, settings, interfaces):
    plan['configuration']['parental'] = settings
    plan['parental'] = {'settings': settings, 'interfaces': interfaces}
    profiles = active_profiles(settings)
    if not profiles:
        return
    ports = {r['name']: r for r in interfaces}
    lines = ['add chain inet murus_igneus pc_schedule',
             'add chain inet murus_igneus pc_forward { type filter hook forward priority -20; policy accept; }',
             'add rule inet murus_igneus pc_forward jump pc_schedule',
             'add chain inet murus_igneus pc_input { type filter hook input priority -20; policy accept; }',
             'add rule inet murus_igneus pc_input udp dport { 53, 67, 12001-12008 } accept',
             'add rule inet murus_igneus pc_input tcp dport { 53, 12001-12008 } accept',
             'add rule inet murus_igneus pc_input jump pc_schedule',
             'add chain inet murus_igneus pc_output { type filter hook output priority -20; policy accept; }',
             'add rule inet murus_igneus pc_output udp sport { 53, 67, 12001-12008 } accept',
             'add rule inet murus_igneus pc_output tcp sport { 53, 12001-12008 } accept',
             'add rule inet murus_igneus pc_output jump pc_schedule',
             'add chain inet murus_igneus pc_dns { type nat hook prerouting priority -110; policy accept; }']
    lines += reporting.rules(settings, interfaces)
    for device in sorted({ports[p['interface']]['device'] for p in profiles if p.get('block_ipv6')}):
        for chain, direction in [('pc_forward', 'iifname'), ('pc_forward', 'oifname'), ('pc_input', 'iifname'), ('pc_output', 'oifname')]:
            lines.append(f'insert rule inet murus_igneus {chain} {direction} {json.dumps(device)} meta nfproto ipv6 counter drop comment "parental IPv6 LAN"')
    plan['warnings'].append('Parental IPv6: nessun filtro per dispositivo. Il blocco IPv6 opzionale copre tutta la LAN scelta, incluso accesso al firewall; non copre percorsi alternativi sullo stesso segmento.')
    for row in profiles:
        dev = json.dumps(ports[row['interface']]['device']); clients = '{ ' + ', '.join(row['clients']) + ' }'; port = 12000 + row['id']
        # Start closed. Evaluate local time after all services start.
        lines += drop_rules(row, settings, interfaces)
        for protocol in ('udp', 'tcp'):
            destination = '' if row['enforce_dns'] else f'ip daddr {ip.IPv4Interface(ports[row["interface"]]["address"]).ip} '
            lines.append(f'add rule inet murus_igneus pc_dns iifname {dev} ip saddr {clients} {destination}{protocol} dport 53 redirect to :{port}')
        accounting = [r for r in reporting.entities(settings, interfaces) if r['profile'] == row['id']] if settings.get('reporting') else []
        for protocol in ('udp', 'tcp'):
            if row['enforce_dns']:
                if accounting:
                    for r in accounting:
                        lines.append(f'add rule inet murus_igneus pc_forward iifname {dev} ip saddr {r["client"]} {protocol} dport {{ 53, 853, 784, 8853 }} counter name {reporting.counter(r, "blocked")} drop')
                else:
                    lines.append(f'add rule inet murus_igneus pc_forward iifname {dev} ip saddr {clients} {protocol} dport {{ 53, 853, 784, 8853 }} counter drop')
        if row['block_quic']:
            if accounting:
                for r in accounting:
                    lines.append(f'add rule inet murus_igneus pc_forward iifname {dev} ip saddr {r["client"]} udp dport 443 counter name {reporting.counter(r, "blocked")} drop')
            else:
                lines.append(f'add rule inet murus_igneus pc_forward iifname {dev} ip saddr {clients} udp dport 443 counter drop')
        for protocol in ('udp', 'tcp'):
            lines.append(f'add rule inet murus_igneus input iifname {dev} ip saddr {clients} ip daddr {ip.IPv4Interface(ports[row["interface"]]["address"]).ip} {protocol} dport {port} counter accept')
    plan['nftables'] += '\n' + '\n'.join(lines) + '\n'
    plan['warnings'].append('Parental: usa IP/subnet stabili e Murus come gateway. DNS forzato e orari si applicano prima di policy, DNAT, IPsec e connessioni esistenti. DoH/VPN sconosciuti e rete mobile non sono coperti.')


def feed_path(category, state=None):
    if category not in FEEDS:
        raise Error('Categoria non valida')
    return Path(state or STATE) / 'parental-lists' / (category + '.json')


def parse_feed(raw):
    if len(raw) > MAX_FEED_BYTES:
        raise Error('Lista troppo grande')
    values = set()
    for line in raw.decode('utf-8-sig').splitlines():
        value = line.strip()
        if not value or value.startswith(('#', '!')):
            continue
        values.add(domain(value, allow_tld=True))
        if len(values) > MAX_FEED_DOMAINS:
            raise Error('Lista oltre il limite di 300.000 domini')
    if not values:
        raise Error('Lista vuota: aggiornamento rifiutato')
    return sorted(values)


def download_feed(category):
    if category not in FEEDS:
        raise Error('Categoria non valida')
    conn = http.client.HTTPSConnection('raw.githubusercontent.com', timeout=30)
    path = '/hagezi/dns-blocklists/main/wildcard/' + FEEDS[category][1]
    try:
        conn.request('GET', path, headers={'User-Agent': 'Murus-Igneus-parental'})
        response = conn.getresponse()
        if response.status != 200:
            raise Error('Download lista HTTP ' + str(response.status))
        raw = response.read(MAX_FEED_BYTES + 1)
    finally:
        conn.close()
    values = parse_feed(raw)
    return {'category': category, 'domains': values, 'updated': time.time(),
            'source': 'https://raw.githubusercontent.com' + path, 'license': 'GPL-3.0',
            'sha256': hashlib.sha256(raw).hexdigest()}


def save_feed(state, category, payload):
    target = feed_path(category, state)
    if target.exists():
        security.write(target.with_suffix('.previous.json'), target.read_text())
    security.write(target, json.dumps(payload))


def update_feed(state, category):
    if category not in FEEDS:
        raise Error('Categoria non valida')
    def action():
        payload = download_feed(category)
        with LOCK:
            save_feed(state, category, payload)
        return {'category': category, 'domains': len(payload['domains']), 'message': 'Lista aggiornata. Verifica e riapplica la bozza per usarla nei profili.'}
    with LOCK:
        return TASK.start(action)


def load_domains(settings, state):
    result = {}
    for category in {c for p in active_profiles(settings) for c in p['categories']}:
        path = feed_path(category, state)
        if not path.exists():
            raise Error('Scaricare prima la lista parental: ' + FEEDS[category][0])
        data = json.loads(path.read_text())
        result[category] = names(data['domains'], MAX_FEED_DOMAINS, allow_tld=True)
    return result


def matches(host, values):
    labels = host.split('.')
    return any('.'.join(labels[i:]) in values for i in range(len(labels)))


def dns_config(profile, settings, interface, feeds, management, study=False):
    blocked = set(profile['blocked_domains'])
    for category in profile['categories']:
        blocked.update(feeds[category])
    for service in profile['services']:
        blocked.update(SERVICES[service])
    if profile['enforce_dns']:
        blocked.update(ENCRYPTED_DNS)
    allowed = profile['allowed_domains']
    allowed_set = set(allowed)
    blocked = {d for d in blocked if not matches(d, allowed_set)}
    BLOCKED[profile['id']] = set(blocked)
    if len(blocked) > 600000:
        raise Error('Profilo oltre il limite di 600.000 domini')
    lines = ['port=' + str(12000 + profile['id']), 'bind-interfaces', 'interface=' + interface['device'],
             'listen-address=' + str(ip.IPv4Interface(interface['address']).ip), 'except-interface=lo',
             'except-interface=' + management, 'no-resolv', 'no-hosts', 'no-poll', 'domain-needed', 'bogus-priv',
             'cache-size=512', 'dns-forward-max=50', 'user=root', 'group=root', 'log-facility=-']
    if settings.get('reporting', False):
        lines += ['log-queries=extra', 'log-async=20']
    lines += ['server=' + v for v in settings['upstream_servers']]
    lines += ['local=/' + v + '/' for v in sorted(blocked)]
    # A specific allow can override a blocked parent, but never encrypted DNS enforcement domains.
    for value in allowed:
        if profile['enforce_dns'] and any(value == d or value.endswith('.' + d) or d.endswith('.' + value) for d in ENCRYPTED_DNS):
            raise Error('Un’eccezione non può riabilitare un resolver cifrato noto mentre DNS forzato è attivo')
        lines += ['server=/' + value + '/' + upstream for upstream in settings['upstream_servers']]
    if study:
        lines += ['local=/#/']
        # During study even ordinary allow exceptions cannot widen the school allowlist.
        lines = [line for line in lines if not line.startswith('server=/')]
        for value in profile.get('study_domains', []):
            if not matches(value, blocked) and not (profile['enforce_dns'] and matches(value, set(ENCRYPTED_DNS))):
                lines += ['server=/' + value + '/' + upstream for upstream in settings['upstream_servers']]
    lines += safe_dns(profile, blocked, study)
    return '\n'.join(lines) + '\n'


# Explicit provider VIPs; no HTTPS interception. See docs/PARENTAL.md for source/scope.
GOOGLE_HOSTS = ('www.google.com', 'www.google.it', 'www.google.co.uk', 'www.google.fr', 'www.google.de', 'www.google.es')
YOUTUBE_HOSTS = ('www.youtube.com', 'm.youtube.com', 'youtubei.googleapis.com', 'youtube.googleapis.com', 'www.youtube-nocookie.com')


def safe_dns(profile, blocked, study):
    groups = []
    if profile.get('safe_search'):
        groups.append(('forcesafesearch.google.com', '216.239.38.120', GOOGLE_HOSTS))
    mode = profile.get('youtube_restricted', 'off')
    if mode != 'off':
        groups.append(('restrict.youtube.com' if mode == 'strict' else 'restrictmoderate.youtube.com',
                       '216.239.38.120' if mode == 'strict' else '216.239.38.119', YOUTUBE_HOSTS))
    lines = []
    for target, address, hosts in groups:
        permitted = [host for host in hosts if (not matches(host, blocked) or matches(host, set(profile['allowed_domains']))) and (not study or matches(host, set(profile.get('study_domains', []))))]
        if permitted:
            lines += ['host-record=' + target + ',' + address]
            for host in permitted:
                lines += ['cname=' + host + ',' + target, 'local=/' + host + '/']
    return lines


def in_mode(profile, key, timezone, now=None):
    windows = profile.get(key, [])
    return bool(windows) and in_window({'windows': windows}, timezone, now)


def in_window(profile, timezone, now=None):
    local = datetime.now(ZoneInfo(timezone)) if now is None else now.astimezone(ZoneInfo(timezone))
    if not profile['windows']:
        return True
    weekday = local.weekday(); current = local.hour * 60 + local.minute
    for window in profile['windows']:
        start = minute(window['start']); end = minute(window['end'])
        if start < end and weekday in window['days'] and start <= current < end:
            return True
        if start > end and ((weekday in window['days'] and current >= start) or ((weekday - 1) % 7 in window['days'] and current < end)):
            return True
    return False


def fingerprint(profile):
    value = {k: profile[k] for k in ('id', 'interface', 'clients')}
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def pauses(state):
    path = Path(state) / 'parental-pauses.json'
    return json.loads(path.read_text()) if path.exists() else {}


def bonus_key(profile):
    return hashlib.sha256(json.dumps(profile, sort_keys=True).encode()).hexdigest()


def bonuses(state):
    path = Path(state) / 'parental-bonuses.json'
    return json.loads(path.read_text()) if path.exists() else {}


def bonus(ident, minutes):
    with LOCK:
        if type(ident) is not int or type(minutes) is not int or not 0 <= minutes <= 240 or CURRENT is None:
            raise Error('Profilo o durata bonus non validi (0–240 minuti)')
        profile = next((p for p in active_profiles(CURRENT['settings']) if p['id'] == ident), None)
        if profile is None:
            raise Error('Profilo non attivo')
        data = bonuses(STATE); key = bonus_key(profile)
        if minutes:
            data[key] = time.time() + minutes * 60
        else:
            data.pop(key, None)
        known = {bonus_key(p) for p in active_profiles(CURRENT['settings'])}
        data = {k: v for k, v in data.items() if k in known and v > time.time()}
        security.write(Path(STATE) / 'parental-bonuses.json', json.dumps(data)); tick()
        return {'ok': True, 'profiles': copy.deepcopy(RUNTIME['profiles'])}


def drop_rules(profile, settings, interfaces):
    dev = json.dumps(next(r['device'] for r in interfaces if r['name'] == profile['interface']))
    if settings.get('reporting', False):
        result = []
        for row in reporting.entities(settings, interfaces):
            if row['profile'] == profile['id']:
                for hook, address in [('iifname', 'saddr'), ('oifname', 'daddr')]:
                    result.append(f'add rule inet murus_igneus pc_schedule {hook} {dev} ip {address} {row["client"]} counter name {reporting.counter(row, "blocked")} drop')
        return result
    clients = '{ ' + ', '.join(profile['clients']) + ' }'
    return [f'add rule inet murus_igneus pc_schedule iifname {dev} ip saddr {clients} counter drop comment "parental {profile["id"]}"',
            f'add rule inet murus_igneus pc_schedule oifname {dev} ip daddr {clients} counter drop comment "parental {profile["id"]}"']


def schedule_rules(settings, interfaces, overrides, now=None, ready=None, grants=None):
    lines = ['flush chain inet murus_igneus pc_schedule']; rows = []
    stamp = time.time() if now is None else now.timestamp()
    for p in active_profiles(settings):
        temporary = overrides.get(fingerprint(p), 0)
        failed = ready is not None and not ready.get(p['id'], False)
        grant = (grants or {}).get(bonus_key(p), 0)
        night = in_mode(p, 'night_windows', settings['timezone'], now)
        study = in_mode(p, 'study_windows', settings['timezone'], now)
        reason = 'resolver fermo' if failed else 'pausa' if p['paused'] or temporary > stamp else 'notte' if night and grant <= stamp else 'fuori orario' if grant <= stamp and not in_window(p, settings['timezone'], now) else ''
        rows.append({'id': p['id'], 'name': p['name'], 'blocked': bool(reason), 'reason': reason,
                     'pause_until': temporary if temporary > stamp else None, 'resolver_running': not failed, 'bonus_until': grant if grant > stamp else None,
                     'study': study, 'devices': copy.deepcopy(p.get('devices', [])), 'ipv6_blocked_lan': p.get('block_ipv6', False)})
        if reason:
            lines += drop_rules(p, settings, interfaces)
    return '\n'.join(lines) + '\n', rows


def tick(now=None):
    global LAST_RULES
    with LOCK:
        if CURRENT is None:
            return
        settings = CURRENT['settings']; interfaces = CURRENT['interfaces']
        synchronize_dns(now)
        ready = {p['id']: bool(security.PROCESSES.get('parental-' + str(p['id'])) and security.PROCESSES['parental-' + str(p['id'])].poll() is None and DNS_MODES.get(p['id']) == in_mode(p, 'study_windows', settings['timezone'], now)) for p in active_profiles(settings)}
        script, rows = schedule_rules(settings, interfaces, pauses(STATE), now, ready, bonuses(STATE))
        if script != LAST_RULES:
            security.command(['nft', '-f', '-'], script); LAST_RULES = script
        RUNTIME.update(running=True, profiles=rows)


def pause(ident, minutes):
    with LOCK:
        if type(ident) is not int or not 1 <= ident <= 8:
            raise Error('ID profilo non valido')
        if CURRENT is None:
            raise Error('Parental control non attivo')
        profile = next((p for p in active_profiles(CURRENT['settings']) if p['id'] == ident), None)
        if profile is None or type(minutes) is not int or not 0 <= minutes <= 1440:
            raise Error('Profilo o durata pausa non validi (0–1440 minuti)')
        data = pauses(STATE); key = fingerprint(profile)
        if minutes:
            data[key] = time.time() + minutes * 60
        else:
            data.pop(key, None)
        # Drop expired and no-longer-matching overrides to keep the file bounded.
        known = {fingerprint(p) for p in active_profiles(CURRENT['settings'])}
        data = {k:v for k,v in data.items() if k in known and v > time.time()}
        security.write(Path(STATE) / 'parental-pauses.json', json.dumps(data)); tick()
        return {'ok': True, 'profiles': copy.deepcopy(RUNTIME['profiles'])}


def stop():
    global THREAD, CURRENT, LAST_RULES, REPORTER
    STOP.set()
    if THREAD is not None:
        THREAD.join(); THREAD = None
    with LOCK:
        CURRENT = None; LAST_RULES = None; DNS_MODES.clear(); DNS_RETRY.clear()
        for name in list(security.PROCESSES):
            if name.startswith('parental-'):
                security.stop(name)
        if REPORTER is not None:
            REPORTER.stop(); REPORTER = None
        RUNTIME.update(running=False, profiles=[], error='')


def activate(plan, state, management):
    global STATE, CURRENT, THREAD, REPORTER, MANAGEMENT, AUTO_NEXT
    stage(plan)
    stop(); STATE = Path(state); MANAGEMENT = management; AUTO_NEXT = 0
    AUTO_STATUS.update(last_success=None, error='')
    status_path = STATE / 'parental-auto-update.json'
    if status_path.exists():
        try:
            stored = json.loads(status_path.read_text())
            AUTO_STATUS.update(last_success=stored.get('last_success'))
        except (ValueError, TypeError, AttributeError):
            AUTO_STATUS['error'] = 'Storico aggiornamenti non leggibile'
    if not plan or not active_profiles(plan['settings']):
        return
    settings = plan['settings']; profiles = active_profiles(settings); ports = {r['name']: r for r in plan['interfaces']}
    feeds = load_domains(settings, STATE)
    try:
        if settings.get('reporting', False):
            REPORTER = reporting.Collector(settings, plan['interfaces'], STATE)
        for profile in profiles:
            name = 'parental-' + str(profile['id']); path = security.RUN / (name + '.conf')
            study = in_mode(profile, 'study_windows', settings['timezone'])
            security.write(path, dns_config(profile, settings, ports[profile['interface']], feeds, management, study))
            DNS_MODES[profile['id']] = study
            security.command(['dnsmasq', '--test', '--conf-file=' + str(path)])
            args = ['dnsmasq', '--keep-in-foreground', '--conf-file=' + str(path), '--pid-file=']
            if REPORTER is not None:
                REPORTER.spawn(profile['id'], name, args)
            else:
                security.spawn(name, args)
        time.sleep(.25)
        if any(security.PROCESSES['parental-' + str(p['id'])].poll() is not None for p in profiles):
            raise Error('Resolver parental non avviato; verificare indirizzi e porte')
        CURRENT = copy.deepcopy(plan); tick(); STOP.clear()
        if REPORTER is not None:
            REPORTER.start()
        def worker():
            while not STOP.wait(2):
                try:
                    tick()
                    maybe_update()
                except Exception as exc:
                    with LOCK:
                        RUNTIME['error'] = str(exc)[:300]
                    # Keep any existing blocks. If nft itself fails, report it rather than claiming protection.
        THREAD = threading.Thread(target=worker, daemon=True, name='murus-parental'); THREAD.start()
    except Exception:
        stop(); raise


def inventory(state):
    lists = []
    for category, (label, filename) in FEEDS.items():
        path = feed_path(category, state); entry = {'id': category, 'name': label, 'license': 'GPL-3.0', 'source': 'https://github.com/hagezi/dns-blocklists', 'ready': False}
        if path.exists():
            try:
                data = json.loads(path.read_text()); entry.update(ready=True, count=len(data['domains']), updated=data['updated'], sha256=data['sha256'], stale=time.time() - data['updated'] > 2 * 86400)
            except (ValueError, KeyError, TypeError):
                entry['error'] = 'Lista locale non valida: riscaricarla'
        lists.append(entry)
    with LOCK:
        return {**copy.deepcopy(RUNTIME), 'lists': lists, 'services': list(SERVICES), 'task': TASK.status(),
                'auto_update': {**AUTO_STATUS, 'enabled': bool(CURRENT and CURRENT['settings'].get('auto_update')), 'next_check': AUTO_NEXT or None},
                'note': 'Filtra domini, non contenuti HTTPS. VPN/DoH sconosciuti, IP modificati fuori dal profilo, rete mobile e traffico che non attraversa Murus possono aggirarlo.'}


def stage(plan):
    global GUARD
    with LOCK:
        GUARD = copy.deepcopy(plan)


def proxy_allowed(client, hostname):
    """The local HTTP antivirus proxy must not bypass profile filters/schedules."""
    with LOCK:
        if not GUARD:
            return True
        address = ip.IPv4Address(client)
        profile = next((p for p in active_profiles(GUARD['settings']) if any(address in ip.IPv4Network(n) for n in p['clients'])), None)
        if profile is None:
            return True
        if not CURRENT or not RUNTIME['running'] or RUNTIME['error']:
            return False
        row = next((r for r in RUNTIME['profiles'] if r['id'] == profile['id']), None)
        if row is None or row['blocked']:
            return False
        try:
            hostname = domain(hostname)
        except ValueError:
            return False
        if profile['enforce_dns'] and matches(hostname, set(ENCRYPTED_DNS)):
            return False
        if (profile.get('safe_search') and hostname in GOOGLE_HOSTS) or (profile.get('youtube_restricted', 'off') != 'off' and hostname in YOUTUBE_HOSTS):
            return False  # The HTTP proxy resolves independently; it must not bypass DNS provider VIPs.
        if row.get('study') and not matches(hostname, set(profile.get('study_domains', []))):
            return False
        if matches(hostname, set(profile['allowed_domains'])):
            return True
        return not matches(hostname, BLOCKED.get(profile['id'], set()))


def preflight(plan, state):
    if plan and active_profiles(plan['settings']):
        load_domains(plan['settings'], state)


def clear_report(state):
    with LOCK:
        if REPORTER is not None:
            REPORTER.clear()
        else:
            reporting.erase(state)
    return {'ok': True}


DNS_RETRY = {}
UPDATE_ALLOWED = lambda: True


def start_resolver(ident):
    name = 'parental-' + str(ident)
    security.stop(name)
    args = ['dnsmasq', '--keep-in-foreground', '--conf-file=' + str(security.RUN / (name + '.conf')), '--pid-file=']
    if REPORTER is not None:
        REPORTER.spawn(ident, name, args)
    else:
        security.spawn(name, args)
    time.sleep(.1)
    if security.PROCESSES[name].poll() is not None:
        raise Error('Resolver parental non avviato')
    if REPORTER is not None:
        # Finished readers are joined/pruned on every restart, bounding long-lived memory.
        REPORTER.readers = [thread for thread in REPORTER.readers if thread.is_alive()]


def replace_dns(feeds, now=None):
    """Validate all candidates before switching; restore every previous resolver on failure.

    Caller holds LOCK. Firewall, VPN, DHCP and reporting counters are untouched.
    """
    settings = CURRENT['settings']; ports = {r['name']: r for r in CURRENT['interfaces']}
    old_blocked = copy.deepcopy(BLOCKED); old_modes = DNS_MODES.copy(); old = {}; candidates = {}; touched = []
    try:
        for p in active_profiles(settings):
            ident = p['id']; path = security.RUN / ('parental-' + str(ident) + '.conf')
            old[ident] = path.read_text()
            study = in_mode(p, 'study_windows', settings['timezone'], now)
            data = dns_config(p, settings, ports[p['interface']], feeds, MANAGEMENT, study)
            check = path.with_suffix('.candidate')
            security.write(check, data)
            try:
                security.command(['dnsmasq', '--test', '--conf-file=' + str(check)])
            finally:
                check.unlink(missing_ok=True)
            candidates[ident] = (path, data, study)
        for ident, (path, data, study) in candidates.items():
            touched.append(ident)
            security.write(path, data); start_resolver(ident); DNS_MODES[ident] = study
    except Exception as exc:
        failures = []
        for ident in touched:
            data = old[ident]
            try:
                security.write(security.RUN / ('parental-' + str(ident) + '.conf'), data)
                start_resolver(ident)
            except Exception as recovery:
                failures.append(str(recovery)[:150])
        BLOCKED.clear(); BLOCKED.update(old_blocked); DNS_MODES.clear(); DNS_MODES.update(old_modes)
        raise Error('Aggiornamento DNS annullato: ' + str(exc)[:200] + ('; ripristino incompleto: ' + '; '.join(failures) if failures else '')) from exc


def synchronize_dns(now=None):
    settings = CURRENT['settings']; stamp = time.monotonic()
    changed = [p for p in active_profiles(settings) if DNS_MODES.get(p['id']) != in_mode(p, 'study_windows', settings['timezone'], now)]
    if not changed or any(DNS_RETRY.get(p['id'], 0) > stamp for p in changed):
        return
    try:
        replace_dns(load_domains(settings, STATE), now)
        RUNTIME['error'] = ''
    except Exception as exc:
        for p in changed:
            DNS_RETRY[p['id']] = stamp + 30
        RUNTIME['error'] = str(exc)[:300]
        # tick observes the mode mismatch and blocks transit until a successful retry.


def refresh_active_lists(expected):
    """Download outside the runtime lock; reject results for a stopped/replaced plan."""
    settings = expected['settings']; state = STATE
    categories = sorted({c for p in active_profiles(settings) for c in p['categories']})
    payloads = {category: download_feed(category) for category in categories}
    with LOCK:
        if CURRENT is not expected or STOP.is_set() or not UPDATE_ALLOWED():
            raise Error('Configurazione cambiata: aggiornamento automatico rinviato')
        previous = {c: feed_path(c, state).read_text() for c in categories}
        old_feeds = load_domains(settings, state)
        try:
            for category, payload in payloads.items():
                save_feed(state, category, payload)
            replace_dns({c: p['domains'] for c, p in payloads.items()})
            tick()
        except Exception:
            for category, data in previous.items():
                security.write(feed_path(category, state), data)
            # replace_dns restores configs on restart failure. Also restore after a later nft failure.
            replace_dns(old_feeds)
            tick()
            raise
        AUTO_STATUS.update(last_success=time.time(), error='')
        security.write(Path(state) / 'parental-auto-update.json', json.dumps(AUTO_STATUS))
        return {'message': 'Liste aggiornate e attivate nei resolver; rete e VPN conservate.'}


def maybe_update():
    global AUTO_NEXT
    with LOCK:
        if CURRENT is None or STOP.is_set() or not CURRENT['settings'].get('auto_update') or not UPDATE_ALLOWED():
            return
        if time.time() < AUTO_NEXT or (TASK.status() or {}).get('state') == 'running':
            return
        settings = CURRENT['settings']; categories = {c for p in active_profiles(settings) for c in p['categories']}
        if not categories:
            AUTO_NEXT = time.time() + 3600
            return
        due = any(not feed_path(c).exists() or time.time() - json.loads(feed_path(c).read_text())['updated'] >= 86400 for c in categories)
        AUTO_NEXT = time.time() + 3600  # On failure retry in an hour; no tight retry loop.
        if not due:
            return
        expected = CURRENT
        def action():
            try:
                return refresh_active_lists(expected)
            except Exception as exc:
                with LOCK:
                    if CURRENT is expected:
                        AUTO_STATUS['error'] = str(exc)[:300]
                raise
        TASK.start(action)
