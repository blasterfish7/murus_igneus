"""Opt-in OpenSSH administration on the management interface. MIT."""
import base64
import binascii
import ipaddress
from pathlib import Path
import time

try:
    from . import security
    from .migration import Error, Q
except ImportError:
    import security
    from migration import Error, Q

SSHD = Path('/usr/sbin/sshd')
NAME = 'admin-ssh'


def defaults():
    return {'enabled': False, 'sources': [], 'keys': []}


def validate(value):
    if not isinstance(value, dict) or set(value) != set(defaults()) or type(value['enabled']) is not bool:
        raise Error('Configurazione SSH non valida')
    sources, keys = value['sources'], value['keys']
    if not isinstance(sources, list) or len(sources) > 16 or not all(isinstance(s, str) and len(s) <= 32 for s in sources):
        raise Error('Specificare fino a 16 sorgenti IPv4/CIDR')
    nets = list(ipaddress.collapse_addresses(ipaddress.IPv4Network(s) for s in sources))
    if any(n.prefixlen == 0 for n in nets):
        raise Error('SSH richiede sorgenti esplicite; 0.0.0.0/0 non è ammesso')
    if not isinstance(keys, list) or len(keys) > 8:
        raise Error('Specificare fino a 8 chiavi SSH pubbliche')
    canonical = []
    for key in keys:
        parts = key.split() if isinstance(key, str) and len(key) <= 512 and '\n' not in key and '\r' not in key else []
        if len(parts) < 2 or parts[0] != 'ssh-ed25519':
            raise Error('Usare chiavi pubbliche ssh-ed25519, senza opzioni')
        try:
            blob = base64.b64decode(parts[1], validate=True)
        except (ValueError, binascii.Error):
            raise Error('Chiave pubblica SSH non valida') from None
        if len(blob) != 51 or not blob.startswith(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'):
            raise Error('Chiave pubblica SSH non valida')
        canonical.append('ssh-ed25519 ' + base64.b64encode(blob).decode())
    if value['enabled'] and (not nets or not canonical):
        raise Error('Per attivare SSH servono almeno una sorgente IPv4 e una chiave pubblica')
    return {'enabled': value['enabled'], 'sources': list(dict.fromkeys(map(str, nets))),
            'keys': list(dict.fromkeys(canonical))}


def decorate(plan, settings, management):
    if settings == defaults():
        return
    plan['configuration']['admin_ssh'] = settings
    if settings['enabled']:
        sources = '{ ' + ', '.join(settings['sources']) + ' }'
        plan['nftables'] += (f'insert rule inet murus_igneus input iifname {Q(management)} ip saddr {sources} '
                             'tcp dport 22 ct state { new, established } accept comment "Murus SSH management"\n')


def inventory(state):
    p = security.PROCESSES.get(NAME)
    return {'available': SSHD.is_file(), 'live': (state/'live-image').exists(),
            'running': p is not None and p.poll() is None}


def preflight(settings, state):
    if settings.get('enabled'):
        status = inventory(state)
        if status['live'] or not status['available']:
            raise Error('SSH richiede OpenSSH su Murus installato su disco')


def stop():
    security.stop(NAME)


def sshd_config(hostkey, authorized_keys):
    return f"""Port 22
AddressFamily inet
HostKey {hostkey}
AuthorizedKeysFile {authorized_keys}
AllowUsers root
PermitRootLogin prohibit-password
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
DisableForwarding yes
PermitTunnel no
PermitUserEnvironment no
PermitUserRC no
MaxAuthTries 3
LoginGraceTime 30
"""


def start(settings, state):
    if not settings.get('enabled'):
        return
    settings = validate(settings)
    preflight(settings, state)
    host = state / 'ssh_host_ed25519_key'
    if not host.exists():
        security.command(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(host)])
    Path('/run/sshd').mkdir(mode=0o755, exist_ok=True)
    keys = security.RUN / 'admin-ssh.keys'
    config = security.RUN / 'admin-ssh.conf'
    security.write(keys, '\n'.join(settings['keys']) + '\n')
    security.write(config, sshd_config(host, keys))
    args = [str(SSHD), '-f', str(config)]
    security.command(args + ['-t'])
    security.spawn(NAME, args + ['-D', '-e'])
    time.sleep(.25)
    if security.PROCESSES[NAME].poll() is not None:
        stop()
        raise Error('OpenSSH non avviato: verificare la porta TCP 22 dalla console')
