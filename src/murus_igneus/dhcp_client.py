"""Owned IPv4 DHCP client leases; no shell-supplied network values. SPDX-License-Identifier: MIT."""
import contextlib
import fcntl
import ipaddress as ip
import json
import os
from pathlib import Path
import secrets
import shlex
import signal
import sys
import threading
import time

try:
    from . import security
    from .migration import Error
except ImportError:
    sys.path.insert(0,str(Path(__file__).resolve().parent))
    import security
    from migration import Error

WATCHER = None
GUARD = threading.RLock()


def command(args):
    return security.command(args)


def write(path, data):
    temporary = path.with_suffix('.tmp')
    fd = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(data, stream)
    temporary.replace(path)


@contextlib.contextmanager
def locked(path):
    with path.with_suffix('.lock').open('a') as lock:
        os.chmod(lock.name, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield json.loads(path.read_text())


def cleanup(state):
    route = state.get('route')
    dev = state['device']
    if route:
        actual = json.loads(command(['ip','-j','-4','route','show','default']))
        if any(r.get('dev') == dev and r.get('gateway') == route and r.get('metric') == state['metric'] and str(r.get('protocol')) == '202' for r in actual):
            command(['ip','route','del','default','via',route,'dev',dev,'metric',str(state['metric']),'proto','202'])
        state['route'] = None
    address = state.get('address')
    if address:
        actual = json.loads(command(['ip','-j','-4','addr','show','dev',dev]))
        if any(str(ip.IPv4Interface(a['local']+'/'+str(a['prefixlen']))) == address for row in actual for a in row.get('addr_info', [])):
            command(['ip','addr','del',address,'dev',dev])
        state['address'] = None
    state['expires'] = 0


def lease(values, reserved):
    interface = ip.IPv4Interface(values['ip'] + '/' + values['subnet'])
    if interface.ip.is_unspecified or interface.ip.is_loopback or interface.ip.is_multicast or interface.ip.is_link_local or interface.ip in (interface.network.network_address, interface.network.broadcast_address):
        raise Error('Indirizzo DHCP non utilizzabile')
    if any(interface.network.overlaps(ip.IPv4Network(n)) for n in reserved):
        raise Error('La rete DHCP si sovrappone a gestione, VPN o altra rete locale')
    routers = values.get('router', '').split()
    gateway = str(ip.IPv4Address(routers[0])) if routers else None
    if gateway and (ip.IPv4Address(gateway) not in interface.network or ip.IPv4Address(gateway) in (interface.ip, interface.network.network_address, interface.network.broadcast_address)):
        raise Error('Gateway DHCP non valido nella subnet ricevuta')
    duration = int(values.get('lease', '3600'))
    if not 10 <= duration <= 604800:
        raise Error('Durata lease DHCP fuori intervallo')
    dns = [str(ip.IPv4Address(n)) for n in values.get('dns', '').split()[:8]]
    return str(interface), gateway, duration, dns


def hook(path, token, reason, values):
    with locked(path) as state:
        if not state['enabled'] or state['token'] != token:
            return
        try:
            if reason in ('deconfig', 'nak', 'leasefail'):
                cleanup(state);state['error'] = 'Lease DHCP non disponibile'
            elif reason in ('bound', 'renew'):
                if values.get('interface') != state['device']:
                    raise Error('Interfaccia DHCP inattesa')
                info = json.loads(command(['ip','-j','link','show','dev',state['device']]))[0]
                if info['ifindex'] != state['ifindex']:
                    raise Error('Scheda DHCP sostituita durante il servizio')
                address, gateway, duration, dns = lease(values, state['reserved'])
                if address != state.get('address') or gateway != state.get('route'):
                    cleanup(state)
                    actual = json.loads(command(['ip','-j','-4','addr','show','dev',state['device']]))
                    if any(row.get('addr_info') for row in actual):
                        raise Error('IPv4 presente fuori dal client DHCP gestito')
                    command(['ip','addr','add',address,'dev',state['device']]);state['address'] = address
                    if gateway:
                        command(['ip','route','add','default','via',gateway,'dev',state['device'],'metric',str(state['metric']),'proto','202']);state['route'] = gateway
                state.update(expires=time.monotonic()+duration,dns=dns,error='')
        except Exception as exc:
            state['error'] = str(exc)[:300]
        finally:
            write(path, state)


def stop():
    with GUARD:
        root = security.RUN/'dhcp-clients'
        if not root.exists():
            return
        for path in root.glob('*/state.json'):
            with locked(path) as state:
                state['enabled'] = False
                write(path, state)
                cleanup(state)
                write(path, state)
            name = state['process']
            if name in security.PROCESSES:
                security.stop(name)
            elif state.get('pid'):
                # Recover only an exact former owned command, never a reused PID.
                try:
                    args = Path('/proc/'+str(state['pid'])+'/cmdline').read_bytes().split(b'\x00')
                    if state['script'].encode() in args and args[0].endswith(b'udhcpc'):
                        os.kill(state['pid'], signal.SIGTERM)
                except (FileNotFoundError, ProcessLookupError):
                    pass
            path.unlink(missing_ok=True)
            for name in ('hook','pid','state.lock','state.tmp'):
                (path.parent/name).unlink(missing_ok=True)
            try:path.parent.rmdir()
            except OSError:pass  # A retiring hook may still hold its private lock file; no lease remains.


def watch():
    while True:
        time.sleep(1)
        with GUARD:
            root = security.RUN/'dhcp-clients'
            for path in root.glob('*/state.json'):
                try:
                    with locked(path) as state:
                        process = security.PROCESSES.get(state['process'])
                        if state['enabled'] and state.get('address') and (state['expires'] <= time.monotonic() or not process or process.poll() is not None):
                            cleanup(state);state['error'] = 'Lease DHCP scaduto o client arrestato';write(path,state)
                except Exception:
                    # A failed expiry cleanup must not leave transit using a stale lease.
                    try:
                        from migration import baseline
                    except ImportError:
                        from .migration import baseline
                    security.command(['nft','-f','-'],baseline(state['management']))


def start(settings, management):
    global WATCHER
    rows = [r for r in settings['interfaces'] if r.get('address_mode') == 'dhcp']
    if not rows:
        return
    with GUARD:
        all_addresses = json.loads(command(['ip','-j','-4','address','show']))
        reserved = [str(ip.IPv4Interface(a['local']+'/'+str(a['prefixlen'])).network) for row in all_addresses if row['ifname'] != 'lo' for a in row.get('addr_info', [])]
        for row in rows:
            dev = row['device']
            if dev in (management, 'lo', security.WG):
                raise Error('DHCP client non consentito sulla gestione o sul tunnel')
            existing = json.loads(command(['ip','-j','-4','addr','show','dev',dev]))
            if any(r.get('addr_info') for r in existing):
                raise Error('Rimuovere la configurazione IPv4 esterna prima di attivare DHCP su '+dev)
            token = secrets.token_hex(16);folder = security.RUN/'dhcp-clients'/(dev+'-'+token)
            folder.mkdir(mode=0o700, parents=True);folder.parent.chmod(0o700)
            path = folder/'state.json';script = folder/'hook'
            name = 'dhcp-client-'+dev
            info = json.loads(command(['ip','-j','link','show','dev',dev]))[0]
            state = {'enabled':True,'token':token,'device':dev,'ifindex':info['ifindex'],'metric':row.get('dhcp_metric',100),'reserved':reserved,'address':None,'route':None,'expires':0,'error':'','dns':[],'pid':None,'process':name,'script':str(script),'management':management}
            write(path,state)
            script.write_text('#!/bin/sh\nexec /usr/bin/python3 -I '+shlex.quote(str(Path(__file__).resolve()))+' '+shlex.quote(str(path))+' '+token+' "$1"\n');script.chmod(0o700)
            command(['nft','add','rule','inet','murus_igneus','input','iifname',json.dumps(dev),'udp','sport','67','udp','dport','68','accept'])
            security.spawn(name,['udhcpc','-f','-n','-t','3','-T','3','-i',dev,'-s',str(script),'-p',str(folder/'pid')])
            with locked(path) as current:
                current['pid'] = security.PROCESSES[name].pid;write(path,current)
            deadline = time.monotonic()+15
            while time.monotonic() < deadline:
                current = json.loads(path.read_text())
                if current.get('address') and not current.get('error'):
                    break
                if current.get('error') and current['error'] != 'Lease DHCP non disponibile':
                    raise Error(current['error'])
                if security.PROCESSES[name].poll() is not None:
                    raise Error('Client DHCP arrestato senza un lease valido su '+dev)
                time.sleep(.1)
            else:
                raise Error('Nessuna risposta DHCP valida su '+dev+' entro 15 secondi')
        if WATCHER is None:
            WATCHER = threading.Thread(target=watch,daemon=True);WATCHER.start()


def health():
    result = []
    with GUARD:
        for path in (security.RUN/'dhcp-clients').glob('*/state.json'):
            state = json.loads(path.read_text())
            if state['enabled']:
                result.append({k:state[k] for k in ('device','address','route','dns','error')})
    return result


if __name__ == '__main__':
    hook(Path(sys.argv[1]),sys.argv[2],sys.argv[3],os.environ)
