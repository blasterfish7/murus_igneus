"""WireGuard and Suricata/ClamAV integration. SPDX-License-Identifier: MIT."""
import base64
import copy
import ipaddress as ip
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import threading
import time
from migration import Error

STATE=Path('/etc/murus_igneus');RUN=Path('/run/murus-igneus');WG='mivpn0'
PROCESSES={};LOGS={};PROXY=None
DEFAULT_RULES='''drop http any any -> any any (msg:"Murus HTTP path traversal"; flow:established,to_server; http.uri; content:"/etc/passwd"; nocase; sid:9900001; rev:1;)
drop http any any -> any any (msg:"Murus HTTP Shellshock pattern"; flow:established,to_server; http.header; content:"() {"; sid:9900002; rev:1;)
'''

def defaults():
    return {'vpn':{'enabled':False,'address':'10.77.0.1/24','port':51820,'public_device':'eth1','peers':[]},'utm':{'ips':False,'rules':DEFAULT_RULES,'proxy':False,'proxy_device':'eth2','clients':['192.168.10.0/24'],'upstream_networks':[],'blocked_domains':[],'enforce_http':True}}

def command(args,data=None,check=True,timeout=60):
    p=subprocess.run(args,input=data,text=True,capture_output=True,timeout=timeout)
    if check and p.returncode:raise Error((p.stderr or p.stdout or 'Comando fallito')[-2000:])
    return p.stdout

def write(path,data,mode=0o600):
    path.parent.mkdir(parents=True,exist_ok=True);temp=path.with_suffix('.tmp');temp.write_text(data);temp.chmod(mode);temp.replace(path)

def key(value):
    try:return isinstance(value,str) and len(base64.b64decode(value,validate=True))==32
    except ValueError:return False

def validate(config,management):
    result=defaults()
    for section in result:
        if section in config:
            if not isinstance(config[section],dict) or set(config[section])-set(result[section]):raise Error('Campi non validi: '+section)
            result[section].update(copy.deepcopy(config[section]))
    v,u=result['vpn'],result['utm']
    for d,k in ((v,'enabled'),(u,'ips'),(u,'proxy'),(u,'enforce_http')):
        if type(d[k])!=bool:raise Error('Booleano non valido: '+k)
    for d,k,enabled in ((v,'public_device',v['enabled']),(u,'proxy_device',u['proxy'])):
        if not isinstance(d[k],str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',d[k]) or (enabled and d[k] in ('lo',management,WG)):raise Error('Porta dati non valida: '+k)
    a=ip.IPv4Interface(v['address']);v['address']=str(a)
    if type(v['port'])!=int or not 1024<=v['port']<=65535:raise Error('Porta VPN non valida')
    if not isinstance(v['peers'],list) or len(v['peers'])>100:raise Error('Elenco peer non valido')
    seen=set();networks=[]
    for p in v['peers']:
        if not isinstance(p,dict) or set(p)-{'name','public_key','allowed_ips','endpoint','keepalive'}:raise Error('Peer non valido')
        if not key(p.get('public_key')) or p['public_key'] in seen:raise Error('Chiave peer non valida o duplicata')
        seen.add(p['public_key'])
        if not isinstance(p.get('allowed_ips'),list) or not p['allowed_ips']:raise Error('Specificare le reti remote del peer')
        current=[ip.IPv4Network(n,strict=False) for n in p['allowed_ips']]
        if any(a.ip in n for n in current):raise Error('Una rete peer contiene l’indirizzo del server VPN')
        if any(n.prefixlen==0 or n.is_multicast or n.is_loopback for n in current):raise Error('La VPN supporta rotte specifiche, non una default route')
        if any(n.overlaps(old) for n in current for old in networks):raise Error('Reti sovrapposte tra peer')
        networks+=current;p['allowed_ips']=[str(n) for n in current]
        ep=p.get('endpoint','')
        if ep and (not re.fullmatch(r'[A-Za-z0-9.-]+:[0-9]{1,5}',ep) or not 1<=int(ep.rsplit(':',1)[1])<=65535):raise Error('Endpoint: usare host:porta IPv4')
        keep=p.get('keepalive',25)
        if type(keep)!=int or not 0<=keep<=65535:raise Error('Keepalive non valido')
        p['keepalive']=keep
    for field in ('clients','upstream_networks'):
        if not isinstance(u[field],list) or len(u[field])>100:raise Error('Elenco reti non valido')
        u[field]=[str(ip.IPv4Network(n,strict=False)) for n in u[field]]
    if u['proxy'] and not u['clients']:raise Error('Specificare le reti autorizzate al proxy')
    if not isinstance(u['blocked_domains'],list) or len(u['blocked_domains'])>1000:raise Error('Elenco domini non valido')
    u['blocked_domains']=[n.lower().rstrip('.') for n in u['blocked_domains']]
    if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?',n) for n in u['blocked_domains']):raise Error('Dominio non valido')
    if not isinstance(u['rules'],str) or len(u['rules'].encode())>1024*1024:raise Error('Regole IPS troppo grandi')
    if u['ips'] and not any(line.strip() and not line.lstrip().startswith('#') for line in u['rules'].splitlines()) and not Path('/var/lib/suricata/rules/suricata.rules').exists():raise Error('Nessuna firma IPS configurata')
    return result

def decorate(script,settings):
    v,u=settings['vpn'],settings['utm'];lines=[]
    if v['enabled']:lines.append(f'add rule inet murus_igneus input iifname {json.dumps(v["public_device"])} udp dport {v["port"]} accept')
    if u['proxy']:
        nets=', '.join(u['clients']);dev=json.dumps(u['proxy_device'])
        lines.append(f'add rule inet murus_igneus input iifname {dev} ip saddr {{ {nets} }} tcp dport 3128 accept')
    if u['ips'] or (u['proxy'] and u['enforce_http']):
        lines.append('add chain inet murus_igneus inspection { type filter hook forward priority 10; policy accept; }')
        if u['proxy'] and u['enforce_http']:lines.append(f'add rule inet murus_igneus inspection iifname {json.dumps(u["proxy_device"])} ip saddr {{ '+', '.join(u['clients'])+' } tcp dport 80 drop')
        if u['ips']:lines.append('add rule inet murus_igneus inspection meta nfproto ipv4 queue num 0')
    return script+'\n'+'\n'.join(lines)+'\n' if lines else script

def public_key():
    STATE.mkdir(mode=0o700,exist_ok=True)
    path=STATE/'wireguard.key'
    if not path.exists():write(path,command(['wg','genkey']).strip()+'\n')
    return command(['wg','pubkey'],path.read_text()).strip()

def vpn_start(v):
    if not v['enabled']:
        command(['ip','link','del',WG],check=False);return
    command(['modprobe','wireguard']);public_key();RUN.mkdir(exist_ok=True)
    created=not Path('/sys/class/net/'+WG).exists()
    if created:command(['ip','link','add',WG,'type','wireguard'])
    try:
        text='[Interface]\nPrivateKey = '+(STATE/'wireguard.key').read_text().strip()+'\nListenPort = '+str(v['port'])+'\n'
        for p in v['peers']:
            text+='\n[Peer]\nPublicKey = '+p['public_key']+'\nAllowedIPs = '+', '.join(p['allowed_ips'])+'\nPersistentKeepalive = '+str(p['keepalive'])+'\n'
            if p.get('endpoint'):text+='Endpoint = '+p['endpoint']+'\n'
        path=RUN/'wireguard.conf';write(path,text)
        # syncconf preserves current handshakes when a firewall-only edit is applied.
        try:command(['wg','syncconf',WG,str(path)])
        finally:path.unlink(missing_ok=True)
        addresses=json.loads(command(['ip','-j','-4','addr','show','dev',WG]))
        current={a['local']+'/'+str(a['prefixlen']) for row in addresses for a in row.get('addr_info',[])}
        for old in current-{v['address']}:command(['ip','addr','del',old,'dev',WG])
        if v['address'] not in current:command(['ip','addr','add',v['address'],'dev',WG])
        command(['ip','link','set',WG,'mtu','1420','up'])
        local=ip.IPv4Interface(v['address']).network
        wanted={n for p in v['peers'] for n in p['allowed_ips'] if not ip.IPv4Network(n).subnet_of(local)}
        routes=json.loads(command(['ip','-j','-4','route','show','dev',WG]))
        existing={str(ip.IPv4Network(r['dst'],strict=False)) for r in routes if r.get('protocol')!='kernel' and r.get('metric')==50}
        for n in existing-wanted:command(['ip','route','del',n,'dev',WG,'metric','50'])
        for n in wanted-existing:command(['ip','route','add',n,'dev',WG,'metric','50'])
    except Exception:
        if created:command(['ip','link','del',WG],check=False)
        raise

def stop(name):
    p=PROCESSES.pop(name,None)
    if p and p.poll() is None:
        p.terminate()
        try:p.wait(timeout=10)
        except subprocess.TimeoutExpired:p.kill();p.wait()
    f=LOGS.pop(name,None)
    if f:f.close()

def spawn(name,args):
    RUN.mkdir(exist_ok=True);f=(RUN/(name+'.log')).open('a');LOGS[name]=f
    PROCESSES[name]=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.STDOUT,close_fds=True)

def suricata_config(u):
    import yaml
    c=yaml.safe_load(Path('/etc/suricata/suricata.yaml').read_text())
    write(STATE/'local.rules',u['rules'],0o644)
    rules=[str(STATE/'local.rules')]
    if Path('/var/lib/suricata/rules/suricata.rules').exists():rules.insert(0,'/var/lib/suricata/rules/suricata.rules')
    c['rule-files']=rules;c['stream']['inline']=True
    c.setdefault('vars',{}).setdefault('address-groups',{})['HOME_NET']='['+', '.join(u['clients'])+']'
    c['stats']={'enabled':False};c['default-log-dir']='/var/log/murus-suricata'
    c['outputs']=[{'eve-log':{'enabled':True,'filetype':'regular','filename':'eve.json','types':['alert','drop']}}]
    c['run-as']={'user':'root','group':'root'}
    c['nfq']=c.get('nfq') or {};c['nfq']['mode']='accept';c['unix-command']={'enabled':False}
    path=RUN/'suricata.yaml';write(path,'%YAML 1.1\n---\n'+json.dumps(c),0o600);Path(c['default-log-dir']).mkdir(exist_ok=True)
    return path

def ips_start(u):
    stop('suricata')
    if not u['ips']:return
    for mod in ('nfnetlink_queue','nft_queue'):command(['modprobe',mod])
    path=suricata_config(u);command(['suricata','-T','-c',str(path)],timeout=180)
    spawn('suricata',['suricata','-c',str(path),'-q','0'])
    for _ in range(100):
        p=PROCESSES['suricata']
        if p.poll() is not None:raise Error('Suricata non avviato: '+(RUN/'suricata.log').read_text()[-1500:])
        q=Path('/proc/net/netfilter/nfnetlink_queue')
        if q.exists() and any(l.split()[0]=='0' for l in q.read_text().splitlines() if l.split()):return
        time.sleep(.2)
    raise Error('Suricata: coda IPS non pronta')

def clam_ping():
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
            s.settimeout(2);s.connect(str(RUN/'clamd.sock'));s.sendall(b'zPING\0');return s.recv(64).startswith(b'PONG')
    except OSError:return False

def clam_scan(data):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(60);s.connect(str(RUN/'clamd.sock'));s.sendall(b'zINSTREAM\0')
        for i in range(0,len(data),65536):part=data[i:i+65536];s.sendall(struct.pack('!I',len(part))+part)
        s.sendall(b'\0\0\0\0');reply=s.recv(4096).decode(errors='replace').strip('\0\n')
    if reply.endswith(' OK'):return True,reply
    if reply.endswith(' FOUND'):return False,reply
    raise Error('Antivirus non disponibile: '+reply)

def antivirus_start(u):
    global PROXY
    if PROXY:PROXY.shutdown();PROXY.server_close();PROXY=None
    stop('clamd')
    if not u['proxy']:return
    db=Path('/var/lib/clamav')
    if not all(any((db/(name+suffix)).is_file() for suffix in ('.cvd','.cld')) for name in ('main','daily')):raise Error('Scaricare prima le firme ufficiali ClamAV complete (main e daily) dalla pagina UTM')
    (RUN/'clamd.sock').unlink(missing_ok=True)
    # Private local socket; network clients can only access the controlled HTTP proxy.
    conf='LocalSocket '+str(RUN/'clamd.sock')+'\nLocalSocketMode 600\nDatabaseDirectory /var/lib/clamav\nForeground yes\nMaxThreads 2\nMaxQueue 8\nStreamMaxLength 20M\nMaxFileSize 20M\nMaxScanSize 40M\nAlertExceedsMax yes\nAlertEncrypted yes\n'
    write(RUN/'clamd.conf',conf);spawn('clamd',['clamd','--config-file='+str(RUN/'clamd.conf')])
    for _ in range(120):
        if PROCESSES['clamd'].poll() is not None:raise Error('ClamAV non avviato: '+(RUN/'clamd.log').read_text()[-1500:])
        if clam_ping():break
        time.sleep(.5)
    else:raise Error('ClamAV: caricamento firme non completato')
    from avproxy import create_proxy
    PROXY=create_proxy(u,clam_scan);threading.Thread(target=PROXY.serve_forever,daemon=True).start()

def activate(settings):
    RUN.mkdir(mode=0o700,exist_ok=True);RUN.chmod(0o700)
    vpn_start(settings['vpn']);ips_start(settings['utm']);antivirus_start(settings['utm'])

def update_command(engine):
    if engine=='suricata':return ['suricata-update','--no-test','--no-reload']
    if engine!='clamav':raise Error('Motore non valido')
    RUN.mkdir(mode=0o700,exist_ok=True)
    # The live image has empty logs. Avoid the distribution config's missing
    # UpdateLogFile; job output is already captured in the maintenance log.
    path=RUN/'freshclam.conf'
    write(path,'DatabaseDirectory /var/lib/clamav\nDatabaseOwner clamav\nDatabaseMirror database.clamav.net\nDNSDatabaseInfo current.cvd.clamav.net\n')
    return ['freshclam','--config-file='+str(path),'--stdout']

def health():
    versions={}
    for name,argv in [('wireguard',['wg','--version']),('suricata',['suricata','-V']),('clamav',['clamscan','--version'])]:
        try:versions[name]=command(argv,timeout=8).strip()
        except (Error,OSError):versions[name]='non installato'
    alerts=[];p=Path('/var/log/murus-suricata/eve.json')
    if p.exists():
        with p.open('rb') as f:f.seek(max(0,p.stat().st_size-60000));lines=f.read().decode(errors='replace').splitlines()
        for line in lines[-100:]:
            try:
                a=json.loads(line)
                if a.get('event_type')=='alert':alerts.append({'time':a.get('timestamp'),'source':a.get('src_ip'),'destination':a.get('dest_ip'),'signature':a.get('alert',{}).get('signature'),'action':a.get('alert',{}).get('action')})
            except ValueError:pass
    return {'versions':versions,'vpn':command(['wg','show',WG],check=False) if Path('/sys/class/net/'+WG).exists() else 'Disabilitata','ips_running':bool(PROCESSES.get('suricata') and PROCESSES['suricata'].poll() is None),'antivirus_ready':clam_ping(),'proxy_running':PROXY is not None,'signatures':[{'name':p.name,'bytes':p.stat().st_size,'modified':p.stat().st_mtime} for p in Path('/var/lib/clamav').glob('*') if p.suffix in ('.cvd','.cld')],'alerts':alerts,'https_scanning':False}

