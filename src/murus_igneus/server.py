"""Murus Igneus local management service. SPDX-License-Identifier: MIT."""
import base64
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
try:
    from .migration import VERSION, baseline, Error
    from .configuration import compile_config, from_backup, empty
except ImportError:  # run as a script from this directory (how the service starts)
    from migration import VERSION, baseline, Error
    from configuration import compile_config, from_backup, empty

STATE=Path('/etc/murus_igneus');MGMT='eth0';LOCK=threading.RLock()
CSRF_HEADER='X-Murus-Igneus-CSRF'  # must be a valid HTTP token (no spaces): browsers reject anything else
CSRF=secrets.token_urlsafe(32);PLAN=None;PENDING=None;LAST='Nessuna configurazione applicata';ACTIVE=None

def run(args,data=None,check=True):
    r=subprocess.run(args,input=data,text=True,capture_output=True,timeout=25)
    if check and r.returncode:raise Error((r.stderr or r.stdout or 'Comando fallito')[:1800])
    return r.stdout

def atomic(path,text):
    temp=path.with_suffix('.tmp')
    with os.fdopen(os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600),'w') as f:f.write(text)  # never readable by others, not even briefly
    temp.chmod(0o600);temp.replace(path)

LEGACY_PASSWORD='igneus'  # the publicly known lab password shipped by 0.2/early 0.3 builds

def ensure_password(state):
    """Create a random admin password on first start. Returns (password, created)."""
    path=state/'admin.password'
    if path.exists():return path.read_text().strip(),False
    password=secrets.token_urlsafe(12);atomic(path,password);return password,True

def default_password():
    try:return (STATE/'admin.password').read_text().strip()==LEGACY_PASSWORD
    except OSError:return False

def network(ops,undo):
    available={x['ifname'] for x in json.loads(run(['ip','-j','link']))}
    mgmt=json.loads(run(['ip','-j','-4','addr','show','dev',MGMT]))
    reserved=[ipaddress.IPv4Interface(a['local']+'/'+str(a['prefixlen'])).network for i in mgmt for a in i.get('addr_info',[])]
    for op in ops:
        dev=op['interface']
        if dev not in available or dev in ('lo',MGMT):raise Error('Scheda dati assente o riservata')
        if op['kind']=='address' and any(ipaddress.IPv4Interface(op['address']).network.overlaps(n) for n in reserved):raise Error('La rete importata si sovrappone alla rete di gestione')
        # A route more specific than the management network would win over the connected route and cut the admin off.
        if op['kind']=='route' and any(ipaddress.IPv4Network(op['destination']).subnet_of(n) for n in reserved):raise Error('La rotta ricade nella rete di gestione')
    for op in ops:
        dev=op['interface'];info=json.loads(run(['ip','-j','link','show','dev',dev]))[0]
        if 'UP' not in info['flags']:
            run(['ip','link','set','dev',dev,'up']);undo.append(['ip','link','set','dev',dev,'down'])
        if op['kind']=='address':
            values=json.loads(run(['ip','-j','-4','addr','show','dev',dev]));existing={a['local']+'/'+str(a['prefixlen']) for i in values for a in i.get('addr_info',[])}
            if op['address'] not in existing:
                run(['ip','addr','add',op['address'],'dev',dev]);undo.append(['ip','addr','del',op['address'],'dev',dev])
        elif op['kind']=='route':
            existing=json.loads(run(['ip','-j','-4','route','show','exact',op['destination']]))
            if any(r.get('gateway')==op['gateway'] and r.get('dev')==dev and r.get('metric')==op['metric'] for r in existing):continue
            args=[op['destination'],'via',op['gateway'],'dev',dev,'metric',str(op['metric'])]
            run(['ip','route','add']+args);undo.append(['ip','route','del']+args)

def remove_previous(previous,current,undo):
    """Remove only resources owned by the last confirmed configuration."""
    obsolete=[o for o in previous if o not in current and o['kind']!='link']
    for op in sorted(obsolete,key=lambda o:0 if o['kind']=='route' else 1):
        dev=op['interface']
        if dev in (MGMT,'lo'):raise Error('Risorsa di gestione riservata')
        if op['kind']=='route':
            existing=json.loads(run(['ip','-j','-4','route','show','exact',op['destination']]))
            if not any(r.get('gateway')==op['gateway'] and r.get('dev')==dev and r.get('metric')==op['metric'] for r in existing):continue
            args=['ip','route','del',op['destination'],'via',op['gateway'],'dev',dev,'metric',str(op['metric'])]
        else:
            existing=json.loads(run(['ip','-j','-4','addr','show','dev',dev]))
            if not any(a['local']+'/'+str(a['prefixlen'])==op['address'] for i in existing for a in i.get('addr_info',[])):continue
            args=['ip','addr','del',op['address'],'dev',dev]
        run(args);restore=args.copy();restore[2]='add';undo.append(restore)

def rollback(ident):
    global PENDING,LAST
    with LOCK:
        if not PENDING or PENDING['id']!=ident:return
        p=PENDING
        for args in reversed(p['undo']):run(args,check=False)
        run(['nft','-f','-'],p['old']);run(['conntrack','-F'],check=False)
        run(['sysctl','-w','net.ipv4.ip_forward='+p['forward']],check=False)
        PENDING=None;LAST='Modifica annullata; ripristinata la configurazione precedente'

def apply(plan):
    global PENDING,LAST
    if PENDING:raise Error('Confermare o annullare la modifica pendente')
    if not plan or not plan['ready']:raise Error('Migrazione non validata o con incompatibilità')
    run(['nft','--check','-f','-'],plan['nftables'])
    old=run(['nft','list','table','inet','murus_igneus']);ident=secrets.token_hex(16)
    PENDING={'id':ident,'deadline':time.time()+90,'undo':[],'old':'add table inet murus_igneus\nflush table inet murus_igneus\n'+old,'forward':Path('/proc/sys/net/ipv4/ip_forward').read_text().strip(),'plan':plan}
    try:
        run(['nft','-f','-'],baseline(MGMT))
        remove_previous(ACTIVE['network_ops'] if ACTIVE else [],plan['network_ops'],PENDING['undo'])
        network(plan['network_ops'],PENDING['undo']);run(['nft','-f','-'],plan['nftables'])
        run(['conntrack','-F']);run(['sysctl','-w','net.ipv4.ip_forward=1'])
    except Exception:
        rollback(ident);raise
    timer=threading.Timer(90,rollback,[ident]);timer.daemon=True;timer.start()
    LAST='Applicata temporaneamente: confermare entro 90 secondi';return ident

class Handler(BaseHTTPRequestHandler):
    server_version='Murus Igneus/'+VERSION
    timeout=15  # applies to the TLS handshake and to every socket read
    def setup(self):
        # The handshake runs here, in the request thread, so a silent client cannot stall accept().
        self.request.settimeout(self.timeout);self.request.do_handshake();super().setup()
    def log_message(self,*_):pass
    def auth(self):
        try:expected='admin:'+(STATE/'admin.password').read_text().strip()
        except OSError:self.reply(503,{'error':'Credenziali non disponibili'});return False
        try:
            h=self.headers.get('Authorization','');actual=base64.b64decode(h[6:],validate=True).decode() if h.startswith('Basic ') else ''
        except Exception:actual=''
        if hmac.compare_digest(hashlib.sha256(actual.encode()).digest(),hashlib.sha256(expected.encode()).digest()):return True
        self.send_response(401);self.send_header('WWW-Authenticate','Basic realm="Murus Igneus", charset="UTF-8"');self.send_header('Content-Length','0');self.end_headers();return False
    def reply(self,status,data,mime='application/json'):
        b=json.dumps(data,ensure_ascii=False).encode() if mime=='application/json' else data
        self.send_response(status);self.send_header('Content-Type',mime);self.send_header('Content-Length',str(len(b)))
        for k,v in {'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"}.items():self.send_header(k,v)
        self.end_headers();self.wfile.write(b)
    def do_GET(self):
        if not self.auth():return
        try:
            with LOCK:
                if self.path=='/api/status':
                    links=json.loads(run(['ip','-j','link']))
                    self.reply(200,{'version':VERSION,'default_password':default_password(),'csrf':CSRF,'management':MGMT,'links':[x['ifname'] for x in links if x['ifname'] not in (MGMT,'lo')],'last':LAST,'pending':{'id':PENDING['id'],'deadline':PENDING['deadline'],'remaining':max(0,PENDING['deadline']-time.time())} if PENDING else None})
                elif self.path=='/api/configuration':self.reply(200,{'configuration':ACTIVE.get('configuration') if ACTIVE else empty(),'legacy':bool(ACTIVE and not ACTIVE.get('configuration'))})
                elif self.path=='/api/rules':self.reply(200,{'rules':run(['nft','list','table','inet','murus_igneus'])})
                elif self.path=='/api/logs':self.reply(200,{'logs':'\n'.join(x for x in run(['dmesg'],check=False).splitlines() if 'OW policy' in x)[-30000:]})
                elif self.path in ('/','/app.js','/style.css'):
                    name,mime={'/':('index.html','text/html; charset=utf-8'),'/app.js':('app.js','text/javascript; charset=utf-8'),'/style.css':('style.css','text/css; charset=utf-8')}[self.path]
                    self.reply(200,Path(__file__).with_name(name).read_bytes(),mime)
                else:self.reply(404,{'error':'Risorsa assente'})
        except Exception as e:self.reply(500,{'error':str(e)})
    def do_POST(self):
        global PLAN,PENDING,LAST,ACTIVE
        if not self.auth():return
        if not hmac.compare_digest(self.headers.get(CSRF_HEADER,'').encode('utf-8','replace'),CSRF.encode()):return self.reply(403,{'error':'Token CSRF non valido'})
        try:
            length=int(self.headers.get('Content-Length','0'))
            if not 0<length<=9*1024**2 or self.headers.get('Content-Type')!='application/json':raise Error('Richiesta non valida')
            data=json.loads(self.rfile.read(length))
            if not isinstance(data,dict):raise Error('Richiesta non valida')
            with LOCK:
                if self.path=='/api/preview':
                    if PENDING:raise Error('Modifica pendente')
                    PLAN=None
                    PLAN=from_backup(data.get('backup'),data.get('mapping',{}),MGMT);PLAN['plan_id']=secrets.token_hex(16);self.reply(200,PLAN)
                elif self.path=='/api/configuration/preview':
                    if PENDING:raise Error('Modifica pendente')
                    PLAN=None
                    PLAN=compile_config(data.get('configuration'),MGMT);PLAN['plan_id']=secrets.token_hex(16);self.reply(200,PLAN)
                elif self.path=='/api/apply':
                    if not PLAN or data.get('plan_id')!=PLAN.get('plan_id'):raise Error('Anteprima scaduta: verificare nuovamente la bozza')
                    self.reply(200,{'id':apply(PLAN)})
                elif self.path=='/api/confirm':
                    if not PENDING or data.get('id')!=PENDING['id'] or time.time()>=PENDING['deadline']:raise Error('Conferma scaduta o non valida')
                    atomic(STATE/'active.json',json.dumps(PENDING['plan']));ACTIVE=PENDING['plan'];PENDING=None;LAST='Configurazione confermata e salvata';self.reply(200,{'ok':True})
                elif self.path=='/api/rollback':
                    if PENDING:rollback(PENDING['id'])
                    self.reply(200,{'ok':True})
                else:self.reply(404,{'error':'Risorsa assente'})
        except (ValueError,KeyError,TypeError,RecursionError,subprocess.TimeoutExpired) as e:self.reply(400,{'error':str(e)})
        except Exception:self.reply(500,{'error':'Errore interno'})

class Server(ThreadingHTTPServer):
    daemon_threads=True
    def handle_error(self,request,client_address):
        # Failed handshakes and client timeouts are routine on a network-facing port; anything else is a bug.
        if not isinstance(sys.exc_info()[1],OSError):super().handle_error(request,client_address)

def make_server(host,port,cert,key):
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_2;ctx.load_cert_chain(cert,key)
    server=Server((host,port),Handler)
    server.socket=ctx.wrap_socket(server.socket,server_side=True,do_handshake_on_connect=False)
    return server

def main():
    global LAST,ACTIVE
    STATE.mkdir(mode=0o700,exist_ok=True);STATE.chmod(0o700)
    password,created=ensure_password(STATE)
    # Only the location is logged, never the secret itself.
    if created:print('Murus Igneus: password iniziale di "admin" generata in '+str(STATE/'admin.password')+' (leggibile solo da root)',file=sys.stderr,flush=True)
    elif password==LEGACY_PASSWORD:print('Murus Igneus: ATTENZIONE, e in uso la password di laboratorio pubblica; sostituire il contenuto di '+str(STATE/'admin.password'),file=sys.stderr,flush=True)
    run(['nft','-f','-'],baseline(MGMT));run(['sysctl','-w','net.ipv4.ip_forward=0'])
    if (STATE/'active.json').exists():
        undo=[]
        try:
            plan=json.loads((STATE/'active.json').read_text())
            if not plan['ready']:raise Error('Piano salvato non valido')
            run(['nft','--check','-f','-'],plan['nftables']);network(plan['network_ops'],undo)
            run(['nft','-f','-'],plan['nftables']);run(['sysctl','-w','net.ipv4.ip_forward=1']);LAST='Configurazione salvata ripristinata';ACTIVE=plan
        except Exception as e:
            for args in reversed(undo):run(args,check=False)
            run(['nft','-f','-'],baseline(MGMT));LAST='Avvio protetto: '+str(e)
    cert,key=STATE/'server.crt',STATE/'server.key'
    if not cert.exists() or not key.exists():
        run(['openssl','req','-x509','-newkey','rsa:2048','-sha256','-nodes','-days','3650','-subj','/CN=murus_igneus.local','-keyout',str(key),'-out',str(cert)]);key.chmod(0o600)
    make_server('0.0.0.0',8443,cert,key).serve_forever()

if __name__=='__main__':main()