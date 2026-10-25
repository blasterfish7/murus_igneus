"""Murus Igneus local management service. SPDX-License-Identifier: MIT."""
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
from pathlib import Path
import secrets
import signal
import ssl
import sys
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
try:
    from .migration import VERSION, baseline, Error
    from .configuration import compile_config, from_backup, empty
    from . import security, installer, jobs, assistant, switches, networking, traffic, enterprise, authentication, eventlog, parental
except ImportError:
    from migration import VERSION, baseline, Error
    from configuration import compile_config, from_backup, empty
    import security, installer, jobs, assistant, switches, networking, traffic, enterprise, authentication, eventlog, parental

STATE=Path('/etc/murus_igneus');MGMT=os.environ.get('MURUS_MANAGEMENT_INTERFACE','eth0');LOCK=threading.RLock()
if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',MGMT) or MGMT=='lo':raise ValueError('Interfaccia di gestione non valida')
CSRF_HEADER='X-Murus-Igneus-CSRF'
CSRF=secrets.token_urlsafe(32);PLAN=None;PENDING=None;LAST='Nessuna configurazione applicata';ACTIVE=None

def run(args,data=None,check=True):
    r=subprocess.run(args,input=data,text=True,capture_output=True,timeout=25)
    if check and r.returncode:raise Error((r.stderr or r.stdout or 'Comando fallito')[:1800])
    return r.stdout

def atomic(path,text):
    temp=path.with_suffix('.tmp');temp.write_text(text);temp.chmod(0o600);temp.replace(path)

def check_vpn_management(settings):
    v=settings['vpn']
    if not v['enabled']:return
    values=json.loads(run(['ip','-j','-4','addr','show','dev',MGMT]))
    protected=[ipaddress.IPv4Interface(a['local']+'/'+str(a['prefixlen'])).network for i in values for a in i.get('addr_info',[])]
    routes=[ipaddress.IPv4Interface(v['address']).network]+[ipaddress.IPv4Network(n) for p in v['peers'] for n in p['allowed_ips']]
    if any(n.overlaps(m) for n in routes for m in protected):raise Error('Una rete VPN si sovrappone alla rete di gestione')

def check_enterprise_management(plan):
    settings=plan.get('enterprise',enterprise.defaults())
    if not any(r['enabled'] for r in settings['ipsec']):return
    values=json.loads(run(['ip','-j','-4','addr','show','dev',MGMT]))
    reserved=[ipaddress.IPv4Interface(a['local']+'/'+str(a['prefixlen'])).network for i in values for a in i.get('addr_info',[])]
    if any(ipaddress.IPv4Network(r[k]).overlaps(n) for r in settings['ipsec'] if r['enabled'] for k in ('local_network','remote_network') for n in reserved):raise Error('Selettore IPsec sovrapposto alla rete di gestione')

def vlan_add(op):
    return ['ip','link','add','link',op['parent'],'name',op['interface'],'type','vlan','id',str(op['vlan_id'])]

def network(ops,undo):
    links=json.loads(run(['ip','-j','-d','link']));available={x['ifname']:x for x in links}
    mgmt=json.loads(run(['ip','-j','-4','addr','show','dev',MGMT]))
    reserved=[ipaddress.IPv4Interface(a['local']+'/'+str(a['prefixlen'])).network for i in mgmt for a in i.get('addr_info',[])]
    vlans={o['interface']:o for o in ops if o['kind']=='vlan'}
    for op in ops:
        dev=op['interface']
        if dev in ('lo',MGMT) or (dev not in available and dev not in vlans):raise Error('Scheda dati assente o riservata')
        if op['kind']=='vlan':
            if op['parent'] not in available or op['parent'] in ('lo',MGMT):raise Error('Porta padre VLAN assente o riservata')
            if available[op['parent']].get('linkinfo',{}).get('info_kind') not in (None,'veth'):raise Error('Il padre VLAN deve essere una porta fisica dati')
            old=available.get(dev)
            if old:
                info=old.get('linkinfo',{});parent=available[op['parent']]
                same_parent=old.get('link')==op['parent'] or old.get('link_index')==parent['ifindex']
                if old.get('ifalias')!=networking.VLAN_ALIAS or info.get('info_kind')!='vlan' or info.get('info_data',{}).get('id')!=op['vlan_id'] or not same_parent:raise Error('Nome VLAN già occupato o VLAN non gestita da Murus')
        if op['kind']=='route' and any(ipaddress.IPv4Network(op['destination']).subnet_of(n) for n in reserved):raise Error('La rotta ricade nella rete di gestione')
        if op['kind']=='address' and any(ipaddress.IPv4Interface(op['address']).network.overlaps(n) for n in reserved):raise Error('La rete importata si sovrappone alla rete di gestione')
    for op in ops:
        dev=op['interface']
        if op['kind']=='vlan':
            parent=json.loads(run(['ip','-j','link','show','dev',op['parent']]))[0]
            if 'UP' not in parent['flags']:
                run(['ip','link','set','dev',op['parent'],'up']);undo.append(['ip','link','set','dev',op['parent'],'down'])
            if dev not in available:
                run(vlan_add(op));undo.append(['ip','link','del','dev',dev])
                run(['ip','link','set','dev',dev,'alias',networking.VLAN_ALIAS])
            continue
        info=json.loads(run(['ip','-j','link','show','dev',dev]))[0]
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
    """Remove owned addresses/routes before obsolete VLANs; restore in reverse."""
    replaced={o['interface'] for o in previous if o['kind']=='vlan' and o not in current}
    obsolete=[o for o in previous if o['kind']!='link' and (o not in current or o['interface'] in replaced)]
    for op in sorted(obsolete,key=lambda o:{'route':0,'address':1,'vlan':2}[o['kind']]):
        dev=op['interface']
        if dev in (MGMT,'lo'):raise Error('Risorsa di gestione riservata')
        if op['kind']=='vlan':
            info=json.loads(run(['ip','-j','-d','link','show','dev',dev]))[0]
            if info.get('ifalias')!=networking.VLAN_ALIAS or info.get('linkinfo',{}).get('info_data',{}).get('id')!=op['vlan_id']:raise Error('VLAN modificata fuori da Murus: rimozione bloccata')
            run(['ip','link','del','dev',dev])
            undo.extend([['ip','link','set','dev',dev,'up'],['ip','link','set','dev',dev,'alias',networking.VLAN_ALIAS],vlan_add(op)])
            continue
        if op['kind']=='route':
            existing=json.loads(run(['ip','-j','-4','route','show','exact',op['destination']]))
            if not any(r.get('gateway')==op['gateway'] and r.get('dev')==dev and r.get('metric')==op['metric'] for r in existing):continue
            args=['ip','route','del',op['destination'],'via',op['gateway'],'dev',dev,'metric',str(op['metric'])]
        else:
            existing=json.loads(run(['ip','-j','-4','addr','show','dev',dev]))
            if not any(a['local']+'/'+str(a['prefixlen'])==op['address'] for i in existing for a in i.get('addr_info',[])):continue
            args=['ip','addr','del',op['address'],'dev',dev]
        run(args);restore=args.copy();restore[2]='add';undo.append(restore)

def service_settings(plan):
    return plan.get('network_services',{'interfaces':[],**networking.defaults()}) if plan else {'interfaces':[],**networking.defaults()}

FAILED={};FAILED_LOCK=threading.Lock()

def password_blocked(peer):
    with FAILED_LOCK:
        now=time.monotonic()
        for k in [k for k,v in FAILED.items() if all(now-t>=60 for t in v)]:del FAILED[k]
        return len([t for t in FAILED.get(peer,[]) if now-t<60])>=10

def password_failed(peer,ok):
    """Count wrong Basic credentials per peer; a request without credentials is only the browser challenge."""
    with FAILED_LOCK:
        if ok:FAILED.pop(peer,None);return
        if len(FAILED)>=1024 and peer not in FAILED:return
        FAILED.setdefault(peer,[]).append(time.monotonic())

def rollback(ident):
    global PENDING,LAST
    with LOCK:
        if not PENDING or PENDING['id']!=ident:return
        p=PENDING
        run(['nft','-f','-'],baseline(MGMT))
        parental.stop()
        enterprise.stop()
        networking.stop()
        for args in reversed(p['undo']):run(args,check=False)
        service_error=None
        try:
            security.activate(p['security'])
            networking.activate(service_settings(ACTIVE),MGMT)
            enterprise.activate(ACTIVE.get('enterprise',enterprise.defaults()) if ACTIVE else enterprise.defaults(), ACTIVE.get('configuration',{}).get('interfaces',[]) if ACTIVE else [])
        except Exception as e:service_error=str(e)
        parental.stage(ACTIVE.get('parental') if ACTIVE else None)
        try:run(['nft','-f','-'],p['old'])
        except Exception as e:service_error=str(e)
        try:parental.activate(ACTIVE.get('parental') if ACTIVE else None,STATE,MGMT)
        except Exception as e:service_error=str(e)
        try:
            if service_error:run(['nft','-f','-'],baseline(MGMT))
        except Exception as e:service_error=str(e)
        run(['conntrack','-F'],check=False)
        run(['sysctl','-w','net.ipv4.ip_forward='+p['forward']],check=False)
        PENDING=None;LAST='Modifica annullata; ripristinata la configurazione precedente'
        if service_error:LAST='Ripristino servizi fallito: '+service_error

def apply(plan):
    global PENDING,LAST
    if PENDING or jobs.busy():raise Error('Confermare la modifica o attendere la manutenzione in corso')
    if (parental.TASK.status() or {}).get('state')=='running':raise Error('Attendere l’aggiornamento delle liste parental')
    if (switches.TASK.status() or {}).get('state')=='running':raise Error('Attendere l’operazione switch prima di applicare il firewall')
    if not plan or not plan['ready']:raise Error('Migrazione non validata o con incompatibilità')
    parental.preflight(plan.get('parental'),STATE)
    check_enterprise_management(plan)
    run(['nft','--check','-f','-'],plan['nftables'])
    old=run(['nft','list','table','inet','murus_igneus']);ident=secrets.token_hex(16)
    PENDING={'id':ident,'deadline':time.time()+90,'undo':[],'old':'add table inet murus_igneus\nflush table inet murus_igneus\n'+old,'forward':Path('/proc/sys/net/ipv4/ip_forward').read_text().strip(),'plan':plan,'security':ACTIVE.get('security',security.defaults()) if ACTIVE else security.defaults()}
    try:
        run(['nft','-f','-'],baseline(MGMT))
        parental.stop()
        enterprise.stop()
        networking.stop()
        remove_previous(ACTIVE['network_ops'] if ACTIVE else [],plan['network_ops'],PENDING['undo'])
        settings=plan.get('security',security.defaults())
        check_vpn_management(settings)
        security.activate(settings)
        network(plan['network_ops'],PENDING['undo'])
        networking.activate(service_settings(plan),MGMT)
        parental.stage(plan.get('parental'))
        enterprise.activate(plan.get('enterprise',enterprise.defaults()),plan.get('configuration',{}).get('interfaces',[]))
        run(['nft','-f','-'],plan['nftables'])
        parental.activate(plan.get('parental'),STATE,MGMT)
        run(['conntrack','-F']);run(['sysctl','-w','net.ipv4.ip_forward=1'])
    except Exception:
        rollback(ident);raise
    PENDING['deadline']=time.time()+90
    timer=threading.Timer(90,rollback,[ident]);timer.daemon=True;timer.start()
    LAST='Applicata temporaneamente: confermare entro 90 secondi';return ident

class Handler(BaseHTTPRequestHandler):
    server_version='Murus Igneus/'+VERSION
    timeout=15
    def setup(self):
        self.request.settimeout(self.timeout)
        if isinstance(self.request,ssl.SSLSocket):self.request.do_handshake()
        super().setup()
    def log_message(self,*_):pass
    def auth(self):
        try:expected='admin:'+(STATE/'admin.password').read_text().strip()
        except OSError:self.reply(503,{'error':'Credenziali non disponibili'});return False
        try:
            h=self.headers.get('Authorization','');actual=base64.b64decode(h[6:],validate=True).decode() if h.startswith('Basic ') else ''
        except Exception:actual=''
        peer=self.client_address[0]
        if actual and password_blocked(peer):
            body=json.dumps({'error':'Troppi tentativi: attendere un minuto'}).encode();self.send_response(429);self.send_header('Retry-After','60');self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body);return False
        if hmac.compare_digest(hashlib.sha256(actual.encode()).digest(),hashlib.sha256(expected.encode()).digest()):
            password_failed(peer,True)
            if authentication.read(STATE) and not self.mfa_session() and self.path not in ('/', '/app.js', '/management.js', '/network.js', '/enterprise.js', '/parental.js', '/style.css', '/api/auth/status', '/api/auth/verify'):
                self.reply(403,{'error':'Inserire il codice TOTP', 'mfa_required':True});return False
            return True
        if actual:password_failed(peer,False)
        self.send_response(401);self.send_header('WWW-Authenticate','Basic realm="Murus Igneus", charset="UTF-8"');self.send_header('Content-Length','0');self.end_headers();return False
    def mfa_session(self):
        from http.cookies import SimpleCookie
        cookie=SimpleCookie()
        try:cookie.load(self.headers.get('Cookie',''))
        except Exception:return False
        return authentication.valid_session(cookie['murus_mfa'].value if 'murus_mfa' in cookie else '', self.client_address[0])
    def reply(self,status,data,mime='application/json'):
        b=json.dumps(data,ensure_ascii=False).encode() if mime=='application/json' else data
        self.send_response(status);self.send_header('Content-Type',mime);self.send_header('Content-Length',str(len(b)))
        for k,v in {'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"}.items():self.send_header(k,v)
        if getattr(self,'mfa_cookie',None):self.send_header('Set-Cookie','murus_mfa='+self.mfa_cookie+'; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=900')
        self.end_headers();self.wfile.write(b)
        if self.command=='POST':
            try:eventlog.append(STATE,'audit',{'path':self.path[:200],'status':status,'peer':self.client_address[0]})
            except Exception:pass
    def do_GET(self):
        if not self.auth():return
        try:
            # Status polling must stay responsive while apply() holds LOCK for long service activation.
            if self.path=='/api/auth/status':return self.reply(200,{'enabled':bool(authentication.read(STATE)),'verified':self.mfa_session(),'csrf':CSRF})
            if self.path=='/api/status':
                pending=PENDING;links=json.loads(run(['ip','-j','link']))
                return self.reply(200,{'version':VERSION,'csrf':CSRF,'management':MGMT,'links':[x['ifname'] for x in links if x['ifname'] not in (MGMT,'lo')],'last':LAST,'maintenance':jobs.busy(),'pending':{'id':pending['id'],'deadline':pending['deadline'],'remaining':max(0,pending['deadline']-time.time())} if pending else None})
            with LOCK:
                if self.path=='/api/events':self.reply(200,eventlog.history(STATE))
                elif self.path in ('/api/parental/report/1','/api/parental/report/7'):self.reply(200,parental.reporting.report(STATE,int(self.path[-1])))
                elif self.path=='/api/parental':self.reply(200,parental.inventory(STATE))
                elif self.path=='/api/enterprise':self.reply(200,enterprise.health())
                elif self.path=='/api/configuration':self.reply(200,{'configuration':ACTIVE.get('configuration') if ACTIVE else {**empty(),**security.defaults(),**networking.defaults(),**enterprise.defaults(),**parental.defaults()},'legacy':bool(ACTIVE and not ACTIVE.get('configuration'))})
                elif self.path=='/api/assistant':self.reply(200,{'settings':{**assistant.load(STATE),'key_configured':(STATE/'openai.key').exists()},'models':assistant.MODELS,'task':assistant.TASK.status()})
                elif self.path=='/api/switches':self.reply(200,switches.inventory(STATE))
                elif self.path=='/api/installer':self.reply(200,installer.inventory())
                elif self.path=='/api/traffic':self.reply(200,traffic.snapshot())
                elif self.path=='/api/network-services':self.reply(200,networking.health())
                elif self.path=='/api/security':self.reply(200,security.health())
                elif self.path=='/api/job':self.reply(200,jobs.status())
                elif self.path=='/api/rules':self.reply(200,{'rules':run(['nft','list','table','inet','murus_igneus'])})
                elif self.path=='/api/logs':self.reply(200,{'logs':'\n'.join(x for x in run(['dmesg'],check=False).splitlines() if 'OW policy' in x)[-30000:]})
                elif self.path in ('/','/app.js','/management.js','/network.js','/enterprise.js','/parental.js','/style.css'):
                    name,mime={'/':('index.html','text/html; charset=utf-8'),'/app.js':('app.js','text/javascript; charset=utf-8'),'/management.js':('management.js','text/javascript; charset=utf-8'),'/network.js':('network.js','text/javascript; charset=utf-8'),'/enterprise.js':('enterprise.js','text/javascript; charset=utf-8'),'/parental.js':('parental.js','text/javascript; charset=utf-8'),'/style.css':('style.css','text/css; charset=utf-8')}[self.path]
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
                if self.path in ('/api/parental/report/export','/api/parental/report/clear'):
                    if self.path.endswith('/clear'):
                        if data.get('confirm') is not True:raise Error('Conferma cancellazione richiesta')
                        self.reply(200,parental.clear_report(STATE))
                    else:self.reply(200,{'csv':parental.reporting.export_csv(parental.reporting.report(STATE,data.get('days',7)))})
                elif self.path in ('/api/parental/update','/api/parental/pause'):
                    if PENDING or jobs.busy():raise Error('Confermare prima la modifica o attendere la manutenzione')
                    if self.path=='/api/parental/update':self.reply(200,parental.update_feed(STATE,data.get('category')))
                    else:self.reply(200,parental.pause(data.get('id'),data.get('minutes')))
                elif self.path=='/api/auth/verify':
                    self.mfa_cookie=authentication.authenticate(STATE,data.get('code'),self.client_address[0]);self.reply(200,{'ok':True})
                elif self.path=='/api/auth/enroll':self.reply(200,authentication.enroll(STATE))
                elif self.path=='/api/auth/confirm':
                    self.mfa_cookie=authentication.confirm(STATE,data.get('code'),self.client_address[0]);self.reply(200,{'ok':True})
                elif self.path=='/api/auth/disable':
                    authentication.disable(STATE,data.get('code'),self.client_address[0]);self.reply(200,{'ok':True})
                elif self.path=='/api/assistant/settings':self.reply(200,assistant.save(STATE,data))
                elif self.path=='/api/assistant/check':
                    settings=assistant.load(STATE)
                    self.reply(200,assistant.TASK.start(lambda:assistant.check(settings,STATE)))
                elif self.path=='/api/assistant/ask':
                    logs=''
                    if data.get('include_logs') is True:
                        logs='\n'.join(x for x in run(['dmesg'],check=False).splitlines() if 'OW policy' in x)[-6000:]
                    summary=[{'name':r['name'],'host':r['host'],'telemetry':r.get('telemetry')} for r in switches.inventory(STATE)['devices']]
                    self.reply(200,assistant.ask(STATE,data,MGMT,summary,logs))
                elif self.path in ('/api/switches/save','/api/switches/delete','/api/switches/poll','/api/switches/port/preview','/api/switches/port/apply'):
                    if PENDING or jobs.busy():raise Error('Modifica firewall o manutenzione in corso')
                    if self.path=='/api/switches/save':result=switches.save(STATE,data)
                    elif self.path=='/api/switches/delete':result=switches.delete(STATE,data.get('id'))
                    elif self.path=='/api/switches/poll':result=switches.poll(STATE,data.get('id'))
                    elif self.path=='/api/switches/port/preview':result=switches.preview(STATE,data)
                    else:result=switches.apply(STATE,data)
                    self.reply(200,result)
                elif self.path in ('/api/installer/preview','/api/installer/start','/api/security/update','/api/vpn/key'):
                    if PENDING or jobs.busy() or (switches.TASK.status() or {}).get('state')=='running':raise Error('Modifica o manutenzione in corso')
                    if self.path=='/api/installer/preview':self.reply(200,installer.preview(data.get('disk')))
                    elif self.path=='/api/installer/start':self.reply(200,installer.start(data))
                    elif self.path=='/api/vpn/key':self.reply(200,{'public_key':security.public_key()})
                    else:
                        engine=data.get('engine')
                        if engine not in ('clamav','suricata'):raise Error('Motore non valido')
                        args=security.update_command(engine)
                        self.reply(200,jobs.start('Aggiornamento '+engine,lambda log:jobs.run(args,log,timeout=1800)))
                elif self.path=='/api/preview':
                    if PENDING:raise Error('Modifica pendente')
                    PLAN=None
                    PLAN=from_backup(data.get('backup'),data.get('mapping',{}),MGMT)
                    if PLAN.get('configuration') and ACTIVE:
                        PLAN['configuration'].update(ACTIVE.get('security',security.defaults()));PLAN=compile_config(PLAN['configuration'],MGMT)
                    PLAN['plan_id']=secrets.token_hex(16);self.reply(200,PLAN)
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
    if not (STATE/'admin.password').exists():atomic(STATE/'admin.password','igneus')
    run(['nft','-f','-'],baseline(MGMT));run(['sysctl','-w','net.ipv4.ip_forward=0'])
    if (STATE/'active.json').exists():
        undo=[]
        try:
            plan=json.loads((STATE/'active.json').read_text())
            if not plan['ready']:raise Error('Piano salvato non valido')
            check_enterprise_management(plan)
            settings=plan.get('security',security.defaults());check_vpn_management(settings);security.activate(settings)
            run(['nft','--check','-f','-'],plan['nftables']);network(plan['network_ops'],undo)
            networking.activate(service_settings(plan),MGMT)
            enterprise.activate(plan.get('enterprise',enterprise.defaults()),plan.get('configuration',{}).get('interfaces',[]))
            parental.stage(plan.get('parental'))
            run(['nft','-f','-'],plan['nftables'])
            parental.activate(plan.get('parental'),STATE,MGMT)
            run(['sysctl','-w','net.ipv4.ip_forward=1']);LAST='Configurazione salvata ripristinata';ACTIVE=plan
        except Exception as e:
            parental.stop()
            enterprise.stop()
            networking.stop()
            for args in reversed(undo):run(args,check=False)
            run(['nft','-f','-'],baseline(MGMT));LAST='Avvio protetto: '+str(e)
    cert,key=STATE/'server.crt',STATE/'server.key'
    if not cert.exists() or not key.exists():
        run(['openssl','req','-x509','-newkey','rsa:2048','-sha256','-nodes','-days','3650','-subj','/CN=murus_igneus.local','-keyout',str(key),'-out',str(cert)]);key.chmod(0o600)
    eventlog.start(STATE);parental.reporting.start_retention(STATE)
    make_server('0.0.0.0',8443,cert,key).serve_forever()

if __name__=='__main__':
    def terminate(signum,frame):raise SystemExit(0)
    signal.signal(signal.SIGTERM,terminate)
    try:main()
    finally:
        # A service restart must not orphan the old queue listener or proxy.
        with LOCK:
            run(['nft','-f','-'],baseline(MGMT),check=False)
            run(['sysctl','-w','net.ipv4.ip_forward=0'],check=False)
            parental.stop()
            enterprise.stop()
            networking.stop()
            security.activate(security.defaults())


