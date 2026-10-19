"""Functional traffic tests. Run only in the disposable Murus lab VM."""
import base64,copy,http.client,json,os,ssl,subprocess,sys,time,urllib.request
from pathlib import Path
assert Path('/etc/murus_igneus/live-image').exists(), 'Disposable live VM required'
assert os.environ.get('MURUS_LAB')=='YES', 'Explicit lab flag required'
AUTH=base64.b64encode(b'admin:igneus').decode();CSRF=''
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
def api(path,data=None):
 global CSRF
 headers={'Authorization':'Basic '+AUTH}
 if data is not None:headers.update({'Content-Type':'application/json','X-Murus-Igneus-CSRF':CSRF})
 req=urllib.request.Request('https://127.0.0.1:8443/api/'+path,headers=headers,data=json.dumps(data).encode() if data is not None else None)
 try:
  with opener.open(req,timeout=300) as r:result=json.load(r)
 except urllib.error.HTTPError as e:raise RuntimeError(e.read().decode()) from e
 if path=='status':CSRF=result['csrf']
 return result
def run(args,check=True,**kw):
 p=subprocess.run(args,text=True,capture_output=True,**kw)
 if check and p.returncode:raise RuntimeError(str(args)+': '+p.stderr+p.stdout)
 return p.stdout
def ns(name,args,**kw):return run(['ip','netns','exec',name]+args,**kw)
def apply(config,confirm=True):
 preview=api('configuration/preview',{'configuration':config});assert preview['ready'],preview['blockers']
 p=api('apply',{'plan_id':preview['plan_id']})
 if confirm:api('confirm',{'id':p['id']})
 return p
def request(nsname,url,proxy=None):
 script='''import http.client,json,sys
from urllib.parse import urlsplit
u=urlsplit(sys.argv[1]);c=http.client.HTTPConnection(sys.argv[2] if len(sys.argv)>2 else u.hostname,3128 if len(sys.argv)>2 else u.port,timeout=8)
c.request('GET',sys.argv[1] if len(sys.argv)>2 else u.path or '/');r=c.getresponse();b=r.read();print(json.dumps({'status':r.status,'body':b.decode(errors='replace')}))
'''
 args=['python3','-c',script,url]+([proxy] if proxy else [])
 p=subprocess.run(['ip','netns','exec',nsname]+args,text=True,capture_output=True,timeout=15)
 return json.loads(p.stdout) if p.returncode==0 else {'error':p.stderr[-500:]}
def ok(name):print('PASS '+name,flush=True)
api('status')
for name,dev,addr,peer in [('milab-lan','lablan','198.51.100.1/24','198.51.100.2/24'),('milab-wan','labwan','203.0.113.1/24','203.0.113.2/24')]:
 run(['ip','netns','del',name],check=False);run(['ip','link','del',dev],check=False)
 run(['ip','netns','add',name]);run(['ip','link','add',dev,'type','veth','peer','name','client']);run(['ip','link','set','client','netns',name])
 ns(name,['ip','link','set','lo','up']);ns(name,['ip','link','set','client','up']);ns(name,['ip','addr','add',peer,'dev','client'])
 ns(name,['ip','route','add','default','via',addr.split('/')[0]])
body='''from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  body=(b"X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" if self.path=='/eicar' else b'clean download')
  self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def log_message(self,*args):pass
ThreadingHTTPServer(('0.0.0.0',18080),Handler).serve_forever()
'''
servers=[]
for name in ('milab-wan','milab-lan'):
 servers.append(subprocess.Popen(['ip','netns','exec',name,'python3','-c',body],stdout=subprocess.DEVNULL,stderr=open('/tmp/'+name+'.log','w')))
config={'schema':1,'interfaces':[{'name':'LAN','device':'lablan','address':'198.51.100.1/24'},{'name':'WAN','device':'labwan','address':'203.0.113.1/24'},{'name':'UPLINK','device':'eth1','address':'192.0.2.2/24'}],'addresses':[],'groups':[],'services':[],'service_groups':[],'routes':[{'id':'1','destination':'0.0.0.0/0','gateway':'192.0.2.1','interface':'UPLINK','distance':10,'priority':0,'enabled':True}],'policies':[{'id':'1','name':'LAN-WAN','srcintf':['LAN'],'dstintf':['WAN'],'srcaddr':['all'],'dstaddr':['all'],'service':['ALL'],'action':'accept','nat':True,'log':False,'enabled':True}]}
apply(config)
assert request('milab-lan','http://203.0.113.2:18080/')['status']==200;ok('native configuration, forwarded HTTP and SNAT')
changed=copy.deepcopy(config);changed['policies'][0]['action']='deny';apply(changed,confirm=False)
assert 'error' in request('milab-lan','http://203.0.113.2:18080/');api('rollback',{})
assert request('milab-lan','http://203.0.113.2:18080/')['status']==200;ok('deny policy and manual rollback restore traffic')
# Real inline inspection, using only the bundled local signatures.
ips=copy.deepcopy(config)
sys.path.insert(0,'/usr/lib/murus-igneus');import security
ips.update(security.defaults());ips['utm'].update(ips=True,clients=['198.51.100.0/24'])
apply(ips)
assert request('milab-lan','http://203.0.113.2:18080/')['status']==200
assert 'error' in request('milab-lan','http://203.0.113.2:18080/etc/passwd')
alerts=api('security')['alerts'];assert any(a['action']=='blocked' for a in alerts),alerts
ok('Suricata passes clean HTTP and blocks local attack signature')
run(['pkill','-TERM','-f','^suricata -c /run/murus-igneus/']);time.sleep(2)
assert 'error' in request('milab-lan','http://203.0.113.2:18080/');ok('IPS engine termination fails closed')
apply(config)
# Real WireGuard handshake and a policy-controlled tunnel to LAN.
key=run(['wg','genkey']).strip();pub=run(['wg','pubkey'],input=key+'\n').strip();server=api('vpn/key',{})['public_key']
vpn=copy.deepcopy(config);vpn.update(security.defaults());vpn['vpn'].update(enabled=True,public_device='labwan',peers=[{'name':'lab','public_key':pub,'allowed_ips':['10.77.0.2/32'],'keepalive':0}])
vpn['policies'].append({'id':'2','name':'VPN-LAN','srcintf':['VPN'],'dstintf':['LAN'],'srcaddr':['all'],'dstaddr':['all'],'service':['ALL'],'action':'accept','nat':False,'log':False,'enabled':True})
apply(vpn)
ns('milab-wan',['ip','link','add','wgclient','type','wireguard'])
path=Path('/run/lab-wg.conf');path.write_text('[Interface]\nPrivateKey = '+key+'\n[Peer]\nPublicKey = '+server+'\nEndpoint = 203.0.113.1:51820\nAllowedIPs = 198.51.100.0/24\nPersistentKeepalive = 1\n');path.chmod(0o600)
ns('milab-wan',['wg','setconf','wgclient',str(path)]);path.unlink()
ns('milab-wan',['ip','addr','add','10.77.0.2/32','dev','wgclient']);ns('milab-wan',['ip','link','set','wgclient','up']);ns('milab-wan',['ip','route','add','198.51.100.0/24','dev','wgclient'])
assert request('milab-wan','http://198.51.100.2:18080/')['status']==200
handshakes=run(['wg','show','mivpn0','latest-handshakes']);assert int(handshakes.split()[1])>0;ok('WireGuard handshake and VPN-to-LAN policy')
deny=copy.deepcopy(vpn);deny['policies'][-1]['action']='deny';apply(deny,confirm=False)
assert 'error' in request('milab-wan','http://198.51.100.2:18080/');api('rollback',{})
assert request('milab-wan','http://198.51.100.2:18080/')['status']==200;ok('VPN deny policy and rollback')
apply(config)
print('NETWORK TESTS COMPLETE',flush=True)
if os.environ.get('MURUS_SKIP_SIGNATURE_UPDATE')=='YES':
 print('SKIP official signature download and ClamAV checks (offline lab)',flush=True);sys.exit(0)
# Definitions must be official. A failed download must not be replaced by a fake database.
db=Path('/var/lib/clamav')
if not all(any((db/(name+suffix)).is_file() for suffix in ('.cvd','.cld')) for name in ('main','daily')):
 api('security/update',{'engine':'clamav'})
 for attempt in range(600):
  j=api('job')
  if j['state']!='running':break
  time.sleep(2)
 print('CLAMAV UPDATE '+json.dumps(j),flush=True)
 if j['state']!='succeeded':raise RuntimeError('Official ClamAV definitions unavailable')
else:print('Using official ClamAV databases bundled by the builder',flush=True)
av=copy.deepcopy(config);av.update(security.defaults());av['utm'].update(proxy=True,proxy_device='lablan',clients=['198.51.100.0/24'],upstream_networks=['203.0.113.0/24'],blocked_domains=['blocked.example'])
apply(av)
assert request('milab-lan','http://203.0.113.2:18080/','198.51.100.1')['status']==200
assert request('milab-lan','http://203.0.113.2:18080/eicar','198.51.100.1')['status']==403
assert request('milab-lan','http://blocked.example/','198.51.100.1')['status']==403
ok('real ClamAV proxy clean download, EICAR block and domain filter')
run(['pkill','-TERM','-f','^clamd --config-file=/run/murus-igneus/']);time.sleep(1)
assert request('milab-lan','http://203.0.113.2:18080/','198.51.100.1')['status']==502;ok('AV engine failure does not deliver content')
apply(config)
print('ALL RUNTIME TESTS COMPLETE',flush=True)
