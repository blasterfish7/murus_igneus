"""Real parental DNS, TCP, DHCP and proxy packets in a disposable namespace. SPDX-License-Identifier: MIT."""
import ast
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src/murus_igneus'))
import server
import security
import parental
import avproxy
from configuration import empty,compile_config

assert os.environ.get('MURUS_LAB')=='YES' and os.geteuid()==0,'Disposable root lab required'
assert os.readlink('/proc/self/ns/net')!=os.readlink('/proc/1/ns/net'),'Separate network namespace required'
checks=[];processes=[];proxy=None;stream=None


def run(args,check=True,**kwargs):
    result=subprocess.run(args,text=True,capture_output=True,timeout=15,**kwargs)
    if check and result.returncode:raise AssertionError(' '.join(args)+': '+result.stderr[-1000:])
    return result.stdout.strip()


def ns(name,args,**kwargs):return run(['ip','netns','exec',name]+args,**kwargs)


def ok(name):checks.append(name);print('PASS '+name,flush=True)


def apply(config,confirm=True):
    plan=compile_config(config,server.MGMT);assert plan['ready'],plan['blockers']
    with server.LOCK:
        ident=server.apply(plan)
        if confirm:
            server.atomic(server.STATE/'active.json',json.dumps(plan));server.ACTIVE=plan;server.PENDING=None
    return ident


def query(domain,source='10.60.0.10',tcp=False,target='1.1.1.1',qtype=1):
    code=r'''import socket,struct,json
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM if TCP else socket.SOCK_DGRAM);s.bind((SOURCE,0));s.settimeout(2)
packet=struct.pack('!6H',4321,256,1,0,0,0)+b''.join(bytes([len(v)])+v.encode() for v in DOMAIN.split('.'))+b'\0'+struct.pack('!HH',QTYPE,1)
if TCP:
 s.connect((TARGET,53));s.sendall(struct.pack('!H',len(packet))+packet);length=struct.unpack('!H',s.recv(2))[0];data=b''
 while len(data)<length:data+=s.recv(length-len(data))
else:s.sendto(packet,(TARGET,53));data=s.recv(4096)
print(json.dumps({'rcode':data[3]&15,'answers':struct.unpack('!H',data[6:8])[0],'wire':data.hex(),'ip':socket.inet_ntoa(data[-4:]) if len(data)>=4 else ''}))
'''
    return json.loads(ns('pc-kid',['python3','-c',f'DOMAIN={domain!r};SOURCE={source!r};TCP={tcp!r};TARGET={target!r};QTYPE={qtype!r}\n'+code]))


def http(domain='192.0.2.2',source='10.60.0.10',use_proxy=False):
    code='''import http.client,json
try:
 c=http.client.HTTPConnection(HOST,PORT,timeout=1,source_address=(SOURCE,0));c.request('GET',PATH);r=c.getresponse();print(json.dumps({'status':r.status,'body':r.read().decode()}));c.close()
except OSError as exc:print(json.dumps({'error':str(exc)}))
'''
    return json.loads(ns('pc-kid',['python3','-c',f"HOST={'10.60.0.1' if use_proxy else '192.0.2.2'!r};PORT={3128 if use_proxy else 8080};SOURCE={source!r};PATH={'http://'+domain+':8080/' if use_proxy else '/'!r}\n"+code]))


def stream_request():
    stream.stdin.write('probe\n');stream.stdin.flush()
    assert select.select([stream.stdout],[],[],4)[0],'Stream response timeout'
    return stream.stdout.readline().strip()


with tempfile.TemporaryDirectory(prefix='murus-parental-lab-') as directory:
    work=Path(directory);server.STATE=work;server.MGMT='mgmt0';security.RUN=work/'run';security.RUN.mkdir()
    run(['mount','--make-rprivate','/']);run(['ip','link','set','lo','up'])
    run(['ip','link','add','mgmt0','type','dummy']);run(['ip','addr','add','198.18.0.1/24','dev','mgmt0']);run(['ip','link','set','mgmt0','up'])
    try:
        for name,dev,addr in [('pc-kid','lan0','10.60.0.10/24'),('pc-up','wan0','192.0.2.2/24')]:
            run(['ip','netns','add',name]);run(['ip','link','add',dev,'type','veth','peer','name','pcpeer']);run(['ip','link','set','pcpeer','netns',name])
            ns(name,['ip','link','set','pcpeer','name','eth0']);ns(name,['ip','link','set','lo','up'])
            if name=='pc-kid':ns(name,['ip','link','set','eth0','address','02:00:00:00:00:01'])
            ns(name,['ip','addr','add',addr,'dev','eth0']);ns(name,['ip','link','set','eth0','up'])
        ns('pc-kid',['ip','addr','add','10.60.0.11/24','dev','eth0']);ns('pc-kid',['ip','route','add','default','via','10.60.0.1'])
        fixture=r'''import socketserver,socket,struct,threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
class HTTP(BaseHTTPRequestHandler):
 def do_GET(self):
  data=b'parental runtime';self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
 def log_message(self,*args):pass
class UDP(socketserver.BaseRequestHandler):
 def handle(self):
  packet,sock=self.request;end=12
  while packet[end]:end+=packet[end]+1
  end+=5;answer=packet[:2]+struct.pack('!5H',0x8180,1,1,0,0)+packet[12:end]+b'\xc0\x0c'+struct.pack('!HHIH',1,1,5,4)+socket.inet_aton('203.0.113.77');sock.sendto(answer,self.client_address)
class TCP(socketserver.BaseRequestHandler):
 def handle(self):
  while True:
   data=self.request.recv(100)
   if not data:return
   self.request.sendall(data)
for address,handler,kind in [(('0.0.0.0',53),UDP,socketserver.ThreadingUDPServer),(('0.0.0.0',853),TCP,socketserver.ThreadingTCPServer),(('0.0.0.0',8081),TCP,socketserver.ThreadingTCPServer)]:
 service=kind(address,handler);threading.Thread(target=service.serve_forever,daemon=True).start()
ThreadingHTTPServer(('0.0.0.0',8080),HTTP).serve_forever()
'''
        processes.append(subprocess.Popen(['ip','netns','exec','pc-up','python3','-c',fixture],stderr=sys.stderr))
        time.sleep(.25)
        run(['nft','-f','-'],input=server.baseline(server.MGMT))
        c=empty();c['interfaces']=[{'name':'LAN','device':'lan0','address':'10.60.0.1/24'},{'name':'WAN','device':'wan0','address':'192.0.2.1/24'}]
        c['policies']=[{'id':'1','name':'LAN WAN','srcintf':['LAN'],'dstintf':['WAN'],'srcaddr':['all'],'dstaddr':['all'],'service':['ALL'],'action':'accept','nat':True,'log':False,'enabled':True}]
        c['dhcp']=[{'interface':'LAN','start':'10.60.0.100','end':'10.60.0.110','lease_hours':12,'dns_servers':['192.0.2.2'],'enabled':True}]
        c['dhcp_reservations']=[{'interface':'LAN','mac':'02:00:00:00:00:01','address':'10.60.0.105','name':'child-device','enabled':True}]
        c.update(parental.defaults());c['parental'].update(enabled=True,reporting=True,upstream_servers=['192.0.2.2'])
        p={'id':1,'name':'Child lab','enabled':True,'interface':'LAN','clients':['10.60.0.10','10.60.0.105'],'categories':['adult'],'services':['instagram'],'blocked_domains':['blocked.test'],'allowed_domains':['school.blocked.test'],'windows':[],'paused':False,'enforce_dns':True,'block_quic':False,'safe_search':True,'youtube_restricted':'strict','block_ipv6':True,'devices':[{'name':'Telefono','address':'10.60.0.10'},{'name':'Tablet','address':'10.60.0.105'}]}
        c['parental']['profiles']=[p]
        security.write(parental.feed_path('adult',work),json.dumps({'domains':['adult.test'],'category':'adult','updated':time.time(),'sha256':'lab','source':'controlled-fixture'}))
        apply(c)
        allowed=query('allowed.test');assert allowed['answers']>0 and allowed['ip']=='203.0.113.77',allowed
        ok('Protected DNS sent to an external resolver is redirected through the local profile')
        for name in ['blocked.test','sub.blocked.test','adult.test','instagram.com']:
            answer=query(name);assert answer['answers']==0 and answer['rcode'] in (0,3),answer
        ok('Custom domains, subdomains, category and Instagram are blocked by real dnsmasq')
        assert query('blocked.test',tcp=True)['answers']==0
        ok('DNS over TCP is also redirected and filtered')
        assert query('school.blocked.test')['answers']>0
        ok('Specific allow exception overrides a blocked parent domain')
        assert query('blocked.test',source='10.60.0.11',target='192.0.2.2')['answers']>0
        ok('Unassigned device retains normal DNS access')
        dot="import socket;s=socket.socket();s.bind(('10.60.0.10',0));s.settimeout(1)\ntry:s.connect(('192.0.2.2',853));print('CONNECTED')\nexcept OSError:print('BLOCKED')"
        assert ns('pc-kid',['python3','-c',dot])=='BLOCKED'
        ok('Direct DNS-over-TLS on TCP 853 is blocked for protected clients')
        assert http()['status']==200
        ok('Allowed Internet forwarding and SNAT remain operational')
        for host in ['www.google.com','www.google.it','www.youtube.com','m.youtube.com','youtubei.googleapis.com']:
            answer=query(host);assert answer['ip']=='216.239.38.120',answer
        ok('Google SafeSearch and YouTube strict mode return actual restricted VIP records through forced DNS')
        answer=query('www.google.com',qtype=28)
        assert 'cb00714d' not in answer['wire'],answer  # Fixture upstream returns an A even for AAAA: must not be contacted.
        ok('SafeSearch AAAA requests cannot leak to the unrestricted upstream resolver')
        # Prove the opt-in whole-LAN IPv6 guard overrides a deliberately permissive later chain.
        run(['sysctl','-w','net.ipv6.conf.all.forwarding=1'])
        run(['ip','-6','addr','add','fd60::1/64','dev','lan0','nodad']);run(['ip','-6','addr','add','fd61::1/64','dev','wan0','nodad'])
        ns('pc-kid',['ip','-6','addr','add','fd60::10/64','dev','eth0','nodad']);ns('pc-up',['ip','-6','addr','add','fd61::2/64','dev','eth0','nodad'])
        ns('pc-kid',['ip','-6','route','add','default','via','fd60::1']);ns('pc-up',['ip','-6','route','add','default','via','fd61::1'])
        # Static lab neighbors isolate routed filtering from NDP, which the whole-LAN guard intentionally drops.
        lan_mac=json.loads(run(['ip','-j','link','show','dev','lan0']))[0]['address']
        wan_mac=json.loads(run(['ip','-j','link','show','dev','wan0']))[0]['address']
        up_mac=json.loads(ns('pc-up',['ip','-j','link','show','dev','eth0']))[0]['address']
        run(['ip','-6','neigh','replace','fd60::10','lladdr','02:00:00:00:00:01','dev','lan0','nud','permanent'])
        run(['ip','-6','neigh','replace','fd61::2','lladdr',up_mac,'dev','wan0','nud','permanent'])
        ns('pc-kid',['ip','-6','neigh','replace','fd60::1','lladdr',lan_mac,'dev','eth0','nud','permanent'])
        ns('pc-up',['ip','-6','neigh','replace','fd61::1','lladdr',wan_mac,'dev','eth0','nud','permanent'])
        v6fixture="import socket;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('fd61::2',8082));s.listen()\nwhile True:\n c,a=s.accept();c.sendall(b'ipv6');c.close()"
        processes.append(subprocess.Popen(['ip','netns','exec','pc-up','python3','-c',v6fixture],stderr=sys.stderr));time.sleep(.2)
        run(['nft','insert','rule','inet','murus_igneus','forward','meta','nfproto','ipv6','accept'])
        run(['nft','insert','rule','inet','murus_igneus','input','meta','nfproto','ipv6','accept'])
        v6client="import socket;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.settimeout(3)\ntry:s.connect(('fd61::2',8082));print(s.recv(16).decode())\nexcept OSError:print('BLOCKED')"
        assert ns('pc-kid',['python3','-c',v6client])=='BLOCKED'
        removed=0
        for chain in ['pc_forward','pc_input','pc_output']:
            handles=json.loads(run(['nft','-j','-a','list','chain','inet','murus_igneus',chain]))
            for entry in handles['nftables']:
                rule=entry.get('rule',{})
                if rule.get('comment')=='parental IPv6 LAN':
                    run(['nft','delete','rule','inet','murus_igneus',chain,'handle',str(rule['handle'])]);removed+=1
        assert removed==4,removed
        positive=ns('pc-kid',['python3','-c',v6client]);assert positive=='ipv6',(positive,run(['ip','-6','neigh']),ns('pc-kid',['ip','-6','neigh']))
        ok('Opt-in IPv6 guard blocks actual routed packets on the whole protected LAN before a permissive forwarding rule')

        # Sample the real named counters and dnsmasq query stream; no fabricated telemetry.
        time.sleep(.25);parental.REPORTER.collect()
        report=parental.reporting.report(work)
        device=next(r for r in report['devices'] if r['client']=='10.60.0.10/32')
        assert device['upload_bytes']>0 and device['download_bytes']>0,report
        assert device['blocked_packets']>0,report
        assert device['dns_queries']>=6 and device['dns_filtered']>=5,report
        assert any(r['domain']=='instagram.com' and r['filtered']>0 for r in report['domains']),report
        assert not any(r['client']=='10.60.0.11/32' for r in report['devices']),report
        ok('Reporting measures actual bidirectional IPv4 counters, DNS requests and filtered domains for assigned devices only')
        parental.clear_report(work)
        assert parental.reporting.report(work)['devices']==[]
        assert http()['status']==200;parental.REPORTER.collect()
        assert sum(r['upload_bytes'] for r in parental.reporting.report(work)['devices'])>0
        ok('Clearing live reports resets the baseline without disabling forwarding or recounting old traffic')
        # Check the existing antivirus proxy path with a controlled clean scanner.
        proxy=avproxy.create_proxy({'clients':['10.60.0.0/24'],'upstream_networks':['192.0.2.0/24'],'blocked_domains':[]},lambda data:(True,'fixture'),address=('10.60.0.1',3128))
        threading.Thread(target=proxy.serve_forever,daemon=True).start()
        run(['nft','add','rule','inet','murus_igneus','input','iifname','lan0','ip','saddr','10.60.0.0/24','tcp','dport','3128','accept'])
        with patch.object(avproxy.socket,'getaddrinfo',return_value=[(2,1,6,'',('192.0.2.2',8080))]):
            assert http('blocked.test',use_proxy=True)['status']==403
            assert http('allowed.test',use_proxy=True)['status']==200
        ok('Local HTTP antivirus proxy respects parental domain blocks without losing allowed downloads')
        stream_code="""import socket,sys
s=socket.create_connection(('192.0.2.2',8081),timeout=2,source_address=('10.60.0.10',0));s.settimeout(1)
for line in sys.stdin:
 try:s.sendall(b'probe');print('OK' if s.recv(100) else 'CLOSED',flush=True)
 except OSError:print('BLOCKED',flush=True)
"""
        stream=subprocess.Popen(['ip','netns','exec','pc-kid','python3','-u','-c',stream_code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        assert stream_request()=='OK';parental.pause(1,1);assert stream_request()=='BLOCKED';assert 'error' in http();assert http(source='10.60.0.11')['status']==200
        ok('Immediate pause blocks new and already-established TCP while leaving an unassigned device online')
        parental.pause(1,0);assert http()['status']==200
        ok('Resume removes temporary pause and restores Internet access')
        with parental.LOCK:
            active=parental.CURRENT['settings']['profiles'][0]
            local=datetime.now(parental.ZoneInfo('Europe/Rome')); start=(local.hour+23)%24;end=(local.hour+1)%24
            active['night_windows']=[{'days':list(range(7)),'start':f'{start:02d}:00','end':f'{end:02d}:00'}]
            parental.tick();assert 'error' in http()
            parental.bonus(1,30);assert http()['status']==200
            assert query('instagram.com')['answers']==0
            parental.pause(1,1);assert 'error' in http();parental.pause(1,0);assert http()['status']==200
            parental.bonus(1,0);assert 'error' in http()
            active['night_windows']=[];parental.tick();assert http()['status']==200
        ok('Night blocks Internet; a timed bonus restores access with DNS filtering, while manual pause and bonus revocation still block')
        with parental.LOCK:
            active['study_windows']=[{'days':[0],'start':'16:00','end':'19:00'}];active['study_domains']=['school.test']
            parental.tick(datetime(2026,10,26,16,0,tzinfo=timezone.utc))
            assert query('school.test')['answers']>0
            unknown=query('allowed.test');ordinary=query('school.blocked.test')
            assert unknown['answers']==0 and ordinary['answers']==0,(unknown,ordinary)
            assert query('www.google.com')['answers']==0
            active['study_windows']=[];parental.tick()
            assert query('allowed.test')['answers']>0 and query('www.google.com')['ip']=='216.239.38.120'
        ok('Entering study mode switches real DNS to the school allowlist; leaving restores normal filtering and SafeSearch')
        with parental.LOCK:
            expected=parental.CURRENT
            payload={'category':'adult','domains':['newadult.test'],'updated':time.time(),'sha256':'controlled-refresh','source':'controlled-fixture'}
            with patch.object(parental,'download_feed',return_value=payload):parental.refresh_active_lists(expected)
            assert query('newadult.test')['answers']==0 and query('adult.test')['answers']>0
            assert http()['status']==200
            with patch.object(parental,'download_feed',side_effect=ValueError('invalid HTML')):
                try:parental.refresh_active_lists(expected);raise AssertionError('Invalid refresh accepted')
                except ValueError:pass
            assert query('newadult.test')['answers']==0 and http()['status']==200
            # Restore the original fixture so later rollback tests use the same baseline.
            payload['domains']=['adult.test']
            with patch.object(parental,'download_feed',return_value=payload):parental.refresh_active_lists(expected)
        ok('Automatic refresh path activates validated category data in actual resolvers and keeps it after a failed subsequent download')

        with parental.LOCK:
            parental.CURRENT['settings']['profiles'][0]['windows']=[{'days':[0],'start':'16:00','end':'17:00'}]
            parental.tick(datetime(2026,10,26,18,0,tzinfo=timezone.utc));assert 'error' in http()
            parental.tick(datetime(2026,10,26,15,30,tzinfo=timezone.utc));assert http()['status']==200
            parental.CURRENT['settings']['profiles'][0]['windows']=[];parental.tick()
        ok('Weekly schedule changes actual traffic in the configured Europe/Rome timezone')
        # Reuse the real DHCP DORA client from the native packet laboratory.
        tree=ast.parse((ROOT/'tools/validate-native-networking.py').read_text())
        client=next(n.value.value for n in ast.walk(tree) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='dhcp_client' for t in n.targets))
        client=client.replace('client0.20','eth0');lease=json.loads(ns('pc-kid',['python3','-c',client]));assert lease['address']=='10.60.0.105',lease
        ok('DHCP DORA returns the exact MAC-reserved address for the protected device')
        security.stop('parental-1');parental.tick();assert 'error' in http()
        ok('Resolver process failure blocks Internet rather than silently bypassing filtering')
        parental.activate(server.ACTIVE['parental'],work,server.MGMT);assert http()['status']==200
        changed=copy.deepcopy(c);changed['parental']['profiles'][0]['blocked_domains'].append('allowed.test')
        ident=apply(changed,confirm=False);assert query('allowed.test')['answers']==0
        with server.LOCK:server.rollback(ident)
        assert query('allowed.test')['answers']>0
        ok('Manual rollback restores the previous profile and resolver rules')
        bad=copy.deepcopy(c);bad['parental']['profiles'][0]['categories'].append('gambling')
        try:apply(bad);raise AssertionError('Missing category was applied')
        except ValueError as exc:assert 'Scaricare prima' in str(exc),exc
        assert http()['status']==200 and query('blocked.test')['answers']==0
        ok('Missing category data refuses activation and restores the previously protected configuration')
    finally:
        if stream is not None:stream.stdin.close();stream.terminate();stream.wait(timeout=5)
        if proxy is not None:proxy.shutdown();proxy.server_close()
        parental.stop();security.activate(security.defaults());server.networking.stop()
        for process in processes:process.terminate();process.wait(timeout=5)
        for name in ['pc-kid','pc-up']:run(['ip','netns','del',name],check=False)
        (ROOT/'dist').mkdir(exist_ok=True);(ROOT/'dist/parental-runtime-qa.json').write_text(json.dumps({'success':len(checks)==23,'checks':checks,'scope':'Real dnsmasq/nftables/DHCP/TCP and the actual HTTP proxy with a controlled clean-scanner fixture; no mobile network, real encrypted app efficacy or commercial category certification.'},indent=2))
assert len(checks)==23,checks
