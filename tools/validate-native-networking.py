"""Real packets in an isolated, disposable network namespace. SPDX-License-Identifier: MIT.
Run: sudo env MURUS_LAB=YES unshare --mount --net --fork python3 tools/validate-native-networking.py
Never run in a workstation/production network namespace.
"""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src/murus_igneus'))
import server
import security
import networking
import traffic
from configuration import empty, compile_config

assert os.environ.get('MURUS_LAB') == 'YES' and os.geteuid() == 0, 'Explicit disposable root lab required'
assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net'), 'A separate network namespace is required'


def run(args, **kwargs):
    return subprocess.check_output(args, text=True, timeout=20, **kwargs).strip()


def ns(name, args):
    return run(['ip', 'netns', 'exec', name] + args)


def ok(name):
    checks.append(name); print('PASS ' + name, flush=True)


def apply(config, confirm=True):
    plan = compile_config(config, server.MGMT)
    assert plan['ready'], plan['blockers']
    with server.LOCK:
        ident = server.apply(plan)
        if confirm:
            server.atomic(server.STATE / 'active.json', json.dumps(plan))
            server.ACTIVE = plan; server.PENDING = None
    return ident


def http(source='192.0.2.2', destination='192.0.2.1', port=8080):
    code = '''import http.client,json
try:
 c=http.client.HTTPConnection(%r,%r,timeout=2,source_address=(%r,0));c.request('GET','/');r=c.getresponse();print(json.dumps({'status':r.status,'body':r.read().decode()}));c.close()
except OSError as e:print(json.dumps({'error':str(e)}))
''' % (destination, port, source)
    return json.loads(ns('miwan', ['python3', '-c', code]))


def dns(namespace, target, expected=True):
    code = '''import socket,struct,json
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2)
packet=struct.pack('!6H',1234,256,1,0,0,0)+b'\\x07example\\x04test\\0'+struct.pack('!2H',1,1)
try:
 s.sendto(packet,(%r,53));reply=s.recv(4096);assert reply[3]&15==0 and struct.unpack('!H',reply[6:8])[0]>0,reply.hex();print(json.dumps({'answer':socket.inet_ntoa(reply[-4:])}))
except OSError as e:print(json.dumps({'error':str(e)}))
''' % target
    value = json.loads(ns(namespace, ['python3', '-c', code]))
    assert (value.get('answer') == '203.0.113.77') if expected else 'error' in value, value


checks = []; processes = []
with tempfile.TemporaryDirectory(prefix='murus-network-qa-') as work:
    server.STATE = Path(work); server.MGMT = 'mgmt0'; security.RUN = Path(work) / 'run'
    run(['mount', '--make-rprivate', '/'])
    run(['ip', 'link', 'set', 'lo', 'up'])
    run(['ip', 'link', 'add', 'mgmt0', 'type', 'dummy']); run(['ip', 'addr', 'add', '198.18.0.1/24', 'dev', 'mgmt0']); run(['ip', 'link', 'set', 'mgmt0', 'up'])
    try:
        for name, dev, peer in [('milan', 'trunk0', 'client0'), ('miwan', 'wan0', 'client0')]:
            run(['ip', 'netns', 'add', name]); run(['ip', 'link', 'add', dev, 'type', 'veth', 'peer', 'name', peer]); run(['ip', 'link', 'set', peer, 'netns', name])
            ns(name, ['ip', 'link', 'set', 'lo', 'up']); ns(name, ['ip', 'link', 'set', peer, 'up'])
        ns('milan', ['ip', 'link', 'add', 'link', 'client0', 'name', 'client0.20', 'type', 'vlan', 'id', '20'])
        ns('milan', ['ip', 'addr', 'add', '198.51.100.10/24', 'dev', 'client0.20']); ns('milan', ['ip', 'link', 'set', 'client0.20', 'up'])
        ns('milan', ['ip', 'route', 'add', 'default', 'via', '198.51.100.1'])
        ns('miwan', ['ip', 'addr', 'add', '192.0.2.2/24', 'dev', 'client0']); ns('miwan', ['ip', 'addr', 'add', '192.0.2.3/24', 'dev', 'client0'])
        ns('miwan', ['ip', 'route', 'add', 'default', 'via', '192.0.2.1'])
        run(['nft', '-f', '-'], input=server.baseline(server.MGMT))
        fixture = '''from http.server import BaseHTTPRequestHandler,HTTPServer
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  b=b'murus real VLAN DNAT';self.send_response(200);self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
 def log_message(self,*a):pass
HTTPServer(('0.0.0.0',18080),H).serve_forever()
'''
        dns_fixture = '''import socket,struct
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('192.0.2.2',53))
while True:
 packet,client=s.recvfrom(4096);end=12
 while packet[end]:end+=packet[end]+1
 end+=5
 reply=packet[:2]+struct.pack('!5H',0x8180,1,1,0,0)+packet[12:end]+b'\\xc0\\x0c'+struct.pack('!HHIH',1,1,30,4)+socket.inet_aton('203.0.113.77');s.sendto(reply,client)
'''
        for namespace, code in [('milan', fixture), ('miwan', dns_fixture)]:
            processes.append(subprocess.Popen(['ip', 'netns', 'exec', namespace, 'python3', '-c', code], stdout=subprocess.DEVNULL, stderr=sys.stderr))
        config = empty(); config.update(networking.defaults())
        config['interfaces'] = [{'name': 'WAN', 'device': 'wan0', 'address': '192.0.2.1/24'}, {'name': 'TRUNK', 'device': 'trunk0', 'address': ''},
                                {'name': 'LAN20', 'device': 'trunk0.20', 'address': '198.51.100.1/24', 'parent': 'trunk0', 'vlan_id': 20}]
        config['dns'] = {'enabled': True, 'interfaces': ['LAN20'], 'upstream_servers': ['192.0.2.2'], 'domain': 'lab.lan'}
        config['dhcp'] = [{'interface': 'LAN20', 'start': '198.51.100.100', 'end': '198.51.100.110', 'lease_hours': 12, 'dns_servers': [], 'enabled': True}]
        config['port_forwards'] = [{'id': '1', 'name': 'Web', 'interface': 'WAN', 'public_ip': '192.0.2.1', 'protocol': 'tcp', 'external_port': 8080, 'target_interface': 'LAN20', 'target_ip': '198.51.100.10', 'target_port': 18080, 'source': '192.0.2.2/32', 'enabled': True, 'log': True}]
        apply(config)
        assert http().get('body') == 'murus real VLAN DNAT'; ok('VLAN tagged forwarding and TCP DNAT with no broad allow policy')
        assert 'error' in http(source='192.0.2.3'); ok('DNAT source restriction rejects unauthorized source')
        assert 'error' in http(destination='198.51.100.10', port=18080); ok('Direct internal service access remains blocked')
        dns('milan', '198.51.100.1'); ok('DNS forwarding from VLAN to controlled upstream')
        dns('miwan', '192.0.2.1', expected=False); ok('DNS is blocked from WAN')
        dhcp_client = r'''import socket,struct,json,random
mac=bytes.fromhex(open('/sys/class/net/client0.20/address').read().strip().replace(':',''));xid=random.randrange(1,2**32)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1);s.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'client0.20\0');s.bind(('',68));s.settimeout(8)
def packet(kind,options=b''):
 return struct.pack('!BBBBIHH4s4s4s4s16s64s128s',1,1,6,0,xid,0,0x8000,b'\0'*4,b'\0'*4,b'\0'*4,b'\0'*4,mac+b'\0'*10,b'\0'*64,b'\0'*128)+b'\x63\x82\x53\x63'+bytes([53,1,kind])+options+b'\xff'
def receive(kind):
 while True:
  data,_=s.recvfrom(4096)
  if struct.unpack('!I',data[4:8])[0]!=xid:continue
  opts={};p=240
  while p<len(data) and data[p]!=255:
   k=data[p];p+=1
   if k==0:continue
   n=data[p];p+=1;opts[k]=data[p:p+n];p+=n
  if opts.get(53)==bytes([kind]):return data,opts
s.sendto(packet(1),("255.255.255.255",67));offer,opts=receive(2)
s.sendto(packet(3,bytes([50,4])+offer[16:20]+bytes([54,4])+opts[54]),("255.255.255.255",67));ack,opts=receive(5)
print(json.dumps({'address':socket.inet_ntoa(ack[16:20]),'gateway':socket.inet_ntoa(opts[3][:4]),'dns':socket.inet_ntoa(opts[6][:4])}))
'''
        lease = json.loads(ns('milan', ['python3', '-c', dhcp_client]))
        assert lease['address'].startswith('198.51.100.10') and lease['gateway'] == '198.51.100.1' and lease['dns'] == '198.51.100.1', lease
        assert networking.health()['leases'], 'Lease file missing'
        ok('Real DHCP discover/offer/request/ack over VLAN, gateway and DNS options, lease file')
        sessions = traffic.snapshot()
        assert any(r['destination'] == '192.0.2.1' and r['reply_source'] == '198.51.100.10' for r in sessions['connections']), sessions
        ok('Conntrack API parser reports actual original and DNAT reply tuples')
        modified = copy.deepcopy(config); modified['interfaces'][2]['vlan_id'] = 30
        ident = apply(modified, confirm=False)
        assert 'error' in http()
        with server.LOCK: server.rollback(ident)
        assert http().get('status') == 200
        dns('milan', '198.51.100.1'); ok('Changed VLAN tag and manual rollback restore VLAN, addresses, DNS and DNAT')
        disabled = copy.deepcopy(config); disabled['port_forwards'][0]['enabled'] = False
        ident = apply(disabled, confirm=False); assert 'error' in http()
        with server.LOCK: server.rollback(ident)
        assert http().get('status') == 200; ok('DNAT removal closes service; rollback restores publication')
        apply(disabled, confirm=False)
        assert 'error' in http()
        print('Waiting for the real 90-second confirmation timeout...', flush=True)
        deadline = time.monotonic() + 110
        while server.PENDING and time.monotonic() < deadline:
            time.sleep(.5)
        assert server.PENDING is None, 'Automatic rollback timer did not complete'
        assert http().get('status') == 200
        dns('milan', '198.51.100.1'); ok('Unconfirmed publication removal rolls back automatically after 90 seconds, including DNS')
        saved = json.loads((server.STATE / 'active.json').read_text()); assert saved['configuration']['dns'] == config['dns']
        assert saved['configuration']['interfaces'][2]['vlan_id'] == 20; ok('Confirmed native settings persisted in active.json')
        result = {'success': True, 'checks': checks, 'scope': 'Isolated Linux namespace with real nftables, veth VLAN, dnsmasq, DHCP packets, DNS and TCP traffic; not ISO/hardware acceptance.'}
        target = ROOT / 'dist/native-networking-qa.json'; target.parent.mkdir(exist_ok=True); target.write_text(json.dumps(result, indent=2) + '\n')
    finally:
        networking.stop()
        for process in processes:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait()
        for name in ('milan', 'miwan'):
            subprocess.run(['ip', 'netns', 'del', name], check=False)
