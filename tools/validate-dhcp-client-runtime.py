"""Real DHCP WAN and anti-lockout in a disposable network namespace. SPDX-License-Identifier: MIT."""
import copy
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src/murus_igneus'))
import server
import security
import networking
import dhcp_client
from configuration import empty, compile_config

assert os.environ.get('MURUS_LAB') == 'YES' and os.geteuid() == 0
assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net')
checks = []; processes = []


def run(args):
    return subprocess.check_output(args,text=True,stderr=subprocess.STDOUT,timeout=20).strip()


def ns(name,args):
    return run(['ip','netns','exec',name]+args)


def request(namespace, address, port):
    code = "import http.client,json\ntry:\n c=http.client.HTTPConnection(%r,%r,timeout=2);c.request('GET','/');r=c.getresponse();print(r.status);r.read()\nexcept OSError:print('blocked')" % (address,port)
    return ns(namespace,['python3','-c',code])


def apply(config,confirm=True):
    plan = compile_config(config,server.MGMT)
    assert plan['ready'],plan['blockers']
    with server.LOCK:
        ident = server.apply(plan)
        if confirm:
            server.ACTIVE = plan;server.PENDING = None
    return ident


def ok(name):
    checks.append(name);print('PASS '+name,flush=True)


def wait_for(predicate, timeout=8):
    deadline = time.monotonic()+timeout
    while time.monotonic() < deadline:
        if predicate():return
        time.sleep(.1)
    raise AssertionError('Timed out waiting for DHCP kernel state')


with tempfile.TemporaryDirectory(prefix='murus-dhcp-client-') as directory:
    work = Path(directory);server.STATE = work;server.MGMT = 'mgmt0';security.RUN = work/'run'
    run(['mount','--make-rprivate','/']);run(['ip','link','set','lo','up'])
    try:
        for name,dev,address in [('mdwan','wan0','192.0.2.1/24'),('mdlan','lan0','10.20.0.2/24'),('mdmgmt','mgmt0','198.18.0.2/24')]:
            run(['ip','netns','add',name]);run(['ip','link','add',dev,'type','veth','peer','name','peer0']);run(['ip','link','set','peer0','netns',name]);run(['ip','link','set',dev,'up'])
            ns(name,['ip','link','set','lo','up']);ns(name,['ip','link','set','peer0','up']);ns(name,['ip','addr','add',address,'dev','peer0'])
        run(['ip','addr','add','198.18.0.1/24','dev','mgmt0'])
        ns('mdlan',['ip','route','add','default','via','10.20.0.1'])
        ns('mdwan',['ip','addr','add','203.0.113.5/32','dev','lo'])
        fixture = "from http.server import BaseHTTPRequestHandler,HTTPServer\nclass H(BaseHTTPRequestHandler):\n def do_GET(self):\n  self.send_response(200);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'OK')\n def log_message(self,*args):pass\nHTTPServer(('0.0.0.0',%d),H).serve_forever()"
        processes.append(subprocess.Popen(['ip','netns','exec','mdwan','python3','-c',fixture%18080],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
        processes.append(subprocess.Popen(['python3','-c',fixture%8443],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
        config = empty();config.update(networking.defaults())
        config['interfaces'] = [{'name':'WAN','device':'wan0','address':'192.0.2.100/24'},{'name':'LAN','device':'lan0','address':'10.20.0.1/24'}]
        config['routes'] = [{'id':'1','destination':'0.0.0.0','gateway':'192.0.2.1','interface':'WAN','distance':10,'priority':0,'enabled':True}]
        config['policies'] = [{'id':'1','name':'LAN Internet','srcintf':['LAN'],'dstintf':['WAN'],'srcaddr':['all'],'dstaddr':['all'],'service':['ALL'],'action':'accept','nat':True,'log':False,'enabled':True}]
        security.command(['nft','-f','-'],server.baseline(server.MGMT))
        apply(config)
        wait_for(lambda: request('mdlan','203.0.113.5',18080) == '200')
        dnsmasq = subprocess.Popen(['ip','netns','exec','mdwan','dnsmasq','--no-daemon','--conf-file=','--port=0','--interface=peer0','--bind-interfaces','--dhcp-range=192.0.2.20,192.0.2.20,255.255.255.0,1m','--dhcp-option=3,192.0.2.1','--dhcp-option=6,192.0.2.1','--dhcp-leasefile='+str(work/'leases'),'--no-hosts','--no-resolv'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        processes.append(dnsmasq);time.sleep(.3)
        dynamic = copy.deepcopy(config);dynamic['routes'] = [];dynamic['interfaces'][0].update(address='',address_mode='dhcp',dhcp_metric=100)
        resolv = Path('/etc/resolv.conf').read_bytes()
        ident = apply(dynamic,False)
        statepath = next((security.RUN/'dhcp-clients').glob('*/state.json'))
        state = json.loads(statepath.read_text())
        assert state['address'] == '192.0.2.20/24' and state['route'] == '192.0.2.1',state
        assert request('mdlan','203.0.113.5',18080) == '200'
        routes = json.loads(run(['ip','-j','-4','route','show','default']))
        assert any(r.get('gateway') == '192.0.2.1' and r.get('metric') == 100 and str(r.get('protocol')) == '202' for r in routes),routes
        ok('Real DHCP WAN DORA acquires IPv4/default gateway and carries actual NAT traffic')
        time.sleep(1);before = state['expires'];os.kill(security.PROCESSES['dhcp-client-wan0'].pid,signal.SIGUSR1)
        wait_for(lambda: json.loads(statepath.read_text())['expires'] > before+.5)
        assert request('mdlan','203.0.113.5',18080) == '200' and Path('/etc/resolv.conf').read_bytes() == resolv
        ok('Real DHCP renewal preserves NAT connectivity without replacing system DNS')
        with server.LOCK:result = server.rollback(ident)
        assert result['ok'],result
        assert request('mdlan','203.0.113.5',18080) == '200'
        assert 'dhcp-client-wan0' not in security.PROCESSES
        assert '192.0.2.100/24' in run(['ip','-4','addr','show','dev','wan0'])
        ok('Manual rollback removes owned DHCP resources and restores the previous static address and route')
        apply(dynamic)
        statepath = next((security.RUN/'dhcp-clients').glob('*/state.json'))
        dnsmasq.terminate();dnsmasq.wait(timeout=5)
        with dhcp_client.locked(statepath) as state:
            state['expires'] = time.monotonic()-1;dhcp_client.write(statepath,state)
        wait_for(lambda: not json.loads(statepath.read_text()).get('address'))
        assert request('mdlan','203.0.113.5',18080) == 'blocked'
        assert '192.0.2.20/24' not in run(['ip','-4','addr','show','dev','wan0'])
        assert '198.18.0.1/24' in run(['ip','-4','addr','show','dev','mgmt0'])
        ok('Recorded lease expiry removes the real address/default route and keeps management unchanged')
        apply(config)
        try:apply(dynamic,False)
        except Exception:pass
        else:raise AssertionError('DHCP without a responding server unexpectedly activated')
        assert server.PENDING is None and request('mdlan','203.0.113.5',18080) == '200',server.LAST
        ok('Missing DHCP response refuses activation and restores working static connectivity')
        deny = copy.deepcopy(config);deny['policies'][0].update(action='deny',nat=False);apply(deny)
        assert request('mdmgmt','198.18.0.1',8443) == '200'
        assert request('mdwan','192.0.2.100',8443) == 'blocked'
        assert request('mdlan','203.0.113.5',18080) == 'blocked'
        assert 'Murus anti-lockout HTTPS' in run(['nft','list','table','inet','murus_igneus'])
        ok('Protected anti-lockout allows management TCP 8443 with data denied and rejects administration from WAN')
        target = ROOT/'dist/dhcp-client-runtime-qa.json';target.parent.mkdir(exist_ok=True)
        target.write_text(json.dumps({'success':True,'checks':checks,'scope':'Disposable namespaces; real udhcpc/dnsmasq, kernel addresses/routes and TCP. Expiry clock is controlled; no production network modified.'},indent=2)+'\n')
    finally:
        networking.stop()
        for process in processes:
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait()
        for name in ('mdwan','mdlan','mdmgmt'):
            subprocess.run(['ip','netns','del',name],check=False)
