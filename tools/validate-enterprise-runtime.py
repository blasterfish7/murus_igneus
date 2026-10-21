"""Disposable namespace acceptance: real IKEv2 and dual-WAN packets. SPDX-License-Identifier: MIT."""
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src/murus_igneus'))

if '--agent' in sys.argv:
    subprocess.run(['mount','--make-rprivate','/'],check=True)
    subprocess.run(['mount','-t','tmpfs','tmpfs','/run'],check=True)
    import enterprise
    import configuration
    enterprise.RUN = Path(sys.argv[-1]); enterprise.RUN.mkdir(mode=0o700)
    def execute(args):
        subprocess.run(args, check=True, capture_output=True)
    for line in sys.stdin:
        try:
            data = json.loads(line)
            if data['action'] == 'start':
                plan = configuration.compile_config(data['configuration'])
                assert plan['ready'], plan['blockers']
                subprocess.run(['nft','-f','-'],input=plan['nftables'],text=True,check=True,capture_output=True)
                execute(['sysctl','-w','net.ipv4.ip_forward=1'])
                enterprise.activate(plan['enterprise'],plan['configuration']['interfaces'])
                result = enterprise.health()
            elif data['action'] == 'health':
                result = enterprise.health()
            elif data['action'] == 'sas':
                result = enterprise.run(['swanctl','--list-sas','--uri','unix://'+str(enterprise.RUN/'charon.vici')])
            else:
                enterprise.stop(); result = {'stopped':True}
            print(json.dumps({'ok':True,'result':result}),flush=True)
        except Exception as exc:
            if (enterprise.RUN/'charon.log').exists():
                print((enterprise.RUN/'charon.log').read_text()[-6000:],file=sys.stderr,flush=True)
            print(json.dumps({'ok':False,'error':str(exc)}),flush=True)
    enterprise.stop()
    raise SystemExit()

assert os.environ.get('MURUS_LAB') == 'YES', 'Run only in a disposable privileged isolated namespace'
NAMES = []; AGENTS = []; REPORT = []


def command(args, check=True):
    result = subprocess.run(args,text=True,capture_output=True,timeout=10)
    if check and result.returncode:
        raise RuntimeError(' '.join(args)+': '+result.stderr[-1500:])
    return result


def ns(name):
    name = 'mi5-' + name; command(['ip','netns','add',name]); NAMES.append(name)
    command(['ip','-n',name,'link','set','lo','up']); return name


def link(a, da, aa, b, db, ab):
    temporary = 'v' + str(len(command(['ip','-j','link']).stdout)) + da[:4]
    command(['ip','link','add',temporary,'type','veth','peer','name',temporary+'p'])
    command(['ip','link','set',temporary,'netns',a]);command(['ip','link','set',temporary+'p','netns',b])
    for space, old, dev, address in [(a,temporary,da,aa),(b,temporary+'p',db,ab)]:
        command(['ip','-n',space,'link','set',old,'name',dev]);command(['ip','-n',space,'addr','add',address,'dev',dev]);command(['ip','-n',space,'link','set',dev,'up'])


def inside(space, args, check=True):
    return command(['ip','netns','exec',space]+args,check)


def route(space, destination, gateway):
    command(['ip','-n',space,'route','add',destination,'via',gateway])


def agent(space, work):
    process = subprocess.Popen(['ip','netns','exec',space,'unshare','--mount','--fork',sys.executable,'-u',str(Path(__file__).resolve()),'--agent',str(work/space)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
    AGENTS.append(process);return process


def ask(process, action, configuration=None):
    process.stdin.write(json.dumps({'action':action,'configuration':configuration})+'\n');process.stdin.flush()
    if not select.select([process.stdout],[],[],20)[0]:
        raise RuntimeError('Agent timeout')
    line = process.stdout.readline()
    if not line:
        raise RuntimeError('Agent stopped: '+process.stderr.read()[-2000:])
    result = json.loads(line)
    assert result['ok'], result
    return result['result']


def wait_for(fn, timeout=35):
    until=time.monotonic()+timeout
    while time.monotonic()<until:
        if fn():
            return
        time.sleep(1)
    raise AssertionError('Condition did not become true')


def record(name):
    REPORT.append({'name':name,'passed':True});print('PASS '+name,flush=True)


def base():
    return {'schema':1,'interfaces':[],'policies':[],'routes':[]}


try:
    with tempfile.TemporaryDirectory(prefix='murus-enterprise-') as temporary:
        work=Path(temporary)
        a=ns('a');b=ns('b');ca=ns('ca');cb=ns('cb')
        link(a,'eth1','198.18.0.1/24',b,'eth1','198.18.0.2/24')
        link(a,'eth2','10.80.1.1/24',ca,'eth1','10.80.1.2/24')
        link(b,'eth2','10.80.2.1/24',cb,'eth1','10.80.2.2/24')
        route(a,'default','198.18.0.2');route(b,'default','198.18.0.1');route(ca,'default','10.80.1.1');route(cb,'default','10.80.2.1')
        configs=[]
        for index in (1,2):
            cfg=base();other=3-index
            cfg['interfaces']=[{'name':'WAN','device':'eth1','address':f'198.18.0.{index}/24'},{'name':'LAN','device':'eth2','address':f'10.80.{index}.1/24'}]
            cfg['ipsec']=[{'id':1,'enabled':True,'public_device':'eth1','remote_ip':f'198.18.0.{other}','local_id':f'peer{index}','remote_id':f'peer{other}','local_network':f'10.80.{index}.0/24','remote_network':f'10.80.{other}.0/24','psk':'LabOnlyRandomSecret123456789'}]
            configs.append(cfg)
        pa=agent(a,work);pb=agent(b,work)
        ask(pa,'start',configs[0]);ask(pb,'start',configs[1]);record('Actual nftables accepts IPsec expressions and strongSwan loads IKEv2 configuration')
        wait_for(lambda:inside(ca,['ping','-n','-c','1','-W','1','10.80.2.2'],False).returncode==0)
        assert 'ESTABLISHED' in ask(pa,'sas');record('Real IKEv2 handshake and LAN-to-LAN encrypted packets')
        ask(pb,'stop')
        # The remote firewall now sends a plaintext packet with a remote selector source.
        assert inside(b,['ping','-n','-I','10.80.2.1','-c','1','-W','1','10.80.1.2'],False).returncode != 0
        record('Plaintext traffic spoofing remote selector is denied')
        ask(pa,'stop')
        assert inside(ca,['ping','-n','-c','1','-W','1','10.80.2.2'],False).returncode != 0
        record('Tunnel shutdown never falls back to plaintext forwarding')
        for process in [pa,pb]:
            process.stdin.close();process.wait(timeout=15)
        AGENTS.clear()
        for space in reversed(NAMES):
            command(['ip','netns','del',space])
        NAMES.clear()
        fw=ns('fw');p1=ns('p1');p2=ns('p2');client=ns('client')
        link(fw,'eth1','198.18.0.1/24',p1,'eth1','198.18.0.254/24')
        link(fw,'eth3','198.19.0.1/24',p2,'eth1','198.19.0.254/24')
        link(fw,'eth2','10.80.1.1/24',client,'eth1','10.80.1.2/24')
        for space in (p1,p2):
            command(['ip','-n',space,'addr','add','203.0.113.1/32','dev','lo'])
        route(client,'default','10.80.1.1')
        cfg=base();cfg['interfaces']=[{'name':'WAN','device':'eth1','address':'198.18.0.1/24'},{'name':'LAN','device':'eth2','address':'10.80.1.1/24'},{'name':'WAN2','device':'eth3','address':'198.19.0.1/24'}]
        cfg['wan']={'enabled':True,'links':[{'device':'eth1','gateway':'198.18.0.254','targets':['203.0.113.1']},{'device':'eth3','gateway':'198.19.0.254','targets':['203.0.113.1']}]}
        cfg['policies']=[{'id':'1','name':'LAN internet','srcintf':['LAN'],'dstintf':['WAN','WAN2'],'srcaddr':['all'],'dstaddr':['all'],'service':['ALL'],'action':'accept','nat':True,'log':False,'enabled':True}]
        controller=agent(fw,work);ask(controller,'start',cfg)
        wait_for(lambda:ask(controller,'health')['wan']['active']=='eth1')
        assert inside(client,['ping','-n','-c','1','-W','1','203.0.113.1'],False).returncode==0
        record('Primary WAN selected after three successful probes; LAN NAT passes real packets')
        command(['ip','-n',p1,'link','set','eth1','down'])
        wait_for(lambda:ask(controller,'health')['wan']['active']=='eth3')
        assert inside(client,['ping','-n','-c','1','-W','1','203.0.113.1'],False).returncode==0
        record('WAN failure moves new LAN traffic to backup')
        command(['ip','-n',p2,'link','set','eth1','down'])
        wait_for(lambda:ask(controller,'health')['wan']['active'] is None)
        assert inside(client,['ping','-n','-c','1','-W','1','203.0.113.1'],False).returncode!=0
        record('Both WANs unavailable install unreachable default')
        command(['ip','-n',p1,'link','set','eth1','up'])
        wait_for(lambda:ask(controller,'health')['wan']['active']=='eth1')
        record('Recovered preferred WAN is selected after hysteresis')
        ask(controller,'stop')
        assert not json.loads(command(['ip','-n',fw,'-j','route','show','default']).stdout)
        assert not any(r.get('priority') in (18081,18082) for r in json.loads(command(['ip','-n',fw,'-j','rule']).stdout))
        record('Stopping failover removes owned routes and policy rules')
finally:
    for process in AGENTS:
        try:
            ask(process,'stop');process.stdin.close();process.wait(timeout=15)
        except Exception:
            process.kill();process.wait()
    for space in reversed(NAMES):
        command(['ip','netns','del',space],False)
    (ROOT/'dist').mkdir(exist_ok=True)
    (ROOT/'dist/enterprise-runtime-qa.json').write_text(json.dumps({'checks':REPORT,'count':len(REPORT)},indent=2))
assert len(REPORT)==9
