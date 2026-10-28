"""Loopback-only GUI fixture; system mutations are disabled. SPDX-License-Identifier: MIT."""
import json
from pathlib import Path
import sys
import tempfile
import time
from http.server import ThreadingHTTPServer
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src/murus_igneus'))
import server


def read_only(args, *a, **kw):
    if args == ['ip', '-j', '-d', 'address', 'show']:
        return json.dumps([{'ifname':'lo','link_type':'loopback'},
                           {'ifname':'eth0','address':'02:00:00:00:00:10','link_type':'ether','flags':['UP','LOWER_UP'],'operstate':'UP','addr_info':[{'family':'inet','local':'192.0.2.10','prefixlen':24}]},
                           {'ifname':'eth1','address':'02:00:00:00:00:11','link_type':'ether','flags':['UP','LOWER_UP'],'operstate':'UP','addr_info':[]},
                           {'ifname':'eth2','address':'02:00:00:00:00:12','link_type':'ether','flags':[],'operstate':'DOWN','addr_info':[]}])
    if args == ['ip', '-j', 'link']:
        return json.dumps([{'ifname': name} for name in ('lo', 'eth0', 'eth1', 'eth2')])
    raise ValueError('System command disabled in browser fixture')


def no_apply(*args, **kwargs):
    raise ValueError('Applying configuration is disabled in browser fixture')


with tempfile.TemporaryDirectory(prefix='murus-browser-fixture-') as state:
    server.STATE = Path(state); (server.STATE / 'admin.password').write_text('test-browser')
    if '--first-login' in sys.argv:
        shadow = server.STATE / 'test-shadow'
        shadow.write_text('root:'+server.authentication.password_hash('igneus','$6$fixture$')+':0:0:99999:7:::\n')
        server.authentication.write(server.STATE/'credentials.json',{'system_root':True})
        original_check = server.authentication.check_password
        original_status = server.authentication.password_status
        original_change = server.authentication.change_password
        def fixture_check(state, value, unused=None):
            return original_check(state, value, shadow)
        def fixture_status(state):
            return original_status(state, shadow)
        def fake_chpasswd(args, **kwargs):
            assert args == ['chpasswd','-e']
            shadow.write_text(kwargs['input'].strip()+':20000:0:99999:7:::\n')
        def fixture_change(state, value, confirmation):
            return original_change(state, value, confirmation, shadow, fake_chpasswd)
        server.authentication.check_password = fixture_check
        server.authentication.password_status = fixture_status
        server.authentication.change_password = fixture_change
    server.run = read_only; server.apply = no_apply
    server.traffic.snapshot = lambda: {'time': 1, 'truncated': False, 'errors': [], 'connections': [],
                                       'events': [{'raw': 'OW dnat 1 IN=eth1 OUT=eth2.20 SRC=192.0.2.10 DST=198.51.100.10 PROTO=TCP DPT=80'}]}
    server.parental.reporting.write(server.STATE, [(int(time.time())//3600*3600, {'entity':'fixture-device','profile':1,'name':'Dispositivi figli','client':'198.51.100.10/32'}, '', (1024,2048,8,3,0,0)), (int(time.time())//3600*3600, {'entity':'fixture-device','profile':1,'name':'Dispositivi figli','client':'198.51.100.10/32'}, 'instagram.com', (0,0,0,0,4,2))], time.time())
    http = ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
    print('PORT:' + str(http.server_port), flush=True)
    http.serve_forever()
