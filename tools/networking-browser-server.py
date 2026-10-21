"""Loopback-only GUI fixture; system mutations are disabled. SPDX-License-Identifier: MIT."""
import json
from pathlib import Path
import sys
import tempfile
from http.server import ThreadingHTTPServer
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src/murus_igneus'))
import server


def read_only(args, *a, **kw):
    if args == ['ip', '-j', 'link']:
        return json.dumps([{'ifname': name} for name in ('lo', 'eth0', 'eth1', 'eth2')])
    raise ValueError('System command disabled in browser fixture')


def no_apply(*args, **kwargs):
    raise ValueError('Applying configuration is disabled in browser fixture')


with tempfile.TemporaryDirectory(prefix='murus-browser-fixture-') as state:
    server.STATE = Path(state); (server.STATE / 'admin.password').write_text('test-browser')
    server.run = read_only; server.apply = no_apply
    server.traffic.snapshot = lambda: {'time': 1, 'truncated': False, 'errors': [], 'connections': [],
                                       'events': [{'raw': 'OW dnat 1 IN=eth1 OUT=eth2.20 SRC=192.0.2.10 DST=198.51.100.10 PROTO=TCP DPT=80'}]}
    http = ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
    print('PORT:' + str(http.server_port), flush=True)
    http.serve_forever()
