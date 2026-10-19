# SPDX-License-Identifier: MIT
"""Regression tests for the issues found in the 0.3.0-alpha code review."""
import base64
import http.client
import json
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / 'src' / 'murus_igneus'
sys.path.insert(0, str(SRC))
import server  # noqa: E402
from configuration import compile_config  # noqa: E402
from migration import translate  # noqa: E402

BASE = Path(__file__).with_name('example.conf').read_text()
MAP = {'wan': 'eth1', 'lan': 'eth2'}
JSON = {'Content-Type': 'application/json'}


@unittest.skipUnless(shutil.which('openssl'), 'openssl is required to create a test certificate')
class ServerTests(unittest.TestCase):
    """Runs the real TLS server (same make_server() as production) on localhost."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        state = Path(cls.tmp.name)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1',
                        '-subj', '/CN=test', '-keyout', str(state / 'k.pem'), '-out', str(state / 'c.pem')],
                       check=True, capture_output=True)
        (state / 'admin.password').write_text('igneus')
        cls.saved = (server.STATE, server.run)
        server.STATE = state
        server.run = lambda *a, **k: '[]'  # no ip/nft on the test host
        cls.srv = server.make_server('127.0.0.1', 0, state / 'c.pem', state / 'k.pem')
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.ctx = ssl._create_unverified_context()
        cls.auth = {'Authorization': 'Basic ' + base64.b64encode(b'admin:igneus').decode()}

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        server.STATE, server.run = cls.saved
        cls.tmp.cleanup()

    def request(self, method, path, body=None, headers=None, timeout=5):
        conn = http.client.HTTPSConnection('127.0.0.1', self.port, context=self.ctx, timeout=timeout)
        try:
            conn.request(method, path, body=body, headers={**self.auth, **(headers or {})})
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    def csrf(self):
        return json.loads(self.request('GET', '/api/status')[1])['csrf']

    def test_csrf_header_is_a_valid_http_token(self):
        # A space in the name made every browser fetch() throw and the server answer 403.
        self.assertRegex(server.CSRF_HEADER, r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
        self.assertIn("'" + server.CSRF_HEADER + "'", (SRC / 'app.js').read_text())

    def test_post_requires_and_accepts_csrf_token(self):
        self.assertEqual(self.request('POST', '/api/rollback', '{}', JSON)[0], 403)
        status, _ = self.request('POST', '/api/rollback', '{}', {**JSON, server.CSRF_HEADER: self.csrf()})
        self.assertEqual(status, 200)

    def test_non_ascii_csrf_header_is_rejected_cleanly(self):
        conn = http.client.HTTPSConnection('127.0.0.1', self.port, context=self.ctx, timeout=5)
        conn.putrequest('POST', '/api/rollback')
        for k, v in {**self.auth, **JSON, 'Content-Length': '2'}.items():
            conn.putheader(k, v)
        conn.putheader(server.CSRF_HEADER, 'café'.encode('latin-1'))
        conn.endheaders(b'{}')
        self.assertEqual(conn.getresponse().status, 403)
        conn.close()

    def test_json_body_that_is_not_an_object_returns_400(self):
        status, _ = self.request('POST', '/api/preview', '[]', {**JSON, server.CSRF_HEADER: self.csrf()})
        self.assertEqual(status, 400)

    def test_idle_tcp_connection_does_not_block_the_server(self):
        idle = socket.create_connection(('127.0.0.1', self.port))
        try:
            time.sleep(0.3)
            self.assertEqual(self.request('GET', '/api/status', timeout=5)[0], 200)
        finally:
            idle.close()

    def test_missing_password_file_does_not_drop_the_connection(self):
        pw = server.STATE / 'admin.password'
        content = pw.read_text()
        pw.unlink()
        try:
            self.assertEqual(self.request('GET', '/api/status')[0], 503)
        finally:
            pw.write_text(content)


def nested_groups(kind, depth):
    """g0 = {leaf}, g_i = {g_(i-1), g_(i-1)}: expands to 2**depth entries without memoization."""
    if kind == 'address':
        text = 'config firewall addrgrp\nedit g0\nset member "LAN network"\nnext\n'
    else:
        text = 'config firewall service custom\nedit APP\nset tcp-portrange 8080\nnext\nend\nconfig firewall service group\nedit g0\nset member APP\nnext\n'
    for i in range(1, depth + 1):
        text += f'edit g{i}\nset member g{i-1} g{i-1}\nnext\n'
    return text + 'end\n'


class NestedGroupTests(unittest.TestCase):
    DEPTH = 40  # 2**40 expansions before the fix: effectively never finishes

    def test_nested_address_groups_are_linear(self):
        text = BASE.replace('set srcaddr "LAN network"', f'set srcaddr g{self.DEPTH}')
        text = text.replace('config firewall policy', nested_groups('address', self.DEPTH) + 'config firewall policy')
        start = time.time()
        plan = translate(text, MAP)
        self.assertLess(time.time() - start, 5)
        self.assertTrue(plan['ready'], plan['blockers'])
        self.assertIn('ip saddr { 198.51.100.0/24 }', plan['nftables'])

    def test_nested_service_groups_are_linear(self):
        text = BASE.replace('"ALL"', f'"g{self.DEPTH}"').replace('config firewall policy', nested_groups('service', self.DEPTH) + 'config firewall policy')
        start = time.time()
        plan = translate(text, MAP)
        self.assertLess(time.time() - start, 5)
        self.assertTrue(plan['ready'], plan['blockers'])
        # Only policy 20 uses the group; the 2**depth duplicates collapse into a single rule.
        self.assertEqual(plan['nftables'].count('tcp dport { 8080 }'), 1)

    def test_native_config_with_nested_groups_compiles_quickly(self):
        groups = [{'name': 'g0', 'members': ['a0']}]
        groups += [{'name': f'g{i}', 'members': [f'g{i-1}', f'g{i-1}']} for i in range(1, self.DEPTH + 1)]
        config = {
            'schema': 1,
            'interfaces': [{'name': 'wan', 'device': 'eth1', 'address': '192.0.2.2/24'},
                           {'name': 'lan', 'device': 'eth2', 'address': '198.51.100.1/24'}],
            'addresses': [{'name': 'a0', 'subnet': '198.51.100.0/24'}],
            'groups': groups, 'services': [], 'service_groups': [],
            'policies': [{'id': '10', 'name': 'out', 'srcintf': ['lan'], 'dstintf': ['wan'],
                          'srcaddr': [f'g{self.DEPTH}'], 'dstaddr': ['all'], 'service': ['ALL'],
                          'action': 'accept', 'nat': False, 'log': False, 'enabled': True}],
            'routes': [],
        }
        start = time.time()
        plan = compile_config(config)
        self.assertLess(time.time() - start, 5)
        self.assertTrue(plan['ready'], plan['blockers'])

    def test_cycles_are_still_detected(self):
        text = 'config firewall addrgrp\nedit a\nset member b\nnext\nedit b\nset member a\nnext\nend\n'
        text += BASE.replace('set srcaddr "LAN network"', 'set srcaddr a')
        self.assertFalse(translate(text, MAP)['ready'])


if __name__ == '__main__':
    unittest.main()
