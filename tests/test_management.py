"""AI protocol, switch write boundaries and credential regressions. SPDX-License-Identifier: MIT."""
import base64
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src/murus_igneus'))
import assistant
import server
import switches
from configuration import empty
from tasks import Task


def wait(task):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        value = task.status()
        if value and value['state'] != 'running':
            return value
        time.sleep(0.01)
    raise AssertionError('Background task did not finish')


class OllamaStub(BaseHTTPRequestHandler):
    calls = []
    answer = {'answer': 'La bozza è vuota.', 'configuration': None}
    def log_message(self, *args):
        pass
    def do_GET(self):
        self.send_response(200); self.end_headers()
        self.wfile.write(json.dumps({'models': [{'name': 'qwen3:4b'}]}).encode())
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.calls.append(body)
        self.send_response(200); self.end_headers()
        self.wfile.write(json.dumps({'message': {'content': json.dumps(self.answer) if 'campo configuration' in body['messages'][0]['content'] else self.answer['answer']}}).encode())


class AssistantTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.srv = ThreadingHTTPServer(('127.0.0.1', 0), OllamaStub)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        assistant.TASK = Task(); OllamaStub.calls = []
        OllamaStub.answer = {'answer': 'Analisi della bozza.', 'configuration': None}
        self.settings = {**assistant.DEFAULTS, 'enabled': True, 'endpoint': 'http://127.0.0.1:' + str(self.srv.server_port)}
        assistant.save(self.temp.name, self.settings)
    def tearDown(self):
        self.srv.shutdown(); self.srv.server_close(); self.temp.cleanup()
    def test_real_http_chat_and_no_execution(self):
        assistant.ask(self.temp.name, {'question': 'Analizza', 'configuration': empty()}, 'eth0')
        result = wait(assistant.TASK)
        self.assertEqual(result['state'], 'succeeded', result)
        self.assertFalse(result['result']['applied'])
        request = OllamaStub.calls[0]
        self.assertFalse(request['stream']); self.assertFalse(request['think'])
        self.assertEqual(request['model'], 'qwen3:4b')
        self.assertNotIn('tools', request)
    def test_valid_proposal_is_only_returned_as_draft(self):
        OllamaStub.answer = {'answer': 'Proposta', 'configuration': empty()}
        assistant.ask(self.temp.name, {'question': 'Proponi', 'allow_proposal': True, 'configuration': empty()}, 'eth0')
        result = wait(assistant.TASK)['result']
        self.assertEqual(result['proposal']['schema'], 1)
        self.assertFalse(result['applied'])
    def test_invalid_model_proposal_rejected(self):
        OllamaStub.answer = {'answer': 'Esegui', 'configuration': {'schema': 1, 'shell': 'reboot'}}
        assistant.ask(self.temp.name, {'question': 'Proponi', 'allow_proposal': True, 'configuration': empty()}, 'eth0')
        result = wait(assistant.TASK)['result']
        self.assertIsNone(result['proposal']); self.assertIn('proposal_errors', result)
    def test_management_interface_in_proposal_blocked(self):
        bad = empty(); bad['interfaces'] = [{'name': 'wan', 'device': 'eth0', 'address': ''}]
        OllamaStub.answer = {'answer': 'Proposta', 'configuration': bad}
        assistant.ask(self.temp.name, {'question': 'Proponi', 'allow_proposal': True, 'configuration': empty()}, 'eth0')
        self.assertIsNone(wait(assistant.TASK)['result']['proposal'])
    def test_secrets_not_in_context(self):
        assistant.ask(self.temp.name, {'question': 'Analizza', 'configuration': empty()}, 'eth0',
                      [{'name': 'sw', 'community': 'PRIVATE', 'nested': {'private_key': 'SECRET'}}])
        wait(assistant.TASK)
        prompt = OllamaStub.calls[0]['messages'][1]['content']
        self.assertNotIn('PRIVATE', prompt); self.assertNotIn('SECRET', prompt)
    def test_endpoint_restrictions(self):
        for endpoint in ['https://8.8.8.8', 'http://example.org:11434', 'http://169.254.169.254:11434',
                         'http://127.0.0.1:22', 'http://user:pass@127.0.0.1:11434',
                         'http://192.168.1.2:11434/api/chat', 'http://127.0.0.1:11434/?x=1']:
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                assistant.validate({**self.settings, 'endpoint': endpoint})
    def test_cloud_and_unreviewed_models_rejected(self):
        for model in ['qwen3:4b-cloud', 'proprietary:latest', 'qwen3:4b/../../']:
            with self.assertRaises(ValueError):
                assistant.validate({**self.settings, 'model': model})
    def test_disabled_ai_rejects_requests(self):
        assistant.save(self.temp.name, {**self.settings, 'enabled': False})
        with self.assertRaises(ValueError):
            assistant.ask(self.temp.name, {'question': 'Test', 'configuration': empty()}, 'eth0')
    def test_private_settings_permissions(self):
        self.assertEqual(os.stat(Path(self.temp.name) / 'assistant.json').st_mode & 0o777, 0o600)
    def test_only_final_answer_is_returned_after_reasoning_tag(self):
        OllamaStub.answer = {'answer': 'Internal scratch text</think>\nRisposta finale.', 'configuration': None}
        assistant.ask(self.temp.name, {'question': 'Analizza', 'configuration': empty()}, 'eth0')
        self.assertEqual(wait(assistant.TASK)['result']['answer'], 'Risposta finale.')
    def test_empty_reply_is_an_error(self):
        OllamaStub.answer = {'answer': '', 'configuration': None}
        assistant.ask(self.temp.name, {'question': 'Analizza', 'configuration': empty()}, 'eth0')
        self.assertEqual(wait(assistant.TASK)['state'], 'failed')
    def test_inactive_ips_rules_do_not_appear_as_active_protection(self):
        assistant.ask(self.temp.name, {'question': 'Analizza', 'configuration': empty()}, 'eth0')
        wait(assistant.TASK)
        context = OllamaStub.calls[0]['messages'][1]['content']
        self.assertIn('"ips_enabled": false', context)
        self.assertNotIn('Shellshock', context)


class SwitchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.state = self.temp.name
        switches.TASK = Task(); switches.CACHE.clear(); switches.PLANS.clear()
        self.row = {'name': 'Laboratorio', 'host': '192.168.10.2', 'version': '3', 'username': 'murus',
                    'auth_pass': 'AuthPassword', 'priv_pass': 'PrivPassword', 'write_enabled': True, 'protected_ports': [1]}
        self.saved = switches.save(self.state, self.row)
        self.ident = self.saved['id']; self.sets = []
    def tearDown(self):
        self.temp.cleanup()
    def fake_snmp(self, row, oid, value=None, walk=False):
        if value is not None:
            self.sets.append((oid, value)); self.admin = value
        if oid == switches.SYSTEM:
            return {switches.SYSTEM + '.1.0': 'Test switch', switches.SYSTEM + '.2.0': '.1.3.6.1.4.1.999', switches.SYSTEM + '.5.0': 'test'}
        if oid.startswith(switches.IFACE + '.7.'):
            return {oid: str(getattr(self, 'admin', 1))}
        if oid == switches.IFACE:
            result = {}
            for index in (1, 2):
                for col, val in [(1, index), (2, 'Port' + str(index)), (3, 6), (5, 1000000000), (7, getattr(self, 'admin', 1)), (8, 1)]:
                    result[f'{oid}.{col}.{index}'] = str(val)
            return result
        return {}
    def test_secret_redaction_and_preservation(self):
        public = switches.inventory(self.state)
        self.assertNotIn('AuthPassword', json.dumps(public)); self.assertNotIn('PrivPassword', json.dumps(public))
        updated = {**self.row, 'id': self.ident, 'auth_pass': '', 'priv_pass': '', 'name': 'Renamed'}
        switches.save(self.state, updated)
        self.assertEqual(switches.get(self.state, self.ident)['auth_pass'], 'AuthPassword')
        self.assertEqual(os.stat(Path(self.state) / 'switches.json').st_mode & 0o777, 0o600)
    def test_poll_if_mib_and_lldp(self):
        with patch.object(switches, 'snmp', self.fake_snmp):
            switches.poll(self.state, self.ident)
            result = wait(switches.TASK)
        self.assertEqual(result['state'], 'succeeded', result)
        ports = switches.inventory(self.state)['devices'][0]['telemetry']['ports']
        self.assertTrue(ports[0]['protected']); self.assertEqual(ports[1]['name'], 'Port2')
    def test_protected_port_cannot_even_preview(self):
        with self.assertRaises(ValueError):
            switches.preview(self.state, {'id': self.ident, 'port': 1, 'admin': 2})
        self.assertEqual(self.sets, [])
    def test_read_only_switch_cannot_write(self):
        switches.save(self.state, {**self.row, 'id': self.ident, 'write_enabled': False})
        with self.assertRaises(ValueError):
            switches.preview(self.state, {'id': self.ident, 'port': 2, 'admin': 2})
    def plan(self):
        switches.preview(self.state, {'id': self.ident, 'port': 2, 'admin': 2})
        result = wait(switches.TASK)
        self.assertEqual(result['state'], 'succeeded', result)
        return result['result']
    def test_set_requires_token_confirmation_and_verifies_state(self):
        with patch.object(switches, 'snmp', self.fake_snmp):
            plan = self.plan()
            self.assertEqual(self.sets, [])
            switches.apply(self.state, {'token': plan['token'], 'confirmation': plan['confirmation']})
            result = wait(switches.TASK)
            self.assertEqual(result['state'], 'succeeded', result)
            self.assertEqual(self.sets, [(switches.IFACE + '.7.2', 2)])
            with self.assertRaises(ValueError):
                switches.apply(self.state, {'token': plan['token'], 'confirmation': plan['confirmation']})
    def test_wrong_confirmation_never_sends_set(self):
        with patch.object(switches, 'snmp', self.fake_snmp):
            plan = self.plan()
            with self.assertRaises(ValueError):
                switches.apply(self.state, {'token': plan['token'], 'confirmation': 'yes'})
        self.assertEqual(self.sets, [])
    def test_changed_port_state_blocks_set(self):
        with patch.object(switches, 'snmp', self.fake_snmp):
            plan = self.plan(); self.admin = 2
            switches.apply(self.state, {'token': plan['token'], 'confirmation': plan['confirmation']})
            result = wait(switches.TASK)
            self.assertEqual(result['state'], 'failed')
        self.assertEqual(self.sets, [])
    def test_expired_plan_blocks_set(self):
        with patch.object(switches, 'snmp', self.fake_snmp):
            plan = self.plan(); switches.PLANS[plan['token']]['expires'] = 0
            with self.assertRaises(ValueError):
                switches.apply(self.state, {'token': plan['token'], 'confirmation': plan['confirmation']})
        self.assertEqual(self.sets, [])
    def test_credential_injection_and_public_addresses_rejected(self):
        for changes in [{'host': '8.8.8.8'}, {'host': '192.168.1.2;reboot'}, {'auth_pass': 'secret\ndefVersion 1'}, {'protected_ports': [True]}, {'version': '1'}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                switches.save(self.state, {**self.row, **changes})
    def test_numeric_oid_and_unsupported_values_parser(self):
        parsed = switches.parse('.1.2.3 = INTEGER: 1\n.1.2.4 = STRING: "Port 1"\n.1.2.5 = No Such Object available on this agent at this OID\n')
        self.assertEqual(parsed, {'.1.2.3': '1', '.1.2.4': 'Port 1'})
    def test_credentials_not_in_process_arguments_or_errors(self):
        def fake(args, stdout, stderr, timeout, env):
            cfg = Path(env['SNMPCONFPATH']) / 'snmp.conf'
            self.assertEqual(cfg.stat().st_mode & 0o777, 0o600)
            self.assertIn('defAuthPassphrase AuthPassword', cfg.read_text())
            self.assertNotIn('AuthPassword', ' '.join(args))
            stdout.write(b'.1.2.3 = INTEGER: 1\n')
            return type('Result', (), {'returncode': 0})()
        with patch.object(switches.shutil, 'which', return_value='/usr/bin/snmpget'), patch.object(switches.subprocess, 'run', fake):
            self.assertEqual(switches.snmp(switches.get(self.state, self.ident), '.1.2.3'), {'.1.2.3': '1'})


class APIManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.state = Path(self.temp.name)
        (self.state / 'admin.password').write_text('igneus')
        self.patch = patch.object(server, 'STATE', self.state); self.patch.start()
        self.srv = ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
    def tearDown(self):
        self.srv.shutdown(); self.srv.server_close(); self.patch.stop(); self.temp.cleanup()
    def request(self, path, data=None, token=None, auth=True):
        conn = http.client.HTTPConnection('127.0.0.1', self.srv.server_port, timeout=5)
        headers = {'Content-Type': 'application/json'}
        if auth: headers['Authorization'] = 'Basic ' + base64.b64encode(b'admin:igneus').decode()
        if token: headers[server.CSRF_HEADER] = token
        conn.request('POST' if data is not None else 'GET', path, json.dumps(data) if data is not None else None, headers)
        response = conn.getresponse(); content = response.read(); conn.close()
        return response.status, json.loads(content) if content and path.startswith('/api/') else content
    def test_new_endpoints_require_authentication_and_csrf(self):
        for path in ['/api/assistant', '/api/switches', '/management.js']:
            self.assertEqual(self.request(path, auth=False)[0], 401)
        for path in ['/api/assistant/settings', '/api/assistant/ask', '/api/switches/save', '/api/switches/port/apply']:
            self.assertEqual(self.request(path, {}, token='wrong')[0], 403)
    def test_settings_and_inventory_routed_through_real_http(self):
        status, data = self.request('/api/assistant')
        self.assertEqual(status, 200); self.assertFalse(data['settings']['enabled'])
        status, _ = self.request('/api/assistant/settings', assistant.DEFAULTS, server.CSRF)
        self.assertEqual(status, 200)
        self.assertEqual(self.request('/api/switches')[0], 200)
        self.assertEqual(self.request('/management.js')[0], 200)
    def test_invalid_requests_fail_without_connection_drop(self):
        self.assertEqual(self.request('/api/assistant/ask', [], server.CSRF)[0], 400)
        self.assertEqual(self.request('/api/switches/save', {'host': '8.8.8.8'}, server.CSRF)[0], 400)


if __name__ == '__main__':
    unittest.main()
