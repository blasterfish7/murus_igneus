"""Provider, TOTP, persistent audit and signed package trust-boundary regressions."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src/murus_igneus'))
import assistant
import authentication
import configuration
import enterprise
import eventlog
import updates
from tasks import Task


def draft():
    result = configuration.empty()
    result['interfaces'] = [{'name':'WAN','device':'eth1','address':'198.18.0.1/24'},
                            {'name':'LAN','device':'eth2','address':'10.80.1.1/24'},
                            {'name':'WAN2','device':'eth3','address':'198.19.0.1/24'}]
    result['ipsec'] = [{'id':1,'enabled':True,'public_device':'eth1','remote_ip':'198.18.0.2',
                        'local_id':'left','remote_id':'right','local_network':'10.80.1.0/24',
                        'remote_network':'10.80.2.0/24','psk':'TestOnlySharedSecret123456'}]
    return result


class NewFeatures(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.state = Path(self.temp.name)
        authentication.SESSIONS.clear(); authentication.ATTEMPTS.clear(); authentication.PENDING.clear()
        assistant.TASK = Task()
    def tearDown(self):
        self.temp.cleanup()
    def test_old_ollama_settings_upgrade(self):
        settings = assistant.validate({'enabled':False,'model':'qwen3:4b','endpoint':'http://127.0.0.1:11434'})
        self.assertEqual(settings['provider'], 'ollama')
    def test_openai_requires_consent_and_never_exposes_key(self):
        settings = {**assistant.DEFAULTS, 'enabled':True, 'provider':'openai', 'model':'project-model'}
        with self.assertRaises(ValueError):
            assistant.validate(settings)
        settings['cloud_consent'] = True
        assistant.save(self.state, {**settings, 'api_key':'sk-test-' + 'a' * 30})
        self.assertNotIn('sk-test', json.dumps(assistant.load(self.state)))
        self.assertEqual((self.state/'openai.key').stat().st_mode & 0o777, 0o600)
        self.assertEqual(assistant.load(self.state)['endpoint'], 'https://api.openai.com/v1')
        assistant.save(self.state, {**settings, 'delete_key':True})
        self.assertFalse((self.state/'openai.key').exists())
    def test_openai_payload_and_response_on_complete_draft(self):
        settings = {**assistant.DEFAULTS, 'enabled':True, 'provider':'openai', 'cloud_consent':True,'model':'project-model'}
        assistant.save(self.state, settings)
        seen = []
        def request(settings, state, path, payload=None):
            seen.append((path, copy.deepcopy(payload)))
            proposal = copy.deepcopy(payload)
            self.assertNotIn('TestOnlySharedSecret', json.dumps(proposal))
            return {'status':'completed','output':[{'type':'message','content':[{'type':'output_text','text':'Analisi completata'}]}]}
        with patch.object(assistant, 'openai_request', request):
            assistant.ask(self.state, {'question':'Controlla token=secret123','configuration':draft()}, 'eth0')
            deadline = time.monotonic() + 5
            while assistant.TASK.status()['state'] == 'running' and time.monotonic() < deadline:
                time.sleep(.01)
        result = assistant.TASK.status()
        self.assertEqual(result['state'], 'succeeded', result)
        self.assertFalse(seen[0][1]['store']); self.assertEqual(seen[0][1]['tools'], [])
        self.assertNotIn('secret123', seen[0][1]['input'])
        self.assertEqual(result['result']['facts']['ipsec_grants'], 1)
        self.assertFalse(result['result']['applied'])
    def test_openai_refuses_partial_generation(self):
        with patch.object(assistant, 'openai_request', return_value={'status':'incomplete','output':[]}):
            with self.assertRaises(ValueError):
                assistant.generate_openai({**assistant.DEFAULTS},self.state, [{'content':'system'},{'content':'input'}],True)
    def test_totp_rfc6238_vector_and_replay(self):
        secret = base64.b32encode(b'12345678901234567890').decode()
        self.assertEqual(authentication.code(secret, 1), '287082')
        self.assertEqual(authentication.verify(secret, '287082', now=59), 1)
        with self.assertRaises(ValueError):
            authentication.verify(secret, '287082', last=1, now=59)
    def test_enrollment_session_and_rate_limit(self):
        setup = authentication.enroll(self.state)
        token = authentication.confirm(self.state, authentication.code(setup['secret'],int(time.time()//30)), '127.0.0.1')
        self.assertTrue(authentication.valid_session(token,'127.0.0.1'))
        self.assertFalse(authentication.valid_session(token,'127.0.0.2'))
        self.assertEqual((self.state/'mfa.json').stat().st_mode & 0o777,0o600)
        with self.assertRaises(ValueError):
            authentication.authenticate(self.state, authentication.code(setup['secret'],int(time.time()//30)), '127.0.0.1')
        for _ in range(5):
            authentication.limit('other')
        with self.assertRaises(ValueError):
            authentication.limit('other')
    def test_event_history_persists_and_deduplicates(self):
        eventlog.append(self.state, 'packet', {'raw':'packet'}, 'unique')
        eventlog.append(self.state, 'packet', {'raw':'packet'}, 'unique')
        eventlog.append(self.state, 'audit', {'path':'/api/apply','status':200})
        history = eventlog.history(self.state)['events']
        self.assertEqual(len(history),2);self.assertEqual(history[0]['kind'],'audit')
        self.assertEqual((self.state/'logs/events.sqlite').stat().st_mode & 0o777,0o600)
    def test_oversized_audit_detail_remains_valid_json(self):
        eventlog.append(self.state, 'audit', {'path':'x'*10000})
        self.assertTrue(eventlog.history(self.state)['events'][0]['detail']['truncated'])
    def test_ipsec_rules_are_bound_to_interfaces_and_xfrm(self):
        plan = configuration.compile_config(draft())
        self.assertTrue(plan['ready'])
        script = plan['nftables']
        self.assertIn('iifname "eth1" oifname "eth2" ip saddr 10.80.2.0/24 ip daddr 10.80.1.0/24 ipsec in reqid 19001 accept',script)
        self.assertIn('ipsec out reqid 19001 accept',script)
        self.assertIn('insert rule inet murus_igneus forward jump ipsec_guard',script)
        self.assertIn('insert rule inet murus_igneus postrouting ip saddr 10.80.1.0/24 ip daddr 10.80.2.0/24 return',script)
        content = enterprise.swan_config(plan['enterprise'], plan['configuration']['interfaces'])
        self.assertIn('start_action = trap',content);self.assertIn('version = 2',content)
    def test_ipsec_rejects_injection_overlap_and_default_selector(self):
        for field, value in [('psk','x\ninclude /tmp/file'),('remote_id','a\n}'),('remote_network','0.0.0.0/0'),('remote_network','10.80.1.0/24')]:
            current = draft();current['ipsec'][0][field] = value
            with self.assertRaises(ValueError):
                configuration.compile_config(current)
    def test_wan_requires_two_declared_static_uplinks_and_no_default(self):
        current = draft();current['wan'] = {'enabled':True,'links':[{'device':'eth1','gateway':'198.18.0.254','targets':['1.1.1.1']}, {'device':'eth3','gateway':'198.19.0.254','targets':['9.9.9.9']}]}
        self.assertTrue(configuration.compile_config(current)['ready'])
        current['routes'] = [{'id':'1','destination':'0.0.0.0/0','gateway':'198.18.0.254','interface':'WAN','enabled':True}]
        with self.assertRaises(ValueError):
            configuration.compile_config(current)
    def test_absent_routing_table_does_not_return_partial_json(self):
        result = subprocess.CompletedProcess(['ip'],2,stdout='[\n',stderr='FIB table does not exist')
        with patch.object(enterprise.subprocess,'run',return_value=result):
            self.assertEqual(enterprise.run(['ip','route'],check=False),'')
    def test_stopping_unused_wan_does_not_change_host_routes(self):
        with patch.object(enterprise,'run') as run:
            enterprise.wan_stop()
        run.assert_not_called()


class SignedUpdates(unittest.TestCase):
    def test_real_ed25519_signature_and_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); package_root = root/'package'; (package_root/'DEBIAN').mkdir(parents=True)
            (package_root/'DEBIAN/control').write_text('Package: murus-igneus\nVersion: 0.3.0~alpha.8\nArchitecture: all\nMaintainer: Test <test@example.invalid>\nDescription: fixture\n')
            subprocess.run(['dpkg-deb','--build',str(package_root),str(root/'murus-igneus.deb')],check=True,capture_output=True)
            private = root/'private.pem';public = root/'public.pem'
            subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(private)],check=True,capture_output=True)
            subprocess.run(['openssl','pkey','-in',str(private),'-pubout','-out',str(public)],check=True,capture_output=True)
            manifest = {'schema':1,'package':'murus-igneus','version':'0.3.0~alpha.8','sha256':hashlib.sha256((root/'murus-igneus.deb').read_bytes()).hexdigest()}
            (root/'manifest.json').write_text(json.dumps(manifest))
            subprocess.run(['openssl','pkeyutl','-sign','-inkey',str(private),'-rawin','-in',str(root/'manifest.json'),'-out',str(root/'manifest.sig')],check=True,capture_output=True)
            self.assertEqual(updates.verify(root,public), manifest)
            with (root/'murus-igneus.deb').open('ab') as stream:
                stream.write(b'tampered')
            with self.assertRaises(ValueError):
                updates.verify(root,public)
            (root/'manifest.json').write_text(json.dumps({**manifest,'version':'0.3.0~alpha.999'}))
            with self.assertRaises(subprocess.CalledProcessError):
                updates.verify(root,public)


if __name__ == '__main__':
    unittest.main()
