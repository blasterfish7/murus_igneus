"""Bounded concurrent Basic authentication and exceptional rollback recovery. SPDX-License-Identifier: MIT."""
import base64
import json
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from murus_igneus import server


class PasswordRegressionTests(unittest.TestCase):
    def setUp(self):
        server.FAILED.clear()

    def tearDown(self):
        server.FAILED.clear()

    def test_continuous_low_rate_attempts_do_not_keep_expired_history(self):
        clock = [0.0]
        with patch.object(server.time, 'monotonic', lambda: clock[0]):
            for i in range(300):
                clock[0] = i * 10.0
                self.assertTrue(server.password_attempt('peer', False))
            self.assertLessEqual(len(server.FAILED['peer']), 6)
            self.assertFalse(server.password_blocked('peer'))

    def test_table_capacity_rejects_untracked_peers_and_reclaims_expired_entries(self):
        with patch.object(server.time, 'monotonic', return_value=100.0):
            for i in range(server.PASSWORD_PEERS):
                self.assertTrue(server.password_attempt(str(i), False))
            self.assertFalse(server.password_attempt('new', False))
            self.assertEqual(len(server.FAILED), server.PASSWORD_PEERS)
            self.assertTrue(server.password_attempt('0', True))
            self.assertTrue(server.password_attempt('new', False))
        with patch.object(server.time, 'monotonic', return_value=161.0):
            self.assertTrue(server.password_attempt('after-expiry', False))
            self.assertEqual(set(server.FAILED), {'after-expiry'})

    def test_parallel_admission_and_recording_is_atomic(self):
        barrier = threading.Barrier(32)
        def attempt(_):
            barrier.wait(timeout=5)
            return server.password_attempt('shared-peer', False)
        with ThreadPoolExecutor(max_workers=32) as pool:
            admitted = list(pool.map(attempt, range(32)))
        self.assertEqual(sum(admitted), 10)
        self.assertEqual(len(server.FAILED['shared-peer']), 10)

    def test_http_challenge_wrong_credentials_lockout_and_expiry(self):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            state = Path(folder); (state / 'admin.password').write_text('test-only-password')
            stack.enter_context(patch.object(server, 'STATE', state))
            stack.enter_context(patch.object(server.authentication, 'read', return_value=None))
            clock = [100.0]; stack.enter_context(patch.object(server.time, 'monotonic', lambda: clock[0]))
            http = ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
            thread = threading.Thread(target=http.serve_forever, daemon=True); thread.start()
            def request(value=None):
                conn = HTTPConnection('127.0.0.1', http.server_port, timeout=3)
                headers = {} if value is None else {'Authorization': value}
                conn.request('GET', '/api/auth/status', headers=headers)
                response = conn.getresponse(); result = (response.status, response.getheader('Retry-After')); response.read(); conn.close()
                return result
            wrong = 'Basic ' + base64.b64encode(b'admin:incorrect').decode()
            correct = 'Basic ' + base64.b64encode(b'admin:test-only-password').decode()
            try:
                for _ in range(12):
                    self.assertEqual(request()[0], 401)
                self.assertEqual(server.FAILED, {})
                for _ in range(10):
                    self.assertEqual(request(wrong)[0], 401)
                self.assertEqual(request(correct), (429, '60'))
                self.assertEqual(request()[0], 401)
                clock[0] = 161.0
                self.assertEqual(request(correct)[0], 200)
                self.assertEqual(server.FAILED, {})
                self.assertEqual(request('Basic !!!')[0], 401)
                self.assertEqual(len(server.FAILED['127.0.0.1']), 1)
                with patch.object(server,'PENDING',{'id':'http-test'}), patch.object(server,'rollback',return_value={'ok':False,'error':'controlled recovery failure'}):
                    conn=HTTPConnection('127.0.0.1',http.server_port,timeout=3)
                    conn.request('POST','/api/rollback',body='{}',headers={'Authorization':correct,'Content-Type':'application/json','X-Murus-Igneus-CSRF':server.CSRF})
                    reply=conn.getresponse();body=json.loads(reply.read());conn.close()
                    self.assertEqual(reply.status,200);self.assertFalse(body['ok']);self.assertEqual(body['error'],'controlled recovery failure')
            finally:
                http.shutdown(); http.server_close(); thread.join(timeout=3)


class RecoveryRegressionTests(unittest.TestCase):
    def scenario(self, failure=None):
        stack = ExitStack(); self.addCleanup(stack.close)
        calls = []
        for field, value in [('PENDING', {'id':'pending', 'undo':[['ip','undo']], 'old':'OLD', 'forward':'0', 'security':{}}), ('ACTIVE', None), ('LAST', '')]:
            stack.enter_context(patch.object(server, field, value))
        def action(label):
            def run(*args, **kwargs):
                calls.append(label)
                if label == failure:
                    raise RuntimeError('controlled ' + label)
                return ''
            return run
        def run(args, data=None, **kwargs):
            label = 'old-rules' if args[0] == 'nft' and data == 'OLD' else 'baseline' if args[0] == 'nft' else args[0]
            return action(label)()
        stack.enter_context(patch.object(server, 'run', run))
        stack.enter_context(patch.object(server, 'baseline', return_value='BASE'))
        for module, name, label in [(server.parental,'stop','stop-parental'), (server.enterprise,'stop','stop-enterprise'),
                                    (server.networking,'stop','stop-network'), (server.security,'activate','security'),
                                    (server.networking,'activate','network'), (server.enterprise,'activate','enterprise'),
                                    (server.parental,'stage','stage'), (server.parental,'activate','parental')]:
            stack.enter_context(patch.object(module, name, side_effect=action(label)))
        return calls

    def test_each_failed_phase_releases_pending_and_attempts_management_baseline(self):
        for phase in ['baseline','stop-parental','stop-enterprise','stop-network','ip','security','network','enterprise','stage','old-rules','parental','conntrack','sysctl']:
            with self.subTest(phase=phase):
                calls = self.scenario(phase)
                result=server.rollback('pending')
                self.assertFalse(result['ok'])
                self.assertIsNone(server.PENDING)
                self.assertIn('Ripristino servizi fallito', server.LAST)
                self.assertIn('controlled ' + phase, server.LAST)
                self.assertEqual(calls[-1], 'baseline')
                if phase == 'baseline':
                    self.assertNotIn('ip', calls)
                    self.assertNotIn('stop-parental', calls)
                elif phase not in ('old-rules','parental','conntrack','sysctl'):
                    self.assertNotIn('old-rules', calls)

    def test_failed_baseline_generation_does_not_keep_pending(self):
        self.scenario()
        with patch.object(server, 'baseline', side_effect=RuntimeError('baseline generator failed')):
            server.rollback('pending')
        self.assertIsNone(server.PENDING)
        self.assertIn('baseline generator failed', server.LAST)
        self.assertIn('Fallback', server.LAST)

    def test_multiple_failures_still_report_the_final_fallback_failure(self):
        self.scenario()
        for module, name in [(server.parental,'stop'),(server.enterprise,'stop'),(server.networking,'stop'),
                             (server.security,'activate'),(server.networking,'activate'),(server.enterprise,'activate'),(server.parental,'stage')]:
            getattr(module,name).side_effect=RuntimeError('service failure')
        count=[0]
        def run(args,data=None,**kwargs):
            if args[0]=='nft':
                count[0]+=1
                if count[0]>1:raise RuntimeError('FINAL FALLBACK FAILED')
            else:raise RuntimeError('command failure')
        with patch.object(server,'run',run):server.rollback('pending')
        self.assertIsNone(server.PENDING)
        self.assertIn('FINAL FALLBACK FAILED',server.LAST)
        self.assertIn('ulteriori errori',server.LAST)

    def test_success_restores_in_order_and_stale_timer_cannot_clear_new_transaction(self):
        calls = self.scenario()
        server.rollback('stale')
        self.assertIsNotNone(server.PENDING); self.assertEqual(calls, [])
        server.rollback('pending')
        self.assertIsNone(server.PENDING); self.assertNotIn('fallito', server.LAST)
        self.assertLess(calls.index('network'), calls.index('old-rules'))
        self.assertLess(calls.index('old-rules'), calls.index('parental'))
        self.assertEqual(calls[-1], 'sysctl')
