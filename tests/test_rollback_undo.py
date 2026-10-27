# SPDX-License-Identifier: MIT
"""Best-effort undo/conntrack/sysctl must not stop the previous ruleset from being restored."""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from murus_igneus import server  # noqa: E402


class RollbackBestEffortTests(unittest.TestCase):
    def rollback(self, failing):
        calls = []

        def run(args, data=None, check=True):
            calls.append((args[0], data))
            if check and args[:2] in failing:
                raise server.Error('simulated failure of ' + ' '.join(args[:2]))
            return ''
        server.PENDING = {'id': 'x', 'undo': [['ip', 'route', 'del', '10.9.0.0/24']], 'old': 'OLD',
                          'forward': '0', 'security': {}}
        with mock.patch.object(server, 'run', run), mock.patch.object(server, 'baseline', return_value='BASE'), \
             mock.patch.object(server, 'service_settings', return_value={}), \
             mock.patch.object(server.parental, 'stop'), mock.patch.object(server.enterprise, 'stop'), \
             mock.patch.object(server.networking, 'stop'), mock.patch.object(server.security, 'activate'), \
             mock.patch.object(server.networking, 'activate'), mock.patch.object(server.enterprise, 'activate'), \
             mock.patch.object(server.parental, 'stage'), mock.patch.object(server.parental, 'activate'):
            result = server.rollback('x')
        self.assertIsNone(server.PENDING)
        return result, [d for c, d in calls if c == 'nft']

    def test_failing_undo_command_still_restores_previous_rules(self):
        result, nft = self.rollback([['ip', 'route']])
        self.assertTrue(result['ok'], server.LAST)
        self.assertEqual(nft[-1], 'OLD')
        self.assertTrue(server.LAST.startswith('Modifica annullata'))

    def test_failing_conntrack_or_sysctl_does_not_downgrade_the_firewall(self):
        result, nft = self.rollback([['conntrack', '-F'], ['sysctl', '-w']])
        self.assertTrue(result['ok'], server.LAST)
        self.assertEqual(nft[-1], 'OLD')

    def test_failing_nft_restore_still_falls_back_to_baseline(self):
        calls = []

        def run(args, data=None, check=True):
            calls.append(data)
            if data == 'OLD':
                raise server.Error('nft restore failed')
            return ''
        server.PENDING = {'id': 'x', 'undo': [], 'old': 'OLD', 'forward': '0', 'security': {}}
        with mock.patch.object(server, 'run', run), mock.patch.object(server, 'baseline', return_value='BASE'), \
             mock.patch.object(server, 'service_settings', return_value={}), \
             mock.patch.object(server.parental, 'stop'), mock.patch.object(server.enterprise, 'stop'), \
             mock.patch.object(server.networking, 'stop'), mock.patch.object(server.security, 'activate'), \
             mock.patch.object(server.networking, 'activate'), mock.patch.object(server.enterprise, 'activate'), \
             mock.patch.object(server.parental, 'stage'), mock.patch.object(server.parental, 'activate'):
            result = server.rollback('x')
        self.assertFalse(result['ok'])
        self.assertIn('BASE', calls)



if __name__ == '__main__':
    unittest.main()
