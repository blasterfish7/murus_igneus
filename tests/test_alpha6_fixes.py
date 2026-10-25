import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from murus_igneus import server  # noqa: E402


class PasswordThrottleTests(unittest.TestCase):
    def setUp(self):
        server.FAILED.clear()

    def test_blocks_after_ten_failures_and_success_resets(self):
        for _ in range(9):
            server.password_failed('10.0.0.5', False)
        self.assertFalse(server.password_blocked('10.0.0.5'))
        server.password_failed('10.0.0.5', False)
        self.assertTrue(server.password_blocked('10.0.0.5'))
        self.assertFalse(server.password_blocked('10.0.0.6'))
        server.password_failed('10.0.0.5', True)
        self.assertFalse(server.password_blocked('10.0.0.5'))

    def test_expires_after_a_minute(self):
        with mock.patch('murus_igneus.server.time.monotonic', return_value=100.0):
            for _ in range(10):
                server.password_failed('10.0.0.7', False)
            self.assertTrue(server.password_blocked('10.0.0.7'))
        with mock.patch('murus_igneus.server.time.monotonic', return_value=161.0):
            self.assertFalse(server.password_blocked('10.0.0.7'))


class RollbackTests(unittest.TestCase):
    def test_failed_nft_restore_still_clears_pending(self):
        calls = []

        def run(args, data=None, check=True):
            calls.append(args[0])
            if args[0] == 'nft' and data == 'OLD':
                raise server.Error('nft restore failed')
            return ''
        server.PENDING = {'id': 'x', 'undo': [], 'old': 'OLD', 'forward': '0', 'security': {}}
        with mock.patch.object(server, 'run', run), mock.patch.object(server, 'baseline', return_value='BASE'), \
             mock.patch.object(server, 'service_settings', return_value={}), \
             mock.patch.object(server.parental, 'stop'), mock.patch.object(server.enterprise, 'stop'), \
             mock.patch.object(server.networking, 'stop'), mock.patch.object(server.security, 'activate'), \
             mock.patch.object(server.networking, 'activate'), mock.patch.object(server.enterprise, 'activate'), \
             mock.patch.object(server.parental, 'stage'), mock.patch.object(server.parental, 'activate'):
            server.rollback('x')
        self.assertIsNone(server.PENDING)
        self.assertIn('Ripristino servizi fallito', server.LAST)


if __name__ == '__main__':
    unittest.main()
