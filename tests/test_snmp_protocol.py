"""Real Net-SNMP agent/clients on loopback; no switch or host interface writes."""
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src/murus_igneus'))
import switches


@unittest.skipUnless(all(shutil.which(p) for p in ('snmpd', 'snmpget', 'snmpbulkwalk')), 'needs Net-SNMP agent and clients')
class RealSNMPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name); (root / 'persist').mkdir()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1', 0)); cls.port = sock.getsockname()[1]
        config = root / 'agent.conf'
        config.write_text(f'agentaddress udp:127.0.0.1:{cls.port}\nrocommunity MurusRead 127.0.0.1\n'
                          'createUser murus SHA AuthPassword AES PrivPassword\nrouser murus priv\nsysName murus-lab-agent\n')
        config.chmod(0o600)
        cls.log = (root / 'agent.log').open('w')
        cls.agent = subprocess.Popen([shutil.which('snmpd'), '-f', '-Lo', '-C', '-c', str(config), '-p', str(root / 'pid')],
                                     env={**os.environ, 'SNMP_PERSISTENT_DIR': str(root / 'persist'), 'MIBS': ''},
                                     stdout=cls.log, stderr=subprocess.STDOUT)
        cls.row = {'host': '127.0.0.1', 'port': cls.port, 'version': '2c', 'community': 'MurusRead',
                   'username': 'murus', 'auth_pass': 'AuthPassword', 'priv_pass': 'PrivPassword', 'protected_ports': []}
        for _ in range(20):
            try:
                switches.snmp(cls.row, switches.SYSTEM + '.5.0'); return
            except ValueError:
                time.sleep(0.1)
        cls.tearDownClass()
        raise RuntimeError('Lab SNMP agent failed to start')

    @classmethod
    def tearDownClass(cls):
        cls.agent.terminate()
        try:
            cls.agent.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.agent.kill(); cls.agent.wait()
        cls.log.close(); cls.temp.cleanup()

    def test_v2c_reads_system_and_real_if_mib(self):
        t = switches.telemetry(self.row)
        self.assertEqual(t['name'], 'murus-lab-agent'); self.assertTrue(t['ports'])
        self.assertIsInstance(t['ports'][0]['admin'], int)

    def test_v3_authpriv_sha_aes_reads_system(self):
        row = {**self.row, 'version': '3'}
        self.assertEqual(switches.snmp(row, switches.SYSTEM + '.5.0')[switches.SYSTEM + '.5.0'], 'murus-lab-agent')

    def test_wrong_v3_credentials_are_refused(self):
        row = {**self.row, 'version': '3', 'auth_pass': 'WrongPassword'}
        with self.assertRaises(ValueError):
            switches.snmp(row, switches.SYSTEM + '.5.0')


if __name__ == '__main__':
    unittest.main()
