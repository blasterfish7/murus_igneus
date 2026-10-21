import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'/'murus_igneus'))
from migration import translate,parse,Error
BASE=Path(__file__).with_name('example.conf').read_text()
M={'wan':'eth1','lan':'eth2'}
class MigrationTests(unittest.TestCase):
    def test_order_and_snat(self):
        r=translate(BASE,M);self.assertTrue(r['ready'],r['blockers']);self.assertLess(r['nftables'].index('comment "policy 10"'),r['nftables'].index('comment "policy 20"'));self.assertIn('ct mark 2 oifname { "eth1" } masquerade',r['nftables']);self.assertEqual(r['network_ops'][-1]['destination'],'0.0.0.0/0')
    def test_logging_separate_from_verdict(self):
        s=translate(BASE,M)['nftables'];self.assertNotIn('drop',next(x for x in s.splitlines() if 'OW policy 10' in x));self.assertNotIn('limit',next(x for x in s.splitlines() if 'comment "policy 10"' in x))
    def test_mapping_missing(self):self.assertFalse(translate(BASE,{})['ready'])
    def test_reserved_management(self):self.assertFalse(translate(BASE,dict(wan='eth0',lan='eth2'))['ready'])
    def test_reserved_loopback(self):self.assertFalse(translate(BASE,dict(wan='lo',lan='eth2'))['ready'])
    def test_duplicate_mapping(self):self.assertFalse(translate(BASE,dict(wan='eth1',lan='eth1'))['ready'])
    def test_injection(self):self.assertFalse(translate(BASE,dict(wan='eth1;reboot',lan='eth2'))['ready'])
    def test_utm(self):self.assertFalse(translate(BASE.replace('set nat enable','set nat enable\n set utm-status enable'),M)['ready'])
    def test_unknown_policy(self):self.assertFalse(translate(BASE.replace('set nat enable','set nat enable\n set internet-service enable'),M)['ready'])
    def test_vip(self):self.assertFalse(translate(BASE+'\nconfig firewall vip\nend',M)['ready'])
    def test_fqdn(self):self.assertFalse(translate(BASE.replace('set subnet 198.51.100.0 255.255.255.0','set type fqdn\n set fqdn example.com'),M)['ready'])
    def test_service_missing(self):self.assertFalse(translate(BASE.replace('"ALL"','"MISSING"'),M)['ready'])
    def test_address_missing(self):self.assertFalse(translate(BASE.replace('set srcaddr "LAN network"','set srcaddr "MISSING"'),M)['ready'])
    def test_disabled(self):self.assertEqual(translate(BASE.replace('set name "Block SSH"','set name "Block SSH"\n set status disable'),M)['counts']['policies'],1)
    def test_central_nat(self):self.assertFalse(translate('config system settings\nset central-nat enable\nend\n'+BASE,M)['ready'])
    def test_custom_service(self):
        extra='config firewall service custom\nedit APP\nset tcp-portrange 8080-8081\nnext\nend\n';r=translate(extra+BASE.replace('"ALL"','"APP"'),M);self.assertTrue(r['ready'],r['blockers']);self.assertIn('tcp dport { 8080-8081 }',r['nftables'])
    def test_cycle(self):
        extra='config firewall addrgrp\nedit cycle\nset member cycle\nnext\nend\n';self.assertFalse(translate(extra+BASE.replace('set srcaddr "LAN network"','set srcaddr cycle'),M)['ready'])
    def test_command_rejected(self):
        with self.assertRaises(Error):parse('execute reboot')
    def test_incomplete(self):
        with self.assertRaises(Error):parse('config system interface\nedit a')
    def test_boolean(self):self.assertFalse(translate(BASE.replace('set nat enable','set nat wrong'),M)['ready'])
    def test_empty(self):self.assertFalse(translate('',{})['ready'])
    def test_ipv6(self):self.assertFalse(translate(BASE+'\nconfig router static6\nend',M)['ready'])
    def test_overlap(self):self.assertFalse(translate(BASE.replace('set ip 198.51.100.1','set ip 192.0.2.5'),M)['ready'])
    def test_missing_schedule(self):self.assertFalse(translate(BASE.replace('set schedule "always"',''),M)['ready'])
if __name__=='__main__':unittest.main()
