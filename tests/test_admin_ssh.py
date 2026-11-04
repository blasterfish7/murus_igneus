"""Reject unsafe SSH drafts and ensure the input filter defaults closed. MIT."""
import base64
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src/murus_igneus'))
from configuration import compile_config, empty


class AdminSSHTests(unittest.TestCase):
    key = 'ssh-ed25519 ' + base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20' + b'Q'*32).decode()

    def test_management_rule_is_explicit_and_optional(self):
        off = compile_config(empty(), 'ens18')['nftables']
        self.assertLess(off.index('tcp dport 22 drop'), off.index('ct state established,related'))
        self.assertNotIn('Murus SSH management', off)
        conf = {**empty(),'admin_ssh':{'enabled':True,'sources':['192.168.56.10'],'keys':[self.key+' workstation']}}
        plan = compile_config(conf,'ens18')
        self.assertTrue(plan['ready'])
        self.assertIn('iifname "ens18" ip saddr { 192.168.56.10/32 } tcp dport 22',plan['nftables'])
        self.assertEqual(plan['configuration']['admin_ssh']['keys'],[self.key])

    def test_reject_broad_empty_or_injected_ssh_settings(self):
        good = {'enabled':True,'sources':['192.168.56.10'],'keys':[self.key]}
        for fields in ({'sources':['0.0.0.0/0']},{'sources':['::/64']},{'sources':[]},
                       {'keys':[]},{'keys':['command="id" '+self.key]},
                       {'keys':[self.key+'\n'+self.key]},{'keys':['ssh-ed25519 aaaa']}):
            with self.subTest(fields=fields),self.assertRaises(ValueError):
                compile_config({**empty(),'admin_ssh':{**good,**fields}})
