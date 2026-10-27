"""Failed network undo is harmless only with verified postconditions. SPDX-License-Identifier: MIT."""
from contextlib import ExitStack
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from murus_igneus import server


class RollbackUndoTests(unittest.TestCase):
    def recover(self,undo,rows,fail='undo',query_ok=True):
        calls=[]
        def process(args,**kwargs):
            data=kwargs.get('input');calls.append((args,data))
            read=args[:2]==['ip','-j']
            failed=(read and not query_ok) or (args==undo and fail=='undo') or args[0]==fail or (fail=='nft-old' and data=='OLD')
            return subprocess.CompletedProcess(args,int(failed),json.dumps(rows) if read else '', 'controlled nonzero exit' if failed else '')
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(server,'PENDING',{'id':'x','undo':[undo] if undo else [],'old':'OLD','forward':'0','security':{}}))
            stack.enter_context(mock.patch.object(server,'ACTIVE',None));stack.enter_context(mock.patch.object(server,'LAST',''))
            stack.enter_context(mock.patch.object(server,'baseline',return_value='BASE'))
            stack.enter_context(mock.patch.object(server,'service_settings',return_value={}))
            stack.enter_context(mock.patch.object(server.subprocess,'run',side_effect=process))
            for module,name in [(server.parental,'stop'),(server.enterprise,'stop'),(server.networking,'stop'),(server.security,'activate'),(server.networking,'activate'),(server.enterprise,'activate'),(server.parental,'stage'),(server.parental,'activate')]:
                stack.enter_context(mock.patch.object(module,name))
            result=server.rollback('x');self.assertIsNone(server.PENDING)
            return result,[data for args,data in calls if args[0]=='nft']

    def test_already_absent_route_is_verified_and_old_rules_are_restored(self):
        result,rules=self.recover(['ip','route','del','10.9.0.0/24'],[])
        self.assertTrue(result['ok']);self.assertEqual(rules[-1],'OLD')

    def test_route_that_still_exists_prevents_false_success(self):
        result,rules=self.recover(['ip','route','del','10.9.0.0/24'],[{'dst':'10.9.0.0/24'}])
        self.assertFalse(result['ok']);self.assertEqual(rules[-1],'BASE')

    def test_existing_restore_must_match_gateway_device_and_metric(self):
        cmd=['ip','route','add','10.9.0.0/24','via','192.0.2.1','dev','wan0','metric','10']
        row={'dst':'10.9.0.0/24','gateway':'192.0.2.1','dev':'wan0','metric':10}
        self.assertTrue(self.recover(cmd,[row])[0]['ok'])
        for key,value in [('gateway','192.0.2.2'),('dev','other'),('metric',20)]:
            with self.subTest(key=key):self.assertFalse(self.recover(cmd,[{**row,key:value}])[0]['ok'])
        self.assertFalse(self.recover(cmd,[])[0]['ok'])

    def test_failed_or_malformed_readback_is_not_proof_of_success(self):
        cmd=['ip','route','del','10.9.0.0/24']
        self.assertFalse(self.recover(cmd,[],query_ok=False)[0]['ok'])
        self.assertFalse(self.recover(cmd,{})[0]['ok'])

    def test_absent_address_delete_is_safe_but_missing_restore_is_an_error(self):
        self.assertTrue(self.recover(['ip','addr','del','10.60.0.1/24','dev','lan0'],[])[0]['ok'])
        self.assertFalse(self.recover(['ip','addr','add','10.60.0.1/24','dev','lan0'],[])[0]['ok'])

    def test_address_restore_requires_exact_interface_and_prefix(self):
        cmd=['ip','addr','add','10.60.0.1/24','dev','lan0']
        row={'ifname':'lan0','addr_info':[{'local':'10.60.0.1','prefixlen':24}]}
        self.assertTrue(self.recover(cmd,[row])[0]['ok'])
        self.assertFalse(self.recover(cmd,[{**row,'ifname':'other'}])[0]['ok'])
        self.assertFalse(self.recover(cmd,[{**row,'addr_info':[{'local':'10.60.0.1','prefixlen':25}]}])[0]['ok'])

    def test_absent_link_delete_and_already_down_are_safe(self):
        self.assertTrue(self.recover(['ip','link','del','dev','lan0.20'],[])[0]['ok'])
        self.assertTrue(self.recover(['ip','link','set','dev','lan0','down'],[{'ifname':'lan0','flags':[]}])[0]['ok'])
        self.assertFalse(self.recover(['ip','link','set','dev','lan0','up'],[])[0]['ok'])
        self.assertFalse(self.recover(['ip','link','set','dev','lan0','down'],[{'ifname':'lan0'}])[0]['ok'])

    def test_alias_must_match(self):
        cmd=['ip','link','set','dev','lan0.20','alias','murus-vlan']
        self.assertTrue(self.recover(cmd,[{'ifname':'lan0.20','ifalias':'murus-vlan'}])[0]['ok'])
        self.assertFalse(self.recover(cmd,[{'ifname':'lan0.20','ifalias':'other'}])[0]['ok'])

    def test_existing_vlan_requires_matching_tag_and_parent(self):
        cmd=['ip','link','add','link','lan0','name','lan0.20','type','vlan','id','20']
        parent={'ifname':'lan0','ifindex':3};row={'ifname':'lan0.20','link_index':3,'linkinfo':{'info_kind':'vlan','info_data':{'id':20}}}
        self.assertTrue(self.recover(cmd,[parent,row])[0]['ok'])
        self.assertFalse(self.recover(cmd,[parent,{**row,'link_index':9}])[0]['ok'])
        self.assertFalse(self.recover(cmd,[parent,{**row,'linkinfo':{'info_kind':'vlan','info_data':{'id':30}}}])[0]['ok'])
        self.assertFalse(self.recover(cmd,[{'ifname':'lan0'},{**row,'link_index':None}])[0]['ok'])

    def test_conntrack_failure_is_reported_and_keeps_baseline(self):
        result,rules=self.recover(None,[],fail='conntrack')
        self.assertFalse(result['ok']);self.assertEqual(rules[-1],'BASE')

    def test_forwarding_failure_is_reported_and_keeps_baseline(self):
        result,rules=self.recover(None,[],fail='sysctl')
        self.assertFalse(result['ok']);self.assertEqual(rules[-1],'BASE')

    def test_failed_nft_restore_is_still_an_error(self):
        result,rules=self.recover(None,[],fail='nft-old')
        self.assertFalse(result['ok']);self.assertEqual(rules[-1],'BASE')
