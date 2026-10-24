"""Parental validation, schedules, resolver/proxy boundaries and pause persistence."""
import copy
from datetime import datetime, timezone
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src/murus_igneus'))
import parental
import networking
from configuration import empty, compile_config


def profile():
    return {'id':1,'name':'Figli','enabled':True,'interface':'LAN','clients':['10.60.0.10'],
            'categories':[],'services':['instagram'],'blocked_domains':['blocked.test'],'allowed_domains':[],
            'windows':[],'paused':False,'enforce_dns':True,'block_quic':False}


def configuration():
    c=empty();c['interfaces']=[{'name':'LAN','device':'lan0','address':'10.60.0.1/24'},{'name':'WAN','device':'wan0','address':'192.0.2.1/24'}]
    c.update(parental.defaults());c['parental']['enabled']=True;c['parental']['upstream_servers']=['192.0.2.2'];c['parental']['profiles']=[profile()]
    return c


class ParentalTests(unittest.TestCase):
    def test_compile_places_guard_before_established_and_ipsec_hooks(self):
        plan=compile_config(configuration());self.assertTrue(plan['ready'])
        self.assertIn('hook forward priority -20',plan['nftables']);self.assertIn('hook input priority -20',plan['nftables']);self.assertIn('hook output priority -20',plan['nftables'])
        self.assertIn('redirect to :12001',plan['nftables']);self.assertIn('53, 853, 784, 8853',plan['nftables'])
        self.assertIn('pc_schedule oifname "lan0" ip daddr { 10.60.0.10/32 } counter drop',plan['nftables'])
    def test_disabled_parental_does_not_add_hooks(self):
        c=configuration();c['parental']['enabled']=False
        self.assertNotIn('pc_schedule',compile_config(c)['nftables'])
    def test_unknown_fields_invalid_devices_and_overlap_rejected(self):
        for change in [lambda p:p.update({'unexpected':True}),lambda p:p.update({'interface':'nope'}),lambda p:p.update({'clients':['192.168.1.5']}),lambda p:p.update({'enforce_dns':'yes'})]:
            c=configuration();change(c['parental']['profiles'][0])
            with self.assertRaises(ValueError):compile_config(c)
        c=configuration();c['parental']['profiles'].append({**profile(),'id':2})
        with self.assertRaises(ValueError):compile_config(c)
    def test_domain_idna_wildcard_and_injection(self):
        self.assertEqual(parental.domain('*.ExAmple.COM.'),'example.com')
        self.assertEqual(parental.domain('città.it'),'xn--citt-3na.it')
        for value in ['https://example.com','example.com/abc','example.com\nserver=1.1.1.1','1.1.1.1','com']:
            with self.assertRaises(ValueError):parental.domain(value)
    def test_feed_validation_rejects_partial_config_and_preserves_tlds(self):
        self.assertEqual(parental.parse_feed(b'# source\n*.example.com\nexample.com\nzip\n'),['example.com','zip'])
        for raw in [b'',b'<html>error</html>',b'server=1.2.3.4',b'example.com\naddress=/#/1.2.3.4']:
            with self.assertRaises(ValueError):parental.parse_feed(raw)
    def test_specific_allow_overrides_parent_and_known_encrypted_dns_cannot_be_allowed(self):
        c=configuration();p=c['parental']['profiles'][0];p['blocked_domains']=['example.com'];p['allowed_domains']=['school.example.com']
        text=parental.dns_config(p,c['parental'],c['interfaces'][0],{},'eth0')
        self.assertIn('local=/example.com/',text);self.assertIn('server=/school.example.com/192.0.2.2',text);self.assertNotIn('log-queries',text)
        p['allowed_domains']=['dns.google']
        with self.assertRaises(ValueError):parental.dns_config(p,c['parental'],c['interfaces'][0],{},'eth0')
    def test_regular_weekday_and_boundary(self):
        p=profile();p['windows']=[{'days':[0],'start':'16:00','end':'20:00'}]
        self.assertTrue(parental.in_window(p,'Europe/Rome',datetime(2026,10,26,15,0,tzinfo=timezone.utc)))
        self.assertFalse(parental.in_window(p,'Europe/Rome',datetime(2026,10,26,19,0,tzinfo=timezone.utc)))
        self.assertFalse(parental.in_window(p,'Europe/Rome',datetime(2026,10,27,15,0,tzinfo=timezone.utc)))
    def test_midnight_and_sunday_wrap(self):
        p=profile();p['windows']=[{'days':[6],'start':'22:00','end':'07:00'}]
        self.assertTrue(parental.in_window(p,'Europe/Rome',datetime(2026,10,26,5,59,tzinfo=timezone.utc)))
        self.assertFalse(parental.in_window(p,'Europe/Rome',datetime(2026,10,26,6,0,tzinfo=timezone.utc)))
    def test_daylight_saving_uses_local_clock(self):
        p=profile();p['windows']=[{'days':[6],'start':'02:00','end':'03:00'}]
        self.assertTrue(parental.in_window(p,'Europe/Rome',datetime(2026,10,25,0,30,tzinfo=timezone.utc)))
        self.assertTrue(parental.in_window(p,'Europe/Rome',datetime(2026,10,25,1,30,tzinfo=timezone.utc)))
    def test_schedule_blocks_both_directions_and_dead_resolver(self):
        plan=compile_config(configuration());s=plan['parental']['settings'];p=s['profiles'][0]
        script,rows=parental.schedule_rules(s,plan['configuration']['interfaces'],{parental.fingerprint(p):float('inf')},ready={1:True})
        self.assertEqual(rows[0]['reason'],'pausa');self.assertIn('ip saddr',script);self.assertIn('ip daddr',script)
        _,rows=parental.schedule_rules(s,plan['configuration']['interfaces'],{},ready={1:False});self.assertEqual(rows[0]['reason'],'resolver fermo')
    def test_pauses_do_not_follow_reused_id_with_new_clients(self):
        p=profile();other={**p,'clients':['10.60.0.20']}
        self.assertNotEqual(parental.fingerprint(p),parental.fingerprint(other))
    def test_proxy_obeys_domain_allow_pause_and_literal_ip(self):
        c=configuration();s=c['parental'];plan={'settings':s,'interfaces':c['interfaces']}
        parental.dns_config(s['profiles'][0],s,c['interfaces'][0],{},'eth0')
        with patch.object(parental,'GUARD',plan),patch.object(parental,'CURRENT',plan),patch.object(parental,'RUNTIME',{'running':True,'error':'','profiles':[{'id':1,'blocked':False}]}):
            self.assertFalse(parental.proxy_allowed('10.60.0.10','instagram.com'))
            self.assertFalse(parental.proxy_allowed('10.60.0.10','192.0.2.2'))
            self.assertTrue(parental.proxy_allowed('10.60.0.10','school.test'))
            self.assertTrue(parental.proxy_allowed('10.60.0.11','instagram.com'))
            parental.RUNTIME['profiles'][0]['blocked']=True
            self.assertFalse(parental.proxy_allowed('10.60.0.10','school.test'))
    def test_resolver_missing_category_refuses_activation(self):
        c=configuration();c['parental']['profiles'][0]['categories']=['adult']
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):parental.load_domains(c['parental'],directory)
    def test_temporary_pause_is_persisted_private_and_resumes_only_override(self):
        plan=compile_config(configuration())['parental']
        with tempfile.TemporaryDirectory() as directory,patch.object(parental,'STATE',Path(directory)),patch.object(parental,'CURRENT',plan),patch.object(parental,'tick'):
            parental.pause(1,30);data=parental.pauses(directory);self.assertIn(parental.fingerprint(plan['settings']['profiles'][0]),data)
            self.assertEqual((Path(directory)/'parental-pauses.json').stat().st_mode&0o777,0o600)
            parental.pause(1,0);self.assertEqual(parental.pauses(directory),{})
    def test_dhcp_reservation_compiles_and_invalid_identity_rejected(self):
        c=configuration();c['dhcp']=[{'interface':'LAN','start':'10.60.0.100','end':'10.60.0.110','lease_hours':12,'dns_servers':['192.0.2.2'],'enabled':True}]
        c['dhcp_reservations']=[{'interface':'LAN','mac':'02:00:00:00:00:01','address':'10.60.0.105','name':'child-device','enabled':True}]
        plan=compile_config(c);text=networking.dnsmasq_config(plan['network_services'],'eth0');self.assertIn('dhcp-host=02:00:00:00:00:01,10.60.0.105,child-device',text)
        for value in ['ff:ff:ff:ff:ff:ff','00:00:00:00:00:00','broken']:
            bad=copy.deepcopy(c);bad['dhcp_reservations'][0]['mac']=value
            with self.assertRaises(ValueError):compile_config(bad)
    def test_failed_upstream_download_leaves_existing_list(self):
        with tempfile.TemporaryDirectory() as directory:
            target=parental.feed_path('adult',directory);target.parent.mkdir();target.write_text('original')
            class Response:
                status=200
                def read(self,n):return b'<html>invalid</html>'
            class Connection:
                def __init__(self,*args,**kwargs):pass
                def request(self,*args,**kwargs):pass
                def getresponse(self):return Response()
                def close(self):pass
            parental.TASK=parental.Task()
            with patch.object(parental.http.client,'HTTPSConnection',Connection):
                parental.update_feed(directory,'adult')
                import time
                deadline=time.monotonic()+3
                while parental.TASK.status()['state']=='running' and time.monotonic()<deadline:time.sleep(.01)
            self.assertEqual(parental.TASK.status()['state'],'failed');self.assertEqual(target.read_text(),'original')
    def test_invalid_or_unknown_timezone_rejected(self):
        c=configuration();c['parental']['timezone']='invalid/unknown'
        with self.assertRaises(ValueError):compile_config(c)


if __name__=='__main__':unittest.main()
