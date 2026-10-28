"""DHCP IPv4 plans and lease validation. SPDX-License-Identifier: MIT."""
import unittest
from murus_igneus import configuration, dhcp_client, migration


class DHCPClientTests(unittest.TestCase):
    def base(self):
        c = configuration.empty()
        c['interfaces'] = [{'name':'WAN','device':'eth1','address':'','address_mode':'dhcp','dhcp_metric':100}]
        return c

    def test_dhcp_plan_is_editable_and_opens_only_its_client_reply_port(self):
        p = configuration.compile_config(self.base())
        self.assertTrue(p['ready'],p['blockers'])
        self.assertEqual(p['configuration']['interfaces'][0]['address_mode'],'dhcp')
        self.assertFalse(any(op['kind']=='address' for op in p['network_ops']))
        self.assertIn('add rule inet murus_igneus input iifname "eth1" udp sport 67 udp dport 68 counter accept',p['nftables'])
        self.assertIn('Murus anti-lockout HTTPS',p['nftables'])

    def test_dhcp_rejects_static_address_and_management_device(self):
        for update in [{'address':'192.0.2.1/24'},{'device':'eth0'},{'address_mode':'unknown'},{'dhcp_metric':0}]:
            c = self.base();c['interfaces'][0].update(update)
            with self.assertRaises((migration.Error, ValueError)):
                configuration.compile_config(c)

    def test_static_default_route_alias_and_reserved_management_message(self):
        c = self.base();c['interfaces'][0].update(address_mode='static',address='192.0.2.2/24')
        c['routes'] = [{'id':'1','destination':'0.0.0.0','gateway':'192.0.2.1','interface':'WAN','distance':10,'priority':0,'enabled':True}]
        p = configuration.compile_config(c)
        self.assertTrue(p['ready'],p['blockers'])
        self.assertEqual(p['configuration']['routes'][0]['destination'],'0.0.0.0/0')
        c['routes'][0]['interface'] = 'eth0'
        with self.assertRaisesRegex(migration.Error,'riservata alla gestione'):
            configuration.compile_config(c)

    def test_dhcp_gateway_is_automatic_and_static_routes_need_static_wan(self):
        c = self.base();c['routes'] = [{'id':'1','destination':'0.0.0.0/0','gateway':'192.0.2.1','interface':'WAN'}]
        with self.assertRaisesRegex(migration.Error,'automaticamente'):
            configuration.compile_config(c)

    def test_valid_lease_and_untrusted_gateway_or_overlapping_subnet(self):
        values = {'ip':'192.0.2.20','subnet':'255.255.255.0','router':'192.0.2.1','lease':'3600','dns':'192.0.2.53'}
        self.assertEqual(dhcp_client.lease(values,['198.18.0.0/24']),('192.0.2.20/24','192.0.2.1',3600,['192.0.2.53']))
        for changes in [{'ip':'192.0.2.255'},{'router':'203.0.113.1'},{'router':'192.0.2.20'},{'subnet':'bad'},{'lease':'-1'}]:
            with self.assertRaises((migration.Error,ValueError)):
                dhcp_client.lease({**values,**changes},[])
        with self.assertRaisesRegex(migration.Error,'sovrappone'):
            dhcp_client.lease(values,['192.0.2.0/24'])
