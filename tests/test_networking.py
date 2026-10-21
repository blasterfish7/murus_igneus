"""Native network validation, rollback ordering and telemetry. SPDX-License-Identifier: MIT."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src/murus_igneus'))
import networking
import server
import traffic
from configuration import empty, compile_config, from_backup


def base():
    c = empty()
    c['interfaces'] = [{'name': 'WAN', 'device': 'eth1', 'address': '192.0.2.2/24'},
                       {'name': 'TRUNK', 'device': 'eth2', 'address': ''},
                       {'name': 'LAN', 'device': 'eth2.20', 'parent': 'eth2', 'vlan_id': 20, 'address': '198.51.100.1/24'}]
    c.update(networking.defaults())
    c['dns'] = {'enabled': True, 'interfaces': ['LAN'], 'upstream_servers': ['203.0.113.53'], 'domain': 'lab.lan'}
    c['dhcp'] = [{'interface': 'LAN', 'start': '198.51.100.10', 'end': '198.51.100.50', 'lease_hours': 12, 'dns_servers': [], 'enabled': True}]
    c['port_forwards'] = [{'id': '1', 'name': 'Web', 'interface': 'WAN', 'public_ip': '192.0.2.2', 'protocol': 'tcp', 'external_port': 8080,
                           'target_interface': 'LAN', 'target_ip': '198.51.100.10', 'target_port': 80, 'source': '192.0.2.0/24', 'enabled': True, 'log': True}]
    return c


class NativeNetworkTests(unittest.TestCase):
    def test_legacy_backup_conversion_remains_equivalent(self):
        backup = (Path(__file__).parent / 'example.conf').read_text()
        from migration import parse, translate
        interfaces = next(s for s in parse(backup).children if s.name == 'system interface').children
        mapping = {r.name: 'eth' + str(i + 1) for i, r in enumerate(interfaces)}
        original = translate(backup, mapping)
        converted = from_backup(backup, mapping)
        self.assertTrue(converted['ready'], converted['blockers'])
        self.assertEqual(converted['nftables'], original['nftables'])
        self.assertEqual(converted['network_ops'], original['network_ops'])

    def test_old_configuration_and_new_roundtrip(self):
        self.assertTrue(compile_config(empty())['ready'])
        plan = compile_config(base())
        self.assertTrue(plan['ready'], plan['blockers'])
        self.assertEqual(plan['network_ops'][0], {'kind': 'vlan', 'interface': 'eth2.20', 'parent': 'eth2', 'vlan_id': 20})
        self.assertEqual(compile_config(plan['configuration'])['nftables'], plan['nftables'])
        self.assertEqual(plan['configuration']['interfaces'][2]['parent'], 'eth2')

    def test_dnat_is_bound_to_original_tuple_and_target_port(self):
        s = compile_config(base())['nftables']
        self.assertIn('dnat ip to 198.51.100.10:80', s)
        self.assertIn('ct original ip daddr 192.0.2.2 ct original proto-dst 8080', s)
        self.assertIn('oifname "eth2.20" ct status dnat ip saddr 192.0.2.0/24 ip daddr 198.51.100.10 tcp dport 80', s)
        self.assertIn('log prefix "OW dnat 1 "', s)
        self.assertIn('policy drop;', s)

    def test_dnat_remains_subject_to_ips(self):
        c = base(); c['utm'] = {'ips': True}
        s = compile_config(c)['nftables']
        self.assertIn('hook forward priority 10', s)
        self.assertIn('queue num 0', s)
        self.assertNotIn('bypass', s)

    def test_udp_publication_cannot_steal_wireguard_listener(self):
        c = base(); c['vpn'] = {'enabled': True, 'public_device': 'eth1', 'port': 51820}
        c['port_forwards'][0].update(protocol='udp', external_port=51820)
        with self.assertRaisesRegex(ValueError, 'WireGuard'): compile_config(c)

    def test_dns_and_dhcp_only_open_selected_data_interface(self):
        s = compile_config(base())['nftables']
        self.assertIn('iifname "eth2.20" udp sport 68 udp dport 67 counter accept', s)
        self.assertIn('iifname "eth2.20" ip saddr 198.51.100.0/24 ip daddr 198.51.100.1 udp dport 53', s)
        self.assertNotIn('iifname "eth1" udp dport 53', s)

    def test_vlan_management_parent_chaining_tag_and_duplicates_rejected(self):
        for parent, tag in [('eth0', 20), ('missing', 20), ('eth2.20', 20), ('eth2', 0), ('eth2', 4095), ('eth2', True)]:
            c = base(); c['interfaces'][2].update(parent=parent, vlan_id=tag)
            with self.subTest(parent=parent, tag=tag), self.assertRaises(ValueError): compile_config(c)
        c = base(); c['interfaces'].append({'name': 'DUP', 'device': 'vlan20', 'parent': 'eth2', 'vlan_id': 20})
        with self.assertRaises(ValueError): compile_config(c)

    def test_pool_cannot_include_gateway_network_broadcast_or_reverse(self):
        for start, end in [('198.51.100.0', '198.51.100.10'), ('198.51.100.1', '198.51.100.50'), ('198.51.100.10', '198.51.100.255'), ('198.51.100.50', '198.51.100.10'), ('203.0.113.1', '203.0.113.10')]:
            c = base(); c['dhcp'][0].update(start=start, end=end)
            with self.subTest(start=start), self.assertRaises(ValueError): compile_config(c)

    def test_dns_injection_self_loop_and_missing_resolver_rejected(self):
        for change in [{'domain': 'lan\nconf-file=/etc/secret'}, {'upstream_servers': ['198.51.100.1']}, {'upstream_servers': []}, {'interfaces': ['VPN']}, {'enabled': 1}]:
            c = base(); c['dns'].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError): compile_config(c)

    def test_dhcp_dns_must_be_available(self):
        c = base(); c['dns']['enabled'] = False
        with self.assertRaises(ValueError): compile_config(c)
        c['dhcp'][0]['dns_servers'] = ['203.0.113.53']
        plan = compile_config(c)
        text = networking.dnsmasq_config(plan['network_services'], 'eth0')
        self.assertIn('port=0', text)
        self.assertIn('option:dns-server,203.0.113.53', text)
        self.assertNotIn('server=', text)

    def test_dnsmasq_no_host_configuration_or_management_binding(self):
        text = networking.dnsmasq_config(compile_config(base())['network_services'], 'eth0')
        self.assertIn('no-resolv\nno-hosts', text)
        self.assertIn('except-interface=eth0', text)
        self.assertIn('interface=eth2.20', text)
        self.assertNotIn('\ninterface=eth0', text)
        self.assertIn('dhcp-range=set:mi0,198.51.100.10,198.51.100.50,255.255.255.0,12h', text)
        self.assertEqual(networking.dnsmasq_config({'interfaces': [], **networking.defaults()}, 'eth0'), '')

    def test_dnat_invalid_public_target_protocol_port_and_duplicate_rejected(self):
        for change in [{'public_ip': '192.0.2.9'}, {'target_ip': '198.51.100.1'}, {'target_ip': '203.0.113.2'}, {'target_ip': '198.51.100.255'}, {'protocol': 'all'}, {'external_port': 0}, {'target_port': True}, {'target_interface': 'WAN'}, {'source': 'all'}]:
            c = base(); c['port_forwards'][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError): compile_config(c)
        c = base(); c['port_forwards'].append({**c['port_forwards'][0], 'id': '2'})
        with self.assertRaises(ValueError): compile_config(c)

    def test_disabled_dnat_retains_configuration_without_permission(self):
        c = base(); c['port_forwards'][0]['enabled'] = False
        plan = compile_config(c)
        self.assertNotIn('ct status dnat', plan['nftables'])
        self.assertEqual(len(plan['configuration']['port_forwards']), 1)


class NetworkRuntimeTests(unittest.TestCase):
    def test_foreign_vlan_collision_fails_before_mutation(self):
        ops = [{'kind': 'vlan', 'interface': 'eth2.20', 'parent': 'eth2', 'vlan_id': 20}]
        links = [{'ifname': 'eth2', 'ifindex': 3}, {'ifname': 'eth2.20', 'ifindex': 4, 'link_index': 3, 'linkinfo': {'info_kind': 'vlan', 'info_data': {'id': 20}}}]
        calls = []
        def run(args, *a, **kw):
            calls.append(args)
            if args == ['ip', '-j', '-d', 'link']: return json.dumps(links)
            if args == ['ip', '-j', '-4', 'addr', 'show', 'dev', 'eth0']: return '[]'
            raise AssertionError('Unexpected mutation: ' + str(args))
        with patch.object(server, 'run', run), self.assertRaisesRegex(ValueError, 'occupato'):
            server.network(ops, [])
        self.assertEqual(len(calls), 2)

    def test_vlan_overlapping_management_fails_before_creation(self):
        ops = [{'kind': 'vlan', 'interface': 'eth2.20', 'parent': 'eth2', 'vlan_id': 20}, {'kind': 'address', 'interface': 'eth2.20', 'address': '10.0.2.1/24'}]
        def run(args, *a, **kw):
            if args == ['ip', '-j', '-d', 'link']: return '[{"ifname":"eth2","ifindex":3}]'
            if args == ['ip', '-j', '-4', 'addr', 'show', 'dev', 'eth0']: return '[{"addr_info":[{"local":"10.0.2.15","prefixlen":24}]}]'
            raise AssertionError('Unexpected mutation: ' + str(args))
        with patch.object(server, 'run', run), self.assertRaisesRegex(ValueError, 'gestione'):
            server.network(ops, [])

    def test_changed_tag_removes_addresses_then_vlan_and_restores_in_reverse(self):
        vlan = {'kind': 'vlan', 'interface': 'eth2.20', 'parent': 'eth2', 'vlan_id': 20}
        address = {'kind': 'address', 'interface': 'eth2.20', 'address': '198.51.100.1/24'}
        old = [vlan, address]; new = [{**vlan, 'vlan_id': 30}, address]; calls = []; undo = []
        def run(args, *a, **kw):
            calls.append(args)
            if args[:5] == ['ip', '-j', '-4', 'addr', 'show']: return '[{"addr_info":[{"local":"198.51.100.1","prefixlen":24}]}]'
            if args[:5] == ['ip', '-j', '-d', 'link', 'show']: return json.dumps([{'ifalias': networking.VLAN_ALIAS, 'linkinfo': {'info_data': {'id': 20}}}])
            return ''
        with patch.object(server, 'run', run): server.remove_previous(old, new, undo)
        mutations = [args for args in calls if '-j' not in args]
        self.assertEqual(mutations[0][:3], ['ip', 'addr', 'del'])
        self.assertEqual(mutations[1], ['ip', 'link', 'del', 'dev', 'eth2.20'])
        self.assertEqual(list(reversed(undo))[0], server.vlan_add(vlan))
        self.assertEqual(list(reversed(undo))[-1][:3], ['ip', 'addr', 'add'])

    def test_rollback_stops_new_services_then_restores_old_services(self):
        pending = {'id': 'test', 'undo': [['ip', 'link', 'del', 'dev', 'vlan20']], 'security': server.security.defaults(), 'old': 'old-rules', 'forward': '0'}
        sequence = []
        with patch.object(server, 'PENDING', pending), patch.object(server, 'ACTIVE', None), patch.object(server, 'run', side_effect=lambda *a, **kw: sequence.append(('run', a[0]))), patch.object(server.networking, 'stop', side_effect=lambda: sequence.append(('stop',))), patch.object(server.networking, 'activate', side_effect=lambda *a: sequence.append(('services',))), patch.object(server.security, 'activate'):
            server.rollback('test')
        self.assertLess(sequence.index(('stop',)), sequence.index(('run', pending['undo'][0])))
        self.assertLess(sequence.index(('run', pending['undo'][0])), sequence.index(('services',)))
        self.assertEqual(sequence[-3], ('run', ['nft', '-f', '-']))


class TrafficTests(unittest.TestCase):
    def test_nat_tuples_not_confused(self):
        text = 'ipv4 2 tcp 6 430 ESTABLISHED src=192.0.2.10 dst=192.0.2.2 sport=55555 dport=8080 packets=2 bytes=120 src=198.51.100.10 dst=192.0.2.10 sport=80 dport=55555 packets=3 bytes=300 [ASSURED] mark=0 use=1'
        row = traffic.connections(text)[0]
        self.assertEqual(row['destination'], '192.0.2.2'); self.assertEqual(row['reply_source'], '198.51.100.10')
        self.assertEqual(row['bytes'], '120'); self.assertEqual(row['reply_bytes'], '300')
        self.assertEqual(row['dport'], '8080'); self.assertEqual(row['reply_sport'], '80')
        self.assertEqual(len(traffic.connections((text + '\n') * 1000)), 500)

    def test_policy_and_dnat_events_exclude_unrelated_kernel_output(self):
        text = 'kernel unrelated\nOW policy 2 IN=eth2.20 OUT=eth1 SRC=198.51.100.10 DST=192.0.2.5 PROTO=TCP SPT=44 DPT=443\nOW dnat 1 IN=eth1 OUT=eth2.20 SRC=192.0.2.5 DST=198.51.100.10 PROTO=TCP DPT=80'
        rows = traffic.events(text)
        self.assertEqual(len(rows), 2); self.assertEqual(rows[1]['kind'], 'dnat')
        self.assertEqual(rows[0]['DPT'], '443')

    def test_missing_tools_return_diagnostic_without_fake_empty_success(self):
        with patch.object(traffic, 'capture', side_effect=OSError('missing')):
            result = traffic.snapshot()
        self.assertEqual(len(result['errors']), 2)
        self.assertEqual(result['connections'], [])


if __name__ == '__main__': unittest.main()
