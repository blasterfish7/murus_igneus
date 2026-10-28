"""Kernel device discovery stays independent of the editable draft. SPDX-License-Identifier: MIT."""
import copy
import json
import unittest
from murus_igneus import networking


class InterfaceInventoryTests(unittest.TestCase):
    def inventory(self, rows):
        def run(args):
            self.assertEqual(args, ['ip', '-j', '-d', 'address', 'show'])
            return json.dumps(rows)
        return networking.interface_inventory('enp1s0', run)['interfaces']

    def test_empty_draft_still_exposes_management_and_disconnected_nics(self):
        rows = [{'ifname':'lo'}, {'ifname':'enp1s0','address':'02:00:00:00:00:01','flags':['UP','LOWER_UP'],'operstate':'UP','link_type':'ether','addr_info':[{'family':'inet','local':'192.0.2.10','prefixlen':24},{'family':'inet6','local':'fe80::1','prefixlen':64}]}, {'ifname':'enp2s0','address':'02:00:00:00:00:02','flags':[],'operstate':'DOWN','link_type':'ether'}]
        before = copy.deepcopy(rows)
        result = self.inventory(rows)
        self.assertEqual([r['device'] for r in result], ['enp1s0','enp2s0'])
        self.assertTrue(result[0]['management'])
        self.assertFalse(result[0]['configurable'])
        self.assertEqual(result[0]['addresses'], ['192.0.2.10/24','fe80::1/64'])
        self.assertTrue(result[1]['configurable'])
        self.assertFalse(result[1]['carrier'])
        self.assertFalse(result[1]['admin_up'])
        self.assertEqual(rows, before)

    def test_owned_tunnel_and_existing_vlans_are_not_physical_port_choices(self):
        rows = [{'ifname':'mivpn0','linkinfo':{'info_kind':'wireguard'}}, {'ifname':'eth2.20','linkinfo':{'info_kind':'vlan'}}, {'ifname':'eth2','link_type':'ether'}]
        result = {r['device']:r for r in self.inventory(rows)}
        self.assertFalse(result['mivpn0']['configurable'])
        self.assertFalse(result['eth2.20']['configurable'])
        self.assertTrue(result['eth2']['configurable'])

    def test_no_devices_and_invalid_address_entries(self):
        self.assertEqual(self.inventory([{'ifname':'lo'}]), [])
        result = self.inventory([{'ifname':'eth3','addr_info':[{'family':'inet','local':'bad','prefixlen':24},{'family':'inet6','local':'::1'},{'family':'packet'}]}])
        self.assertEqual(result[0]['addresses'], [])
