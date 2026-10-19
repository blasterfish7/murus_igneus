import base64,copy,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src/murus_igneus'))
import security,installer
from configuration import compile_config
from migration import Error
BASE={'schema':1,'interfaces':[{'name':'WAN','device':'eth1','address':'192.0.2.2/24'},{'name':'LAN','device':'eth2','address':'198.51.100.1/24'}],'addresses':[],'groups':[],'services':[],'service_groups':[],'policies':[],'routes':[]}
class SecurityTests(unittest.TestCase):
 def test_vendor_suricata_empty_nfq_section(self):
  import yaml
  with patch.object(Path,'read_text',return_value='stream: {}\nnfq:\nvars: {}\n'),patch.object(Path,'mkdir'),patch.object(security,'write') as write:
   security.suricata_config(security.defaults()['utm'])
  rendered=write.call_args.args[1]
  self.assertTrue(rendered.startswith('%YAML 1.1\n---\n'))
  self.assertEqual(yaml.safe_load(rendered)['nfq']['mode'],'accept')
 def test_remote_peer_cannot_claim_management_subnet(self):
  import server
  c=security.defaults();c['vpn']['enabled']=True;c['vpn']['peers']=[{'allowed_ips':['192.168.56.7/32']}]
  addresses=[{'addr_info':[{'local':'192.168.56.1','prefixlen':24}]}]
  with patch.object(server,'run',return_value=json.dumps(addresses)):
   with self.assertRaises(Error):server.check_vpn_management(c)
 def test_disabled_features_allow_different_management_port(self):
  self.assertTrue(compile_config({'schema':1},management='eth1')['ready'])
 def test_peer_cannot_claim_server_address(self):
  c=security.defaults();c['vpn']['peers']=[{'public_key':base64.b64encode(bytes(range(32))).decode(),'allowed_ips':['10.77.0.0/24']}]
  with self.assertRaises(Error):security.validate(c,'eth0')
 def test_peer_cannot_replace_connected_lan_route(self):
  c=copy.deepcopy(BASE);c.update(security.defaults());c['vpn']['enabled']=True;c['vpn']['peers']=[{'public_key':base64.b64encode(bytes(range(32))).decode(),'allowed_ips':['198.51.100.0/24']}]
  with self.assertRaises(Error):compile_config(c)
 def test_wireguard_compiles_into_firewall(self):
  c=copy.deepcopy(BASE);c.update(security.defaults());c['vpn']['enabled']=True
  c['policies']=[{'id':'1','name':'vpn-lan','srcintf':['VPN'],'dstintf':['LAN'],'srcaddr':['all'],'dstaddr':['all'],'service':['ALL'],'action':'accept','nat':False,'log':True,'enabled':True}]
  r=compile_config(c);self.assertTrue(r['ready'],r['blockers']);self.assertIn('"mivpn0"',r['nftables']);self.assertIn('udp dport 51820 accept',r['nftables']);self.assertEqual(len(r['configuration']['interfaces']),2)
 def test_vpn_default_route_rejected(self):
  c=security.defaults();c['vpn']['peers']=[{'public_key':base64.b64encode(bytes(range(32))).decode(),'allowed_ips':['0.0.0.0/0']}]
  with self.assertRaises(Error):security.validate(c,'eth0')
 def test_peer_overlap_rejected(self):
  c=security.defaults();c['vpn']['peers']=[{'public_key':base64.b64encode(bytes([n])*32).decode(),'allowed_ips':['10.90.0.0/24']} for n in (1,2)]
  with self.assertRaises(Error):security.validate(c,'eth0')
 def test_ips_runs_after_firewall_without_bypass(self):
  c=copy.deepcopy(BASE);c.update(security.defaults());c['utm']['ips']=True;r=compile_config(c);s=r['nftables'];self.assertIn('hook forward priority 10',s);self.assertIn('queue num 0',s);self.assertNotIn('bypass',s)
 def test_vpn_overlaps_lan_rejected(self):
  c=copy.deepcopy(BASE);c.update(security.defaults());c['vpn'].update(enabled=True,address='198.51.100.8/24')
  with self.assertRaises(Error):compile_config(c)
 def test_proxy_has_input_acl_and_direct_http_block(self):
  c=copy.deepcopy(BASE);c.update(security.defaults());c['utm'].update(proxy=True,clients=['198.51.100.0/24']);s=compile_config(c)['nftables'];self.assertIn('ip saddr { 198.51.100.0/24 } tcp dport 3128 accept',s);self.assertIn('tcp dport 80 drop',s)
 def test_installer_rejects_missing_confirmation(self):
  with patch.object(installer,'PREVIEW',{'id':'ok','expires':9999999999,'disk':{'path':'/dev/vda'}}):
   with self.assertRaises(Error):installer.start({'id':'ok','confirmation':'yes'})
 def test_installer_rejects_changed_disk(self):
  disk={'path':'/dev/vda','identity':'old'}
  with patch.object(installer,'PREVIEW',{'id':'ok','expires':9999999999,'disk':disk}),patch.object(installer,'inventory',return_value={'disks':[{'path':'/dev/vda','identity':'new'}]}):
   with self.assertRaises(Error):installer.start({'id':'ok','confirmation':'CANCELLA /dev/vda'})
 def test_installer_not_available_on_installed_system(self):
  with patch.object(installer,'live',return_value=False):self.assertFalse(installer.inventory()['live'])

