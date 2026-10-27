"""Family policy boundaries, transition failures and transactional list refresh. SPDX-License-Identifier: MIT."""
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from test_parental import configuration
import parental
from configuration import compile_config


class FamilyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        self.c = configuration(); self.plan = compile_config(self.c)['parental']
        self.s = self.plan['settings']; self.p = self.s['profiles'][0]
        self.when = datetime(2026, 10, 26, 16, 0, tzinfo=timezone.utc)

    def test_old_backups_gain_disabled_optional_features(self):
        self.assertFalse(self.s['auto_update']); self.assertFalse(self.p['safe_search'])
        self.assertEqual(self.p['devices'], []); self.assertEqual(self.p['night_windows'], [])
        self.assertFalse(self.p['block_ipv6'])

    def test_names_are_only_labels_for_explicit_single_addresses(self):
        p = self.c['parental']['profiles'][0]; p['devices'] = [{'name': 'Tablet', 'address': '10.60.0.10'}]
        self.assertEqual(compile_config(self.c)['parental']['settings']['profiles'][0]['devices'][0]['name'], 'Tablet')
        for devices in [[{'name':'Other','address':'10.60.0.11'}], [{'name':'Bad\nname','address':'10.60.0.10'}], p['devices'] * 2]:
            p['devices'] = devices
            with self.assertRaises(ValueError): compile_config(self.c)

    def test_invalid_new_fields_do_not_silently_disable_controls(self):
        for key, value in [('safe_search','true'), ('block_ipv6',1), ('youtube_restricted','unknown'), ('study_windows',[{'days':[True],'start':'16:00','end':'18:00'}])]:
            c = copy.deepcopy(self.c); c['parental']['profiles'][0][key] = value
            with self.assertRaises(ValueError): compile_config(c)
        self.c['parental']['auto_update'] = 'yes'
        with self.assertRaises(ValueError): compile_config(self.c)

    def test_study_and_safesearch_require_forced_dns(self):
        for addition in [{'study_windows':[{'days':[0],'start':'16:00','end':'18:00'}], 'study_domains':['school.test']}, {'safe_search':True}, {'youtube_restricted':'strict'}]:
            c = copy.deepcopy(self.c); c['parental']['profiles'][0].update(addition, enforce_dns=False)
            with self.assertRaises(ValueError): compile_config(c)
        self.c['parental']['profiles'][0]['study_windows'] = [{'days':[0],'start':'16:00','end':'18:00'}]
        with self.assertRaises(ValueError): compile_config(self.c)

    def test_school_dns_is_allowlist_and_cannot_open_ordinary_exceptions(self):
        self.p.update(study_domains=['school.test'], allowed_domains=['ordinary.test'])
        text = parental.dns_config(self.p, self.s, self.plan['interfaces'][0], {}, 'eth0', study=True)
        self.assertIn('address=/#/', text); self.assertNotIn('server=192.0.2.2', text); self.assertIn('server=/school.test/192.0.2.2', text)
        self.assertNotIn('server=/ordinary.test/', text)

    def test_school_allowlist_does_not_erase_baseline_service_block(self):
        self.p['study_domains'] = ['instagram.com']
        text = parental.dns_config(self.p, self.s, self.plan['interfaces'][0], {}, 'eth0', study=True)
        self.assertNotIn('server=/instagram.com/', text)

    def test_safesearch_cannot_unblock_service_or_widen_school_list(self):
        self.p.update(safe_search=True, youtube_restricted='strict', services=['youtube'], study_domains=['school.test'])
        text = parental.dns_config(self.p, self.s, self.plan['interfaces'][0], {}, 'eth0')
        self.assertIn('cname=www.google.it,forcesafesearch.google.com', text)
        self.assertNotIn('cname=www.youtube.com', text)
        study = parental.dns_config(self.p, self.s, self.plan['interfaces'][0], {}, 'eth0', True)
        self.assertNotIn('cname=www.google.it', study)
        self.p.update(services=[], youtube_restricted='moderate')
        self.assertIn('host-record=restrictmoderate.youtube.com,216.239.38.119', parental.dns_config(self.p,self.s,self.plan['interfaces'][0],{},'eth0'))

    def test_specific_exception_still_gets_restricted_google_dns(self):
        self.p.update(safe_search=True, blocked_domains=['google.com'], allowed_domains=['www.google.com'])
        text = parental.dns_config(self.p,self.s,self.plan['interfaces'][0],{},'eth0')
        self.assertIn('cname=www.google.com,forcesafesearch.google.com', text)

    def test_bonus_overrides_only_schedules_not_pause_or_failed_resolver(self):
        self.p['night_windows'] = [{'days':[0],'start':'16:00','end':'20:00'}]
        key = parental.bonus_key(self.p); grants = {key:self.when.timestamp()+60}
        def reason(overrides=None, ready=True, grants=grants):
            return parental.schedule_rules(self.s,self.plan['interfaces'],overrides or {},self.when,{1:ready},grants)[1][0]['reason']
        self.assertEqual(reason(grants={}), 'notte'); self.assertEqual(reason(), '')
        self.assertEqual(reason(ready=False), 'resolver fermo')
        self.assertEqual(reason({parental.fingerprint(self.p):self.when.timestamp()+60}), 'pausa')
        self.p['paused'] = True
        self.assertEqual(reason(), 'pausa')

    def test_expired_bonus_and_policy_change_invalidate_grant(self):
        self.p['windows'] = [{'days':[0],'start':'08:00','end':'09:00'}]
        key = parental.bonus_key(self.p)
        _, rows = parental.schedule_rules(self.s,self.plan['interfaces'],{},self.when,{1:True},{key:self.when.timestamp()})
        self.assertEqual(rows[0]['reason'], 'fuori orario')
        self.p['clients'] = ['10.60.0.20/32']; self.assertNotEqual(key,parental.bonus_key(self.p))

    def test_bonus_private_persistence_revoke_and_duration_validation(self):
        with patch.object(parental,'STATE',self.state), patch.object(parental,'CURRENT',self.plan), patch.object(parental,'tick'):
            parental.bonus(1,30); self.assertIn(parental.bonus_key(self.p),parental.bonuses(self.state))
            self.assertEqual((self.state/'parental-bonuses.json').stat().st_mode&0o777,0o600)
            parental.bonus(1,0); self.assertEqual(parental.bonuses(self.state),{})
            for ident,minutes in [(True,30),(1,True),(9,30),(1,241),(1,-1)]:
                with self.assertRaises(ValueError): parental.bonus(ident,minutes)

    def test_modes_midnight_dst_and_empty_windows(self):
        self.p['night_windows'] = [{'days':[6],'start':'22:00','end':'07:00'}]
        self.assertTrue(parental.in_mode(self.p,'night_windows','Europe/Rome',datetime(2026,10,26,5,0,tzinfo=timezone.utc)))
        self.assertFalse(parental.in_mode(self.p,'study_windows','Europe/Rome',self.when))
        self.p['study_windows'] = [{'days':[6],'start':'02:00','end':'03:00'}]
        for hour in (0,1): self.assertTrue(parental.in_mode(self.p,'study_windows','Europe/Rome',datetime(2026,10,25,hour,30,tzinfo=timezone.utc)))

    def test_ipv6_block_scopes_both_directions_and_local_access_to_whole_lan(self):
        self.c['parental']['profiles'][0]['block_ipv6'] = True
        text = compile_config(self.c)['nftables']
        for chain,direction in [('pc_forward','iifname'),('pc_forward','oifname'),('pc_input','iifname'),('pc_output','oifname')]:
            self.assertIn(f'insert rule inet murus_igneus {chain} {direction} "lan0" meta nfproto ipv6 counter drop',text)
        self.assertNotIn('iifname "wan0" meta nfproto ipv6 counter drop',text)

    def test_proxy_does_not_bypass_school_or_safesearch_vips(self):
        self.p.update(study_domains=['school.test'], safe_search=True)
        runtime = {'running':True,'error':'','profiles':[{'id':1,'blocked':False,'study':True}]}
        with patch.object(parental,'GUARD',self.plan),patch.object(parental,'CURRENT',self.plan),patch.object(parental,'RUNTIME',runtime),patch.object(parental,'BLOCKED',{}):
            self.assertTrue(parental.proxy_allowed('10.60.0.10','school.test'))
            self.assertFalse(parental.proxy_allowed('10.60.0.10','ordinary.test'))
            runtime['profiles'][0]['study'] = False
            self.assertFalse(parental.proxy_allowed('10.60.0.10','www.google.com'))

    def test_feed_save_keeps_private_previous_copy_and_stale_flag(self):
        old = {'domains':['old.test'],'updated':time.time()-3*86400,'sha256':'old'}
        parental.save_feed(self.state,'adult',old)
        inventory = parental.inventory(self.state); self.assertTrue(inventory['lists'][0]['stale'])
        parental.save_feed(self.state,'adult',{**old,'domains':['new.test']})
        previous = parental.feed_path('adult',self.state).with_suffix('.previous.json')
        self.assertEqual(json.loads(previous.read_text()),old); self.assertEqual(previous.stat().st_mode&0o777,0o600)

    def test_automatic_refresh_restores_previous_feed_on_resolver_failure(self):
        self.p['categories']=['adult']; parental.save_feed(self.state,'adult',{'domains':['old.test'],'updated':0,'sha256':'old'})
        payload = {'domains':['new.test'],'updated':time.time(),'sha256':'new'}
        with patch.object(parental,'STATE',self.state),patch.object(parental,'CURRENT',self.plan),patch.object(parental.STOP,'is_set',return_value=False),patch.object(parental,'UPDATE_ALLOWED',return_value=True),patch.object(parental,'download_feed',return_value=payload),patch.object(parental,'replace_dns',side_effect=[ValueError('dead resolver'),None]),patch.object(parental,'tick'):
            with self.assertRaisesRegex(ValueError,'dead resolver'): parental.refresh_active_lists(self.plan)
        self.assertEqual(json.loads(parental.feed_path('adult',self.state).read_text())['domains'],['old.test'])

    def test_automatic_results_for_replaced_plan_are_discarded(self):
        self.p['categories']=['adult']
        with patch.object(parental,'STATE',self.state),patch.object(parental,'CURRENT',copy.deepcopy(self.plan)),patch.object(parental,'download_feed',return_value={}):
            with self.assertRaisesRegex(ValueError,'Configurazione cambiata'): parental.refresh_active_lists(self.plan)
        self.assertFalse(parental.feed_path('adult',self.state).exists())

    def test_automatic_download_failure_does_not_touch_runtime(self):
        self.p['categories']=['adult']
        with patch.object(parental,'download_feed',side_effect=ValueError('invalid HTML')),patch.object(parental,'replace_dns') as reload:
            with self.assertRaises(ValueError): parental.refresh_active_lists(self.plan)
            reload.assert_not_called()

    def test_automatic_success_activates_and_persists_status(self):
        self.p['categories']=['adult'];parental.save_feed(self.state,'adult',{'domains':['old.test'],'updated':0,'sha256':'old'})
        payload = {'domains':['new.test'],'updated':time.time(),'sha256':'new'}
        with patch.object(parental,'STATE',self.state),patch.object(parental,'CURRENT',self.plan),patch.object(parental.STOP,'is_set',return_value=False),patch.object(parental,'UPDATE_ALLOWED',return_value=True),patch.object(parental,'download_feed',return_value=payload),patch.object(parental,'replace_dns') as reload,patch.object(parental,'tick'):
            parental.refresh_active_lists(self.plan); reload.assert_called_once_with({'adult':['new.test']})
        self.assertTrue(json.loads((self.state/'parental-auto-update.json').read_text())['last_success'])

    def test_scheduler_opt_in_pending_and_recent_data_suppress_download(self):
        self.p['categories']=['adult'];parental.save_feed(self.state,'adult',{'domains':['old.test'],'updated':time.time(),'sha256':'old'})
        with patch.object(parental,'STATE',self.state),patch.object(parental,'CURRENT',self.plan),patch.object(parental,'AUTO_NEXT',0),patch.object(parental.STOP,'is_set',return_value=False),patch.object(parental,'UPDATE_ALLOWED',return_value=True),patch.object(parental.TASK,'start') as start:
            parental.maybe_update(); start.assert_not_called()
            self.s['auto_update']=True;parental.maybe_update();start.assert_not_called()
        with patch.object(parental,'CURRENT',self.plan),patch.object(parental,'UPDATE_ALLOWED',return_value=False),patch.object(parental.TASK,'start') as start:
            parental.maybe_update();start.assert_not_called()

    def test_resolver_transition_tests_before_switch_and_restores_configs_on_failure(self):
        run=self.state/'run';run.mkdir();path=run/'parental-1.conf';path.write_text('previous config')
        with patch.object(parental,'CURRENT',self.plan),patch.object(parental.security,'RUN',run),patch.object(parental.security,'command',side_effect=ValueError('invalid candidate')),patch.object(parental,'start_resolver') as start:
            with self.assertRaisesRegex(ValueError,'Aggiornamento DNS annullato'):parental.replace_dns({})
            self.assertEqual(path.read_text(),'previous config');self.assertEqual(start.call_count,0)
            self.assertFalse(path.with_suffix('.candidate').exists())


if __name__ == '__main__': unittest.main()
