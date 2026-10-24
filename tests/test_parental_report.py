"""Reporting deltas, DNS semantics, retention and privacy boundaries."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src/murus_igneus'))
import parental
import parental_report as reports
from configuration import compile_config
from test_parental import configuration


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name); self.c = configuration(); self.c['parental']['reporting'] = True
        self.plan = compile_config(self.c); self.settings = self.plan['parental']['settings']
        self.rows = reports.entities(self.settings, self.c['interfaces']); self.row = self.rows[0]
        self.values = {reports.counter(self.row, d): (0, 0) for d in ('up', 'down', 'blocked')}
        self.patch = patch.object(reports.Collector, 'read_counters', lambda _: dict(self.values)); self.patch.start(); self.addCleanup(self.patch.stop)
        self.collector = reports.Collector(self.settings, self.c['interfaces'], self.state)

    def total(self, now=10000):
        return reports.report(self.state, 1, now)['devices'][0]

    def test_opt_in_and_backwards_compatibility(self):
        c = configuration(); c['parental'].pop('reporting', None); plan = compile_config(c)
        self.assertFalse(plan['parental']['settings']['reporting']); self.assertNotIn('pc_report', plan['nftables'])
        p = plan['parental']['settings']['profiles'][0]
        self.assertNotIn('log-queries', parental.dns_config(p, plan['parental']['settings'], c['interfaces'][0], {}, 'eth0'))
        c['parental']['reporting'] = 'true'
        with self.assertRaises(ValueError):
            compile_config(c)

    def test_named_counters_after_filter_and_all_parental_drop_paths(self):
        nft = self.plan['nftables']; self.assertIn('hook forward priority 20', nft)
        name = reports.counter(self.row, 'blocked')
        self.assertLess(nft.index('add counter inet murus_igneus ' + name), nft.index('counter name ' + name))
        script, _ = parental.schedule_rules(self.settings, self.c['interfaces'], {}, ready={1: False})
        self.assertEqual(script.count('counter name ' + name + ' drop'), 2)
        self.assertIn('log-queries=extra', parental.dns_config(self.settings['profiles'][0], self.settings, self.c['interfaces'][0], {}, 'eth0'))

    def test_deltas_no_double_count_and_kernel_reset(self):
        self.values[reports.counter(self.row, 'up')] = (1000, 10)
        self.values[reports.counter(self.row, 'down')] = (2000, 20)
        self.values[reports.counter(self.row, 'blocked')] = (90, 3)
        self.collector.collect(10000); self.collector.collect(10001)
        self.assertEqual((self.total()['upload_bytes'], self.total()['download_bytes'], self.total()['blocked_packets']), (1000, 2000, 3))
        self.values[reports.counter(self.row, 'up')] = (50, 1); self.collector.collect(10002)
        self.assertEqual(self.total()['upload_bytes'], 1050)
        self.assertEqual(reports.report(self.state, 1, 10002)['hourly'][0]['entity'], self.row['entity'])

    def test_missing_counter_is_not_reported_as_zero_and_read_errors_surface(self):
        del self.values[reports.counter(self.row, 'down')]
        with self.assertRaises(ValueError):
            self.collector.collect(10000)
        self.assertFalse(reports.path(self.state).exists())

    def test_dns_queries_are_not_visits_and_only_local_nxdomain_is_filtered(self):
        pending = {}
        lines = ['dnsmasq[42]: 1 10.60.0.10/51000 query[A] blocked.test from 10.60.0.10',
                 'dnsmasq[42]: 1 10.60.0.10/51000 config blocked.test is NXDOMAIN',
                 'dnsmasq[42]: 2 10.60.0.10/51000 query[AAAA] allowed.test from 10.60.0.10',
                 'dnsmasq[42]: 2 10.60.0.10/51000 reply allowed.test is NXDOMAIN',
                 'dnsmasq[42]: 3 10.60.0.11/51000 query[A] unassigned.test from 10.60.0.11']
        for line in lines:
            self.collector.dns_line(1, line, pending, 10000)
        self.collector.collect(10000); total = self.total()
        self.assertEqual((total['dns_queries'], total['dns_filtered']), (2, 1))
        self.assertEqual(total['upload_bytes'], 0)
        self.assertNotIn('unassigned.test', json.dumps(reports.report(self.state, 1, 10000)))
        self.assertEqual(list(self.state.rglob('*.log')), [])

    def test_dns_pending_buffer_is_bounded_and_drops_are_visible(self):
        pending = {}
        for i in range(2200):
            self.collector.dns_line(1, f'42 {"10.60.0.10"}/123 query[A] d{i}.test from 10.60.0.10', pending, 10000)
        self.assertLessEqual(len(self.collector.pending), 2048); self.assertGreater(reports.STATUS['discarded_dns'], 0)

    def test_clear_resets_baseline_and_does_not_restore_old_totals(self):
        self.values[reports.counter(self.row, 'up')] = (100, 1); self.collector.collect(10000)
        self.collector.clear(); self.collector.collect(10001)
        self.assertEqual(reports.report(self.state, 1, 10001)['devices'], [])
        self.values[reports.counter(self.row, 'up')] = (150, 2); self.collector.collect(10002)
        self.assertEqual(self.total()['upload_bytes'], 50)

    def test_restart_does_not_count_previous_kernel_totals(self):
        self.values[reports.counter(self.row, 'up')] = (5000, 50)
        restarted = reports.Collector(self.settings, self.c['interfaces'], self.state); restarted.collect(10000)
        self.assertEqual(reports.report(self.state, 1, 10000)['devices'], [])

    def test_profile_reuse_and_subnet_identity_do_not_merge(self):
        c = copy.deepcopy(self.settings); c['profiles'][0]['clients'] = ['10.60.0.0/24']
        row = reports.entities(c, self.c['interfaces'])[0]
        self.assertNotEqual(row['entity'], self.row['entity']); self.assertEqual(row['client'], '10.60.0.0/24')

    def test_retention_and_storage_permissions(self):
        reports.write(self.state, [(3600, self.row, '', (10, 0, 1, 0, 0, 0)), (700000, self.row, '', (20, 0, 1, 0, 0, 0))], 700000)
        r = reports.report(self.state, 7, 700000)
        self.assertEqual(r['devices'][0]['upload_bytes'], 20)
        self.assertEqual(os.stat(reports.path(self.state)).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(reports.path(self.state).parent).st_mode & 0o777, 0o700)
        with patch.object(reports, 'MAX_ROWS', 2):
            reports.write(self.state, [(700000, self.row, f'd{i}.test', (0, 0, 0, 0, 1, 0)) for i in range(5)], 700000)
            with reports.connect(self.state) as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM samples').fetchone()[0], 2)

    def test_period_validation_and_csv_formula_escape(self):
        for days in (0, 30, '7', True):
            with self.assertRaises(ValueError):
                reports.report(self.state, days)
        row = dict(self.row, name='=HYPERLINK("test")')
        reports.write(self.state, [(7200, row, 'example.test', (0, 0, 0, 0, 1, 0))], 10000)
        csv = reports.export_csv(reports.report(self.state, 1, 10000))
        self.assertIn("'=HYPERLINK", csv); self.assertIn('example.test', csv)

    def test_json_named_counter_parser(self):
        raw = json.dumps({'nftables': [{'metainfo': {}}, {'counter': {'table': 'murus_igneus', 'name': 'pcr_test_up', 'bytes': 123, 'packets': 2}}, {'counter': {'table': 'other', 'name': 'pcr_test_up', 'bytes': 999, 'packets': 9}}]})
        self.assertEqual(reports.decode_counters(raw), {'pcr_test_up': (123, 2)})
