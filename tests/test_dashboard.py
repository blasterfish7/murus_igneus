"""Kernel telemetry parsing and partial failure behavior. SPDX-License-Identifier: MIT."""
from pathlib import Path
import tempfile
import unittest
from murus_igneus.traffic import system_snapshot


class DashboardTests(unittest.TestCase):
    def test_kernel_counters_exclude_guest_cpu_and_loopback(self):
        with tempfile.TemporaryDirectory() as folder:
            proc = Path(folder)
            (proc/'net').mkdir()
            (proc/'stat').write_text('cpu  10 2 3 40 5 6 7 8 9 10\n')
            (proc/'meminfo').write_text('MemTotal: 1000 kB\nMemAvailable: 250 kB\n')
            (proc/'uptime').write_text('123.45 60.00\n')
            (proc/'net/dev').write_text('header\nheader\n lo: 90 0 0 0 0 0 0 0 90 0 0 0 0 0 0 0\n eth0: 1024 0 0 0 0 0 0 0 2048 0 0 0 0 0 0 0\n')
            result = system_snapshot(proc)
            self.assertEqual(result['cpu'], {'total':81, 'idle':45})
            self.assertEqual(result['memory'], {'total':1024000, 'used':768000})
            self.assertEqual(result['interfaces'], [{'device':'eth0', 'rx':1024, 'tx':2048}])
            self.assertEqual(result['uptime'], 123.45)
            self.assertEqual(result['errors'], [])

    def test_missing_and_invalid_sources_are_unavailable(self):
        with tempfile.TemporaryDirectory() as folder:
            proc = Path(folder)
            (proc/'stat').write_text('cpu invalid\n')
            result = system_snapshot(proc)
            self.assertIsNone(result['cpu'])
            self.assertIsNone(result['memory'])
            self.assertIsNone(result['uptime'])
            self.assertEqual(len(result['errors']), 4)
