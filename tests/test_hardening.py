# SPDX-License-Identifier: MIT
"""Regression tests for the second round of review fixes."""
import io
import json
import os
import shutil
import subprocess
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'src' / 'murus_igneus'
sys.path.insert(0, str(SRC))
import server  # noqa: E402
from migration import VERSION, Error, translate  # noqa: E402
from configuration import compile_config, empty  # noqa: E402

BASE = Path(__file__).with_name('example.conf').read_text()


class VersionTests(unittest.TestCase):
    def test_every_version_string_agrees(self):
        init = (SRC / '__init__.py').read_text()
        self.assertIn(f'__version__ = "{VERSION}"', init)
        self.assertEqual(translate(BASE, {'wan': 'eth1', 'lan': 'eth2'})['version'], VERSION)
        self.assertEqual(compile_config(empty())['version'], VERSION)  # version is reported even when not ready
        self.assertEqual(server.Handler.server_version, 'Murus Igneus/' + VERSION)
        self.assertIn(VERSION.split('-')[0], (SRC / 'index.html').read_text())


class ManagementRouteTests(unittest.TestCase):
    """network() must refuse routes that would hijack the management network."""

    def setUp(self):
        self.saved = server.run
        self.calls = []

        def fake(args, data=None, check=True):
            self.calls.append(args)
            if args[:4] == ['ip', '-j', 'link', 'show']:
                return json.dumps([{'flags': ['UP']}])
            if args[:3] == ['ip', '-j', 'link']:
                return json.dumps([{'ifname': 'eth0'}, {'ifname': 'eth1'}])
            if args[:4] == ['ip', '-j', '-4', 'addr'] and args[-1] == server.MGMT:
                return json.dumps([{'addr_info': [{'local': '10.0.0.5', 'prefixlen': 24}]}])
            return '[]'

        server.run = fake

    def tearDown(self):
        server.run = self.saved

    @staticmethod
    def route(destination):
        return {'kind': 'route', 'destination': destination, 'gateway': '192.0.2.1', 'interface': 'eth1', 'metric': 655360}

    def test_route_inside_management_network_is_refused(self):
        for destination in ('10.0.0.0/24', '10.0.0.128/25', '10.0.0.7/32'):
            with self.subTest(destination=destination):
                self.calls.clear()
                with self.assertRaises(Error):
                    server.network([self.route(destination)], [])
                self.assertFalse([c for c in self.calls if c[:3] == ['ip', 'route', 'add']], 'nothing may be applied')

    def test_default_and_unrelated_routes_are_accepted(self):
        for destination in ('0.0.0.0/0', '10.0.0.0/16', '172.16.0.0/12'):
            with self.subTest(destination=destination):
                undo = []
                server.network([self.route(destination)], undo)
                self.assertEqual(len(undo), 1)


class AdminPasswordTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name)
        self.saved = server.STATE
        server.STATE = self.state

    def tearDown(self):
        server.STATE = self.saved
        self.tmp.cleanup()

    def test_first_start_creates_a_random_private_password(self):
        first, created = server.ensure_password(self.state)
        self.assertTrue(created)
        self.assertNotEqual(first, server.LEGACY_PASSWORD)
        self.assertGreaterEqual(len(first), 12)
        self.assertEqual(stat.S_IMODE((self.state / 'admin.password').stat().st_mode), 0o600)
        other = tempfile.TemporaryDirectory()
        try:
            self.assertNotEqual(first, server.ensure_password(Path(other.name))[0])
        finally:
            other.cleanup()

    def test_existing_password_is_kept(self):
        (self.state / 'admin.password').write_text('chosen-by-admin\n')
        self.assertEqual(server.ensure_password(self.state), ('chosen-by-admin', False))
        self.assertEqual((self.state / 'admin.password').read_text(), 'chosen-by-admin\n')

    def test_default_password_flag(self):
        self.assertFalse(server.default_password())  # no file at all
        (self.state / 'admin.password').write_text(server.LEGACY_PASSWORD)
        self.assertTrue(server.default_password())
        server.ensure_password(self.state)
        (self.state / 'admin.password').write_text('something-else')
        self.assertFalse(server.default_password())

    def test_atomic_never_exposes_the_file_with_wider_permissions(self):
        target = self.state / 'secret'
        old = os.umask(0)  # the strictest case for "readable by others"
        try:
            server.atomic(target, 'x')
        finally:
            os.umask(old)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_startup_message_names_the_file_but_never_the_secret(self):
        # main() prints through print(..., file=sys.stderr); reproduce its exact logic around ensure_password.
        buffer = io.StringIO()
        with redirect_stderr(buffer):
            password, created = server.ensure_password(self.state)
            self.assertTrue(created)
        self.assertNotIn(password, buffer.getvalue())
        source = (SRC / 'server.py').read_text()
        self.assertNotIn("print(password", source)
        self.assertNotIn("+password+", source.replace(' ', ''))


class PackageImportTests(unittest.TestCase):
    def test_importable_as_a_package(self):
        # The service runs server.py as a script; the package form must work too.
        env = {**os.environ, 'PYTHONPATH': str(ROOT / 'src')}
        result = subprocess.run([sys.executable, '-c', 'import murus_igneus.server as s; print(s.VERSION)'],
                                env=env, capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), VERSION)


@unittest.skipUnless(shutil.which('git') and (ROOT / '.git').exists(), 'needs a git checkout')
class GitignoreTests(unittest.TestCase):
    def ignored(self, path):
        return subprocess.run(['git', 'check-ignore', '-q', path], cwd=ROOT).returncode == 0

    def test_secrets_and_backups_are_ignored(self):
        for path in ('server.key', 'a/b/cert.pem', 'server.crt', 'admin.password', 'active.json', 'fortigate-backup.conf'):
            with self.subTest(path=path):
                self.assertTrue(self.ignored(path))

    def test_the_synthetic_test_fixture_is_not_ignored(self):
        self.assertFalse(self.ignored('tests/example.conf'))


if __name__ == '__main__':
    unittest.main()
