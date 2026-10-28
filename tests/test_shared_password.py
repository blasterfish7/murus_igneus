"""Shared root credentials without changing the host's shadow file. SPDX-License-Identifier: MIT."""
import json
from pathlib import Path
import tempfile
import unittest
from murus_igneus import authentication as auth


class SharedPasswordTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        self.shadow = self.state/'shadow'
        self.old_hash = auth.password_hash('igneus', '$6$fixture$')
        self.shadow.write_text('root:'+self.old_hash+':0:0:99999:7:::\n')
        auth.write(self.state/'credentials.json', {'system_root':True})

    def test_initial_password_forces_change_and_console_change_updates_web(self):
        self.assertTrue(auth.check_password(self.state,'igneus',self.shadow))
        self.assertTrue(auth.password_status(self.state,self.shadow)['password_change_required'])
        new = auth.password_hash('console-new', '$6$new$')
        self.shadow.write_text('root:'+new+':20000:0:99999:7:::\n')
        self.assertFalse(auth.check_password(self.state,'igneus',self.shadow))
        self.assertTrue(auth.check_password(self.state,'console-new',self.shadow))
        self.assertFalse(auth.password_status(self.state,self.shadow)['password_change_required'])

    def test_web_change_writes_only_root_hash_and_removes_plaintext(self):
        (self.state/'admin.password').write_text('legacy-secret')
        def update(args, **kwargs):
            self.assertEqual(args, ['chpasswd','-e'])
            self.assertNotIn('openwall', kwargs['input'])
            self.shadow.write_text(kwargs['input'].strip()+':20000:0:99999:7:::\n')
        result = auth.change_password(self.state,'openwall','openwall',self.shadow,update)
        self.assertTrue(result['shared_console_password'])
        self.assertTrue(auth.check_password(self.state,'openwall',self.shadow))
        self.assertFalse((self.state/'admin.password').exists())
        self.assertFalse(auth.password_status(self.state,self.shadow)['password_change_required'])

    def test_failure_restores_legacy_authority_when_shadow_unchanged(self):
        auth.write(self.state/'credentials.json', {'system_root':False,'must_change':True})
        (self.state/'admin.password').write_text('legacy-secret')
        def failed(*args, **kwargs):
            raise OSError('controlled failure')
        with self.assertRaisesRegex(ValueError,'non completato'):
            auth.change_password(self.state,'openwall','openwall',self.shadow,failed)
        self.assertTrue(auth.check_password(self.state,'legacy-secret',self.shadow))
        self.assertEqual(auth.shadow_record(self.shadow)[1],self.old_hash)

    def test_password_validation_and_locked_accounts(self):
        for password,confirm in [('short','short'),('openwall','mismatch'),('bad\npassword','bad\npassword')]:
            with self.assertRaises(ValueError):
                auth.change_password(self.state,password,confirm,self.shadow)
        self.shadow.write_text('root:!'+self.old_hash+':20000:0:99999:7:::\n')
        self.assertFalse(auth.check_password(self.state,'igneus',self.shadow))

    def test_initialize_does_not_modify_console_or_existing_web_password(self):
        (self.state/'credentials.json').unlink()
        (self.state/'admin.password').write_text('legacy-secret')
        before = self.shadow.read_bytes()
        auth.initialize_credentials(self.state)
        self.assertEqual(self.shadow.read_bytes(),before)
        self.assertTrue(auth.password_status(self.state,self.shadow)['password_change_required'])
        self.assertTrue(auth.check_password(self.state,'legacy-secret',self.shadow))
        self.assertEqual(json.loads((self.state/'credentials.json').read_text())['system_root'],False)


class InstalledPasswordTests(unittest.TestCase):
    def test_install_preserves_changed_console_password_and_other_accounts(self):
        from murus_igneus import installer
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder);(root/'etc').mkdir()
            destination = root/'etc/shadow';destination.write_text('root:factory:0:0:99999:7:::\ndaemon:*:20000:0:99999:7:::\n');destination.chmod(0o640)
            source = root/'live-shadow';source.write_text('root:changed:20001:0:99999:7:::\ndaemon:other:0:0:99999:7:::\n')
            installer.preserve_root_password(root,source)
            self.assertIn('root:changed:20001:',destination.read_text())
            self.assertIn('daemon:*:20000:',destination.read_text())
            self.assertEqual(destination.stat().st_mode&0o777,0o640)

    def test_invalid_source_cannot_replace_target_credentials(self):
        from murus_igneus import installer
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder);(root/'etc').mkdir()
            destination = root/'etc/shadow';destination.write_text('root:factory:0:0:99999:7:::\n')
            source = root/'live-shadow';source.write_text('not a shadow record')
            with self.assertRaises(Exception):installer.preserve_root_password(root,source)
            self.assertIn('root:factory:',destination.read_text())
