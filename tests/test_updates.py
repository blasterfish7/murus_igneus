"""Signed staging, journal, independent-worker and recovery acceptance. SPDX-License-Identifier: MIT."""
import base64
import hashlib
import http.client
from http.server import ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.error
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src/murus_igneus'))
import updates


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.cache = self.root/'cache'; self.cache.mkdir(mode=0o700)
        self.state = self.root/'state'; self.state.mkdir(mode=0o700)
        (self.state/'active.json').write_text('{"configuration":"old"}')
        self.bundle = self.root/'bundle'; self.bundle.mkdir()
        self.version = '0.3.0~alpha.10'
        self.new = '0.3.0~alpha.11'
        self.old_deb = self.make_deb(self.root/'old', self.version)
        new_deb = self.make_deb(self.root/'new', self.new)
        shutil.copyfile(new_deb, self.bundle/'murus-igneus.deb')
        self.key = self.root/'update.pub'
        self.private = self.root/'private'
        self.original = updates.command
        self.original(['openssl','genpkey','-algorithm','ED25519','-out',str(self.private)])
        self.original(['openssl','pkey','-in',str(self.private),'-pubout','-out',str(self.key)])
        self.meta = {'schema':1,'package':'murus-igneus','version':self.new,
                     'sha256':hashlib.sha256(new_deb.read_bytes()).hexdigest()}
        (self.bundle/'manifest.json').write_text(json.dumps(self.meta))
        self.original(['openssl','pkeyutl','-sign','-inkey',str(self.private),'-rawin','-in',str(self.bundle/'manifest.json'),'-out',str(self.bundle/'manifest.sig')])
        self.patches = [patch.object(updates,'CACHE',self.cache), patch.object(updates,'STATE',self.state),
                        patch.object(updates,'EXTRA_CONFIG',{}), patch.object(updates,'TRUST_KEY',self.key), patch.object(updates,'LIVE',self.root/'no-live'),
                        patch.object(updates,'compatible_host',return_value=True),
                        patch.object(updates,'installed_version',side_effect=lambda:self.version),
                        patch.object(updates,'command',side_effect=self.command),
                        patch.object(updates,'management_ready')]
        for item in self.patches:
            item.start()
        self.calls = []

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def make_deb(self, directory, version):
        (directory/'DEBIAN').mkdir(parents=True)
        (directory/'DEBIAN/control').write_text('Package: murus-igneus\nVersion: '+version+'\nArchitecture: all\nMaintainer: Test <test@example.invalid>\nDescription: update fixture\n')
        target = directory.with_suffix('.deb')
        subprocess.run(['dpkg-deb','--build',str(directory),str(target)],check=True,capture_output=True)
        return target

    def command(self, args, **kwargs):
        self.calls.append(args)
        if args == ['dpkg','--audit']:
            return ''
        if args[:1] == ['dpkg-repack']:
            shutil.copyfile(self.old_deb, Path(kwargs['cwd'])/'murus-igneus_old.deb')
            return ''
        if args[0] == 'dpkg' and '-i' in args:
            self.version = self.original(['dpkg-deb','-f',args[-1],'Version'])
            if self.version == self.new:
                (self.state/'active.json').write_text('{"configuration":"migrated"}')
            return ''
        if args[:1] == ['rc-service']:
            return ''
        return self.original(args, **kwargs)

    def payload(self):
        return {'files':{name:base64.b64encode((self.bundle/name).read_bytes()).decode() for name in ('manifest.json','manifest.sig','murus-igneus.deb')}}

    def test_console_install_uses_private_verified_copy(self):
        modified = False
        def mutate_source(args, **kwargs):
            nonlocal modified
            if args == ['rc-service','murus-igneus','stop'] and not modified:
                (self.bundle/'murus-igneus.deb').write_bytes(b'changed after verification')
                modified = True
            return self.command(args,**kwargs)
        with patch.object(updates,'command',side_effect=mutate_source):
            updates.install(self.bundle)
        self.assertTrue(modified)
        self.assertEqual(self.version,self.new)
        self.assertEqual(updates.read(self.cache/'status.json')['state'],'succeeded')

    def test_signing_helper_emits_only_the_three_bundle_files(self):
        target = self.root/'signed-output'
        helper = Path(__file__).resolve().parents[1]/'tools/sign-update-bundle.py'
        package = self.root/'new.deb'
        subprocess.run([sys.executable,str(helper),str(package),'--key',str(self.private),'--output',str(target)],check=True,capture_output=True)
        self.assertEqual({path.name for path in target.iterdir()},{'manifest.json','manifest.sig','murus-igneus.deb'})
        self.assertEqual(updates.verify(target,self.key)['version'],self.new)

    def test_real_signature_stage_does_not_install_and_has_private_files(self):
        result = updates.stage(self.payload())
        self.assertEqual(result['version'], self.new)
        self.assertEqual(result['confirmation'], 'AGGIORNA '+self.new)
        self.assertEqual((self.cache/'staged/murus-igneus.deb').stat().st_mode & 0o777, 0o600)
        self.assertFalse(any(args[0] == 'dpkg' and '-i' in args for args in self.calls))

    def test_tampered_package_missing_key_and_writable_trust_are_rejected(self):
        payload = self.payload(); payload['files']['murus-igneus.deb'] = base64.b64encode(b'altered').decode()
        with self.assertRaises(ValueError):
            updates.stage(payload)
        self.key.chmod(0o666)
        with self.assertRaises(ValueError):
            updates.stage(self.payload())
        self.key.unlink()
        with self.assertRaises(ValueError):
            updates.stage(self.payload())

    def test_live_unsupported_downgrade_and_audit_rejected(self):
        with patch.object(updates,'compatible_host',return_value=False), self.assertRaises(ValueError):
            updates.stage(self.payload())
        self.version = '0.3.0~alpha.99'
        with self.assertRaises(ValueError):
            updates.stage(self.payload())
        self.version = '0.3.0~alpha.10'
        with patch.object(updates,'command',side_effect=lambda args,**kw:'broken' if args == ['dpkg','--audit'] else self.command(args,**kw)), self.assertRaises(ValueError):
            updates.stage(self.payload())

    def test_upload_limits_path_names_and_invalid_base64(self):
        for value in ({'files':{'../../key':'value'}}, {'files':{**self.payload()['files'],'manifest.sig':'!'}},
                      {'files':{**self.payload()['files'],'manifest.json':'x'*6000}}):
            with self.subTest(value=str(value)[:50]), self.assertRaises(ValueError):
                updates.stage(value)

    def test_launch_confirms_id_and_hands_off_locked_fd(self):
        first = updates.stage(self.payload())
        second = updates.stage(self.payload())
        with self.assertRaises(ValueError):
            updates.launch('install', {'id':first['id'],'confirmation':first['confirmation']})
        with self.assertRaises(ValueError):
            updates.launch('install', {'id':second['id'],'confirmation':'wrong'})
        def spawn(args, **kwargs):
            self.assertTrue(updates.busy())
            self.assertTrue(kwargs['start_new_session'])
            os.fstat(kwargs['pass_fds'][0])
        with patch.object(updates,'preflight',return_value=self.meta), patch.object(updates.subprocess,'Popen',side_effect=spawn):
            updates.launch('install', {'id':second['id'],'confirmation':second['confirmation']})
        self.assertEqual(updates.inventory()['job']['state'],'recovery_required')
        self.assertTrue(updates.blocked())

    def test_success_has_prior_package_and_configuration_before_dpkg(self):
        updates.save(self.cache/'status.json', {'id':'test','state':'running'})
        updates.transaction('install', self.bundle)
        backup = updates.read(self.cache/'rollback.json')
        root = self.cache/backup['directory']
        self.assertEqual((root/'configuration/active.json').read_text(),'{"configuration":"old"}')
        self.assertEqual(backup['sha256'],hashlib.sha256(self.old_deb.read_bytes()).hexdigest())
        self.assertEqual(updates.read(self.cache/'status.json')['state'],'succeeded')
        self.assertEqual(self.version,self.new)
        updates.management_ready.assert_called_with(require_marker=True)

    def test_failed_start_restores_package_and_configuration(self):
        updates.save(self.cache/'status.json', {'id':'test','state':'running'})
        updates.management_ready.side_effect = [ValueError('new version unhealthy'),None]
        with self.assertRaises(ValueError):
            updates.transaction('install', self.bundle)
        self.assertEqual(self.version,'0.3.0~alpha.10')
        self.assertEqual((self.state/'active.json').read_text(),'{"configuration":"old"}')
        result = updates.read(self.cache/'status.json')
        self.assertEqual(result['state'],'failed'); self.assertTrue(result['recovered'])

    def test_failed_recovery_is_explicit_and_blocks_new_changes(self):
        updates.management_ready.side_effect = ValueError('HTTPS down')
        with self.assertRaises(ValueError):
            updates.transaction('install', self.bundle)
        self.assertEqual(updates.read(self.cache/'status.json')['state'],'recovery_required')
        self.assertTrue(updates.blocked())

    def test_recovery_before_package_write_only_restarts_service(self):
        updates.save(self.cache/'status.json', {'action':'recover','recovery_job':{'action':'install','state':'running'}})
        with patch.object(updates,'restore') as restore:
            updates.transaction('recover')
            restore.assert_not_called()
        self.assertEqual(updates.read(self.cache/'status.json')['state'],'succeeded')

    def test_recovery_after_package_write_requires_exact_snapshot(self):
        updates.save(self.cache/'rollback.json', {'directory':'snapshot-wrong'})
        updates.save(self.cache/'status.json', {'action':'recover','recovery_job':{'package_changed':True,'snapshot_directory':'snapshot-expected'}})
        with patch.object(updates,'restore') as restore, self.assertRaises(ValueError):
            updates.transaction('recover')
        restore.assert_not_called()
        self.assertEqual(updates.read(self.cache/'status.json')['state'],'recovery_required')

    def test_config_link_rejected_before_package_change(self):
        (self.state/'external').symlink_to(self.key)
        with self.assertRaises(ValueError):
            updates.transaction('install', self.bundle)
        self.assertFalse(any(args[0] == 'dpkg' and '-i' in args for args in self.calls))

    def test_restore_handles_interrupted_directory_switch(self):
        updates.snapshot()
        shutil.rmtree(self.state)
        updates.restore()
        self.assertEqual((self.state/'active.json').read_text(),'{"configuration":"old"}')

    def test_release_channels_and_private_catalog_error(self):
        rows = [{'tag_name':'v0.3.0-alpha.11','prerelease':True,'body':'alpha'},
                {'tag_name':'v0.3.0','prerelease':False,'body':'stable'},
                {'tag_name':'v9.0.0','draft':True}]
        class Opener:
            def open(self, *args, **kwargs):
                return io.BytesIO(json.dumps(rows).encode())
        with patch.object(updates.urllib.request,'build_opener',return_value=Opener()):
            self.assertEqual(len(updates.releases('stable')['releases']),1)
            found = updates.releases('experimental')['releases']
            self.assertEqual(len(found),2); self.assertTrue(found[0]['newer'])
        with patch.object(updates.urllib.request,'build_opener') as opener:
            opener.return_value.open.side_effect = urllib.error.HTTPError('https://api.github.com',404,'Not found',None,None)
            with self.assertRaisesRegex(ValueError,'privato'):
                updates.releases('experimental')

    def test_external_boot_config_is_backed_up_and_restored(self):
        defaults = self.root/'default-config'; defaults.write_text('MURUS_MANAGEMENT_INTERFACE=eth0\n'); defaults.chmod(0o600)
        with patch.object(updates,'EXTRA_CONFIG',{'defaults':defaults}):
            updates.snapshot()
            defaults.write_text('MURUS_MANAGEMENT_INTERFACE=eth9\n')
            updates.restore()
            self.assertIn('eth0',defaults.read_text())
            self.assertEqual(defaults.stat().st_mode & 0o777,0o600)

    def test_http_auth_csrf_staging_and_update_write_guards(self):
        import server
        (self.state/'admin.password').write_text('test-password')
        patches = [patch.object(server,'STATE',self.state), patch.object(server,'PENDING',None),
                   patch.object(server.jobs,'busy',return_value=False)]
        for item in patches:
            item.start()
        httpd = ThreadingHTTPServer(('127.0.0.1',0),server.Handler)
        threading.Thread(target=httpd.serve_forever,daemon=True).start()
        def request(path, data=None, csrf=True, auth=True):
            connection = http.client.HTTPConnection('127.0.0.1',httpd.server_port,timeout=3)
            headers = {'Content-Type':'application/json'}
            if auth:
                headers['Authorization']='Basic '+base64.b64encode(b'admin:test-password').decode()
            if csrf:
                headers[server.CSRF_HEADER]=server.CSRF
            connection.request('GET' if data is None else 'POST',path,None if data is None else json.dumps(data),headers)
            response=connection.getresponse(); raw=response.read(); body=json.loads(raw) if raw else {}; connection.close()
            return response.status,body
        try:
            self.assertEqual(request('/api/updates',auth=False)[0],401)
            self.assertEqual(request('/api/updates/stage',self.payload(),csrf=False)[0],403)
            status,body=request('/api/updates/stage',self.payload())
            self.assertEqual(status,200,body); self.assertEqual(body['version'],self.new)
            tampered = {'files':{**self.payload()['files'],'murus-igneus.deb':base64.b64encode(b'altered').decode()}}
            code,body=request('/api/updates/stage',tampered)
            self.assertEqual(code,400); self.assertIn('Checksum',body['error'])
            with patch.object(updates,'blocked',return_value=True), patch.object(updates,'launch',return_value={'id':'recover'}) as launch:
                code,body=request('/api/configuration/preview',{'configuration':{}})
                self.assertNotEqual(code,200); self.assertIn('recupero',body['error'])
                code,_=request('/api/updates/recover',{'confirmation':'RECUPERA SERVIZIO'})
                self.assertEqual(code,200); launch.assert_called_once()
            with patch.object(server,'PENDING',{'id':'pending'}), patch.object(updates,'launch') as launch:
                code,_=request('/api/updates/install',{'id':'test','confirmation':'test'})
                self.assertNotEqual(code,200); launch.assert_not_called()
        finally:
            httpd.shutdown(); httpd.server_close()
            for item in reversed(patches):
                item.stop()

    def test_lock_survives_real_independent_child_handoff(self):
        ready = self.root/'ready'
        with updates.locked() as fd:
            process = subprocess.Popen([sys.executable,'-c',
                'import os,sys,time; from pathlib import Path; os.fstat(int(sys.argv[1])); Path(sys.argv[2]).write_text("ready"); sys.stdin.read(1)',str(fd),str(ready)],
                pass_fds=(fd,), start_new_session=True, stdin=subprocess.PIPE)
        try:
            self.assertTrue(updates.busy())
            process.communicate(input=b'x',timeout=5)
            self.assertEqual(process.returncode,0)
            self.assertEqual(ready.read_text(),'ready')
            self.assertFalse(updates.busy())
        finally:
            if process.poll() is None:
                process.kill(); process.wait()
