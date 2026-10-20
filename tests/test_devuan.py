"""Packaging and management regression checks; no host firewall changes."""
import base64
import http.client
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import ThreadingHTTPServer

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src/murus_igneus'))
import server

class ManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        state=Path(self.temp.name);(state/'admin.password').write_text('test-local-password')
        self.state=patch.object(server,'STATE',state);self.state.start()
        self.http=ThreadingHTTPServer(('127.0.0.1',0),server.Handler)
        self.thread=threading.Thread(target=self.http.serve_forever,daemon=True);self.thread.start()
    def tearDown(self):
        self.http.shutdown();self.http.server_close();self.thread.join();self.state.stop();self.temp.cleanup()
    def post(self,token):
        headers={'Authorization':'Basic '+base64.b64encode(b'admin:test-local-password').decode(),'Content-Type':'application/json','X-Murus-Igneus-CSRF':token}
        connection=http.client.HTTPConnection('127.0.0.1',self.http.server_port,timeout=5)
        connection.request('POST','/api/configuration/preview',json.dumps({'configuration':server.empty()}),headers)
        response=connection.getresponse();result=(response.status,json.loads(response.read()));connection.close();return result
    def test_frontend_header_and_backend_preview(self):
        code=(ROOT/'src/murus_igneus/app.js').read_text()
        header=re.search(r"'(X-[^']+-CSRF)':csrf",code).group(1)
        self.assertEqual(header,'X-Murus-Igneus-CSRF')
        status,body=self.post(server.CSRF);self.assertEqual(status,200);self.assertTrue(body['ready']);self.assertIn('plan_id',body)
    def test_wrong_csrf_is_rejected(self):self.assertEqual(self.post('wrong')[0],403)
    def test_predictable_management_name_is_reserved(self):
        c=server.empty();c['interfaces']=[{'name':'wan','device':'ens18','address':'192.0.2.1/24'}]
        p=server.compile_config(c,management='ens18');self.assertFalse(p['ready'])
        self.assertIn('"ens18" tcp dport 8443 accept',server.baseline('ens18'))
    def test_invalid_management_env_fails_before_main(self):
        env=os.environ.copy();env['MURUS_MANAGEMENT_INTERFACE']='eth0;reboot';env['PYTHONPATH']=str(ROOT/'src/murus_igneus')
        result=subprocess.run([sys.executable,'-c','import server'],env=env,capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0);self.assertIn('Interfaccia di gestione non valida',result.stderr)

class PackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        subprocess.run(['sh',str(ROOT/'packaging/devuan/build-deb.sh'),cls.temp.name],check=True,capture_output=True)
        cls.package=Path(cls.temp.name)/'murus-igneus_0.3.0~alpha.3_all.deb'
        cls.data=tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb','--fsys-tarfile',str(cls.package)])))
        cls.control=tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb','--ctrl-tarfile',str(cls.package)])))
    @classmethod
    def tearDownClass(cls):cls.data.close();cls.control.close();cls.temp.cleanup()
    def test_package_contains_native_service_and_app(self):
        for name in ('./etc/init.d/murus-igneus','./usr/sbin/murus-serve','./usr/sbin/murus-prepare','./usr/sbin/murus-info'):
            item=self.data.getmember(name);self.assertEqual(item.mode,0o755);self.assertEqual(item.uid,0);self.assertEqual(item.gid,0)
        for name in ('server.py','configuration.py','migration.py','tasks.py','assistant.py','switches.py','management.js','app.js','index.html','style.css','LICENSE-MIT'):
            self.data.getmember('./usr/lib/murus-igneus/'+name)
        self.assertFalse(any('legacy' in m.name or 'admin.password' in m.name for m in self.data.getmembers()))
    def test_preinstall_checks_target_os(self):
        preinst=self.control.extractfile('./preinst').read().decode()
        self.assertIn('devuan',preinst);self.assertIn('excalibur',preinst)
    def test_install_does_not_start_firewall(self):
        postinst=self.control.extractfile('./postinst').read().decode()
        executable='\n'.join(x for x in postinst.splitlines() if not x.strip().startswith('echo'))
        self.assertNotIn('rc-service',executable);self.assertNotIn('chpasswd',executable)
    def test_apt_config_uses_only_free_component(self):
        for line in (ROOT/'packaging/devuan/sources.list').read_text().splitlines():
            if not line or line.startswith('#'):continue
            fields=line.split();self.assertEqual(fields[0],'deb');self.assertEqual(fields[1],'http://deb.devuan.org/merged');self.assertEqual(fields[3:],['main']);self.assertTrue(fields[2].startswith('excalibur'))

if __name__=='__main__':unittest.main()


