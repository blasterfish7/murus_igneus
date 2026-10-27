"""Real TLS status polling with a held transaction lock. SPDX-License-Identifier: MIT."""
import base64
from http.client import HTTPSConnection
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src/murus_igneus'))
import server
assert os.environ.get('MURUS_LAB')=='YES','Explicit disposable loopback laboratory required'

with tempfile.TemporaryDirectory(prefix='murus-status-qa-') as directory:
    work=Path(directory);server.STATE=work;(work/'admin.password').write_text('qa-only-password')
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(work/'key.pem'),'-out',str(work/'cert.pem'),'-days','1','-subj','/CN=localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    def readonly(args,*a,**kw):
        assert args==['ip','-j','link'],'System mutation disabled in status fixture'
        return json.dumps([{'ifname':'eth0'},{'ifname':'eth1'}])
    server.run=readonly;server.PENDING=None
    http=server.make_server('127.0.0.1',0,work/'cert.pem',work/'key.pem')
    worker=threading.Thread(target=http.serve_forever,daemon=True);worker.start()
    def request(path,post=False):
        conn=HTTPSConnection('127.0.0.1',http.server_port,context=ssl._create_unverified_context(),timeout=3)
        headers={'Authorization':'Basic '+base64.b64encode(b'admin:qa-only-password').decode()}
        if post:headers.update({'Content-Type':'application/json',server.CSRF_HEADER:server.CSRF})
        try:
            conn.request('POST' if post else 'GET','/api/'+path,body='{}' if post else None,headers=headers)
            response=conn.getresponse();data=json.loads(response.read());assert response.status==200,(response.status,data);return data
        finally:conn.close()
    done=threading.Event();started=threading.Event();errors=[]
    def write():
        started.set()
        try:assert request('rollback',True)['ok']
        except Exception as exc:errors.append(str(exc))
        finally:done.set()
    writer=None
    try:
        with server.LOCK:
            assert request('status')['pending'] is None
            assert request('auth/status')['csrf']==server.CSRF
            writer=threading.Thread(target=write,daemon=True);writer.start();assert started.wait(1)
            assert not done.wait(.3),'Mutation bypassed transaction serialization'
        assert done.wait(3),errors
        assert not errors,errors
        print('PASS real HTTPS status/auth polling remains responsive while mutations wait for the transaction lock',flush=True)
    finally:
        if writer:writer.join(timeout=4)
        http.shutdown();http.server_close();worker.join(timeout=4)
