"""UEFI ISO boot and native-network acceptance in disposable QEMU. SPDX-License-Identifier: MIT."""
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import time
import urllib.request
import tempfile

import pexpect

ROOT = Path(__file__).resolve().parents[1]
assert os.environ.get('MURUS_LAB') == 'YES', 'Explicit disposable VM flag required'
iso = ROOT / 'dist/murus-igneus-0.3.0-alpha.9-devuan-amd64.iso'
assert iso.is_file()
firmware = Path('/usr/share/OVMF')
code = firmware / 'OVMF_CODE_4M.fd'; template = firmware / 'OVMF_VARS_4M.fd'
assert code.is_file() and template.is_file(), 'OVMF 4M required'
checks = []
with tempfile.TemporaryDirectory(prefix='murus-iso-qa-') as work:
    disk=Path(work)/'install-disk.raw'
    with disk.open('wb') as file:file.truncate(16*1024**3)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0));web_port=listener.getsockname()[1]
    variables = Path(work) / 'vars.fd'; shutil.copyfile(template, variables)
    args = ['qemu-system-x86_64', '-machine', 'q35,accel=tcg', '-cpu', 'max', '-smp', '2', '-m', '2048',
            '-drive', 'if=pflash,format=raw,readonly=on,file=' + str(code), '-drive', 'if=pflash,format=raw,file=' + str(variables),
            '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot', '-boot', 'd', '-cdrom', str(iso)]
    args += ['-drive','file='+str(disk)+',if=virtio,format=raw']
    for index in range(3):
        args += ['-netdev', f'user,id=n{index}'+(f',hostfwd=tcp:127.0.0.1:{web_port}-:8443' if index==0 else ''), '-device', f'virtio-net-pci,netdev=n{index},romfile=']
    child = pexpect.spawn(args[0], args[1:], encoding='utf-8', timeout=360)
    log = (ROOT / 'dist/alpha9-iso-console.log').open('w'); child.logfile = log
    try:
        child.expect(r'login:'); child.sendline('root'); child.expect('Password:'); child.sendline('igneus')
        child.expect(r'root@[^\r\n]*[#$] ')
        child.sendline("export PS1='MIQA# '")
        prompt = r'(?m)(?:^|\r|\n|\x1b\[\?2004h)MIQA# '
        child.expect(prompt)
        checks.append('UEFI live ISO boot and console login'); print('PASS ' + checks[-1], flush=True)

        def command(text, timeout=180):
            child.sendline(text + "; printf '\\n__MIQA_END__:%s\\n' \"$?\"")
            child.expect(r'\r*\n__MIQA_END__:(\d+)\r*\n', timeout=timeout)
            output = child.before; status = int(child.match.group(1)); child.expect(prompt)
            if status:
                raise RuntimeError('Guest command failed: ' + output[-5000:])
            return output

        trust_probe = """import hashlib,json,subprocess
from pathlib import Path
p=json.loads(Path('/usr/share/doc/murus-igneus/bootstrap-provenance.json').read_text())
assert p['package']=='devuan-keyring' and p['verified_installed_files'] is True
assert p['seed_image']=='dyne/devuan:excalibur@sha256:10f6138df94c08164f300a2f35f96cd8c8966fc4948550dbe0485149d020248f'
assert subprocess.check_output(['dpkg-query','-W','-f=${Version}','devuan-keyring'],text=True)==p['version']
assert p['keyfiles_sha256']
for name,digest in p['keyfiles_sha256'].items():
 assert name.startswith(('/usr/share/keyrings/devuan','/etc/apt/trusted.gpg.d/devuan')) and name.endswith('.gpg')
 assert hashlib.sha256(Path(name).read_bytes()).hexdigest()==digest,name
print('Installed Devuan trust anchors verified')
"""
        payload = base64.b64encode(gzip.compress(trust_probe.encode())).decode()
        command("python3 -c \"import base64,gzip;exec(gzip.decompress(base64.b64decode('" + payload + "')))\"")
        checks.append('Installed Devuan archive trust package and keyfiles match the recorded public builder provenance'); print('PASS ' + checks[-1],flush=True)

        # Read the real HTTPS backend, then preview a complete native VLAN plan.
        probe = '''import base64,http.client,json,ssl,time,urllib.request
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
def api(path,data=None):
 h={'Authorization':'Basic '+base64.b64encode(b'admin:igneus').decode()}
 if data is not None:h.update({'Content-Type':'application/json','X-Murus-Igneus-CSRF':csrf})
 r=opener.open(urllib.request.Request('https://127.0.0.1:8443/api/'+path,headers=h,data=json.dumps(data).encode() if data is not None else None),timeout=30)
 return json.load(r)
for i in range(60):
 try:s=api('status');break
 except OSError:time.sleep(2)
else:raise AssertionError('HTTPS backend not ready')
assert s['version']=='0.3.0-alpha.9',s
# A separate loopback source verifies the real TLS/Basic gate without locking out the QA client.
def auth_probe(password):
 conn=http.client.HTTPSConnection('127.0.0.1',8443,context=ssl._create_unverified_context(),source_address=('127.0.0.2',0),timeout=10)
 header='Basic '+base64.b64encode(('admin:'+password).encode()).decode()
 conn.request('GET','/api/status',headers={'Authorization':header});r=conn.getresponse();result=(r.status,r.getheader('Retry-After'));r.read();conn.close();return result
for attempt in range(10):assert auth_probe('controlled-incorrect-password')[0]==401
assert auth_probe('igneus')==(429,'60')
assert api('status')['version']=='0.3.0-alpha.9'
print('ISO_HTTPS_BASIC_THROTTLE_OK')
csrf=s['csrf'];c=api('configuration')['configuration'];assert 'dns' in c and 'dhcp' in c and 'port_forwards' in c,c
c['interfaces']=[{'name':'TRUNK','device':'eth2','address':''},{'name':'LAN','device':'eth2.20','address':'198.51.100.1/24','parent':'eth2','vlan_id':20}]
p=api('configuration/preview',{'configuration':c});assert p['ready'],p
assert p['network_ops'][0]['kind']=='vlan',p
print('ISO_HTTPS_ALPHA8_NATIVE_VLAN_PREVIEW_OK')
c=api('configuration')['configuration']
c['interfaces']=[{'name':'WAN','device':'eth1','address':'198.18.0.1/24'},{'name':'LAN','device':'eth2','address':'10.80.1.1/24'}]
c['ipsec']=[{'id':1,'enabled':True,'public_device':'eth1','remote_ip':'198.18.0.2','local_id':'iso-local','remote_id':'iso-remote','local_network':'10.80.1.0/24','remote_network':'10.80.2.0/24','psk':'LabOnlyRootServiceSecret123456'}]
p=api('configuration/preview',{'configuration':c});assert p['ready'],p
applied=api('apply',{'plan_id':p['plan_id']});assert applied['id'],applied
try:
 h=api('enterprise');assert h['ipsec_running'],h
finally:
 api('rollback',{})
assert not api('enterprise')['ipsec_running']
assert api('status')['pending'] is None
print('ISO_ROOT_IPSEC_APPLY_ROLLBACK_OK')
c['ipsec']=[]
c['parental']={'enabled':True,'timezone':'Europe/Rome','upstream_servers':['1.1.1.1'],'profiles':[{'id':1,'name':'ISO parental','enabled':True,'interface':'LAN','clients':['10.80.1.99'],'categories':[],'services':['instagram'],'blocked_domains':['blocked.test'],'allowed_domains':[],'windows':[],'paused':False,'enforce_dns':True,'block_quic':False}]}
p=api('configuration/preview',{'configuration':c});assert p['ready'],p
api('apply',{'plan_id':p['plan_id']})
try:
 h=api('parental');assert h['running'] and h['profiles'][0]['resolver_running'],h
finally:
 api('rollback',{})
assert not api('parental')['running']
print('ISO_ROOT_PARENTAL_APPLY_ROLLBACK_OK')
'''
        encoded = base64.b64encode(probe.encode()).decode()
        command("python3 -c \"import base64;exec(base64.b64decode('" + encoded + "'))\"")
        checks.append('Real HTTPS authentication rejects ten wrong passwords, throttles further credentials and isolates peers'); print('PASS ' + checks[-1], flush=True)
        checks.append('Real HTTPS backend alpha.9, empty setup and native VLAN preview'); print('PASS ' + checks[-1], flush=True)
        checks.append('Real appliance HTTPS preview/apply starts owned strongSwan and rollback stops it'); print('PASS ' + checks[-1], flush=True)
        checks.append('Real appliance HTTPS parental apply starts resolver and rollback stops it'); print('PASS ' + checks[-1], flush=True)
        remote=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
        def web(path,data=None):
            headers={'Authorization':'Basic '+base64.b64encode(b'admin:igneus').decode()}
            if data is not None:headers.update({'Content-Type':'application/json','X-Murus-Igneus-CSRF':remote_csrf})
            request=urllib.request.Request(f'https://127.0.0.1:{web_port}/'+path,headers=headers,data=json.dumps(data).encode() if data is not None else None)
            with remote.open(request,timeout=20) as response:return response.read()
        assert b'install-home' in web('')
        remote_csrf=json.loads(web('api/status'))['csrf']
        inventory=json.loads(web('api/installer'));assert inventory['live'] and any(d['path']=='/dev/vda' for d in inventory['disks']),inventory
        preview=json.loads(web('api/installer/preview',{'disk':'/dev/vda'}));assert preview['confirmation']=='CANCELLA /dev/vda',preview
        checks.append('Management HTTPS and live installer disk preview are reachable from outside the guest through the management NIC');print('PASS '+checks[-1],flush=True)
        info=command('murus-info && murus-install --list')
        assert 'https://' in info and ':8443' in info and '/dev/vda' in info and 'murus-install' in info,info
        checks.append('Installed console helpers show real web URLs and list the blank installation disk without writing it');print('PASS '+checks[-1],flush=True)
        command('mkdir -p /tmp/murus-qa/tools /tmp/murus-qa/src && cp -a /usr/lib/murus-igneus /tmp/murus-qa/src/murus_igneus')
        status_payload=base64.b64encode(gzip.compress((ROOT/'tools/validate-status-runtime.py').read_bytes())).decode()
        command("python3 -c \"import base64,gzip;from pathlib import Path;Path('/tmp/murus-qa/tools/validate-status-runtime.py').write_bytes(gzip.decompress(base64.b64decode('"+status_payload+"')))\"")
        command('MURUS_LAB=YES python3 /tmp/murus-qa/tools/validate-status-runtime.py')
        checks.append('Installed management HTTPS polling stays responsive under the transaction lock; mutations remain serialized');print('PASS '+checks[-1],flush=True)
        payload = base64.b64encode(gzip.compress((ROOT / 'tools/validate-native-networking.py').read_bytes())).decode()
        command(': > /tmp/murus-qa/runtime.b64')
        for pos in range(0, len(payload), 1000):
            command("printf '%s' '" + payload[pos:pos + 1000] + "' >> /tmp/murus-qa/runtime.b64")
        command("python3 -c \"import base64,gzip;from pathlib import Path;Path('/tmp/murus-qa/tools/validate-native-networking.py').write_bytes(gzip.decompress(base64.b64decode(Path('/tmp/murus-qa/runtime.b64').read_bytes())))\"")
        output = command('MURUS_LAB=YES unshare --mount --net --fork python3 /tmp/murus-qa/tools/validate-native-networking.py', timeout=360)
        runtime = json.loads(re.search(r'MIQA_JSON=(\{[^\r\n]+\})', command("python3 -c \"import json;print('MIQA_JSON='+json.dumps(json.load(open('/tmp/murus-qa/dist/native-networking-qa.json'))))\"")).group(1))
        assert runtime['success'] and len(runtime['checks']) == 13, output
        checks += ['Devuan ISO: ' + item for item in runtime['checks']]
        print('PASS real packet suite on original ISO: ' + str(len(runtime['checks'])) + ' checks', flush=True)
        payload = base64.b64encode(gzip.compress((ROOT / 'tools/validate-enterprise-runtime.py').read_bytes())).decode()
        command(': > /tmp/murus-qa/enterprise.b64')
        for pos in range(0, len(payload), 1000):
            command("printf '%s' '" + payload[pos:pos + 1000] + "' >> /tmp/murus-qa/enterprise.b64")
        command("python3 -c \"import base64,gzip;from pathlib import Path;Path('/tmp/murus-qa/tools/validate-enterprise-runtime.py').write_bytes(gzip.decompress(base64.b64decode(Path('/tmp/murus-qa/enterprise.b64').read_bytes())))\"")
        command('MURUS_LAB=YES unshare --mount --net --fork python3 /tmp/murus-qa/tools/validate-enterprise-runtime.py', timeout=360)
        enterprise_report = json.loads(re.search(r'MIQA_ENTERPRISE=(\{[^\r\n]+\})', command("python3 -c \"import json;print('MIQA_ENTERPRISE='+json.dumps(json.load(open('/tmp/murus-qa/dist/enterprise-runtime-qa.json'))))\"")).group(1))
        assert enterprise_report['count'] == 9, enterprise_report
        checks += ['Devuan ISO: ' + item['name'] for item in enterprise_report['checks']]
        print('PASS real IKEv2 and dual WAN suite on original ISO: 9 checks', flush=True)
        payload = base64.b64encode(gzip.compress((ROOT / 'tools/validate-parental-runtime.py').read_bytes())).decode()
        command(': > /tmp/murus-qa/parental.b64')
        for pos in range(0, len(payload), 1000):
            command("printf '%s' '" + payload[pos:pos + 1000] + "' >> /tmp/murus-qa/parental.b64")
        command("python3 -c \"import base64,gzip;from pathlib import Path;Path('/tmp/murus-qa/tools/validate-parental-runtime.py').write_bytes(gzip.decompress(base64.b64decode(Path('/tmp/murus-qa/parental.b64').read_bytes())))\"")
        command('MURUS_LAB=YES unshare --mount --net --fork python3 /tmp/murus-qa/tools/validate-parental-runtime.py', timeout=360)
        parental_report = json.loads(re.search(r'MIQA_PARENTAL=(\{[^\r\n]+\})', command("python3 -c \"import json;print('MIQA_PARENTAL='+json.dumps(json.load(open('/tmp/murus-qa/dist/parental-runtime-qa.json'))))\"")).group(1))
        assert parental_report['success'] and len(parental_report['checks']) == 23, parental_report
        checks += ['Devuan ISO: ' + item for item in parental_report['checks']]
        print('PASS parental packet suite on original ISO: 23 checks', flush=True)
        # Install only onto the fresh sparse disk created by this disposable QEMU fixture.
        child.sendline("murus-install --disk /dev/vda; printf '\\n__MIQA_INSTALL_END__:%s\\n' \"$?\"")
        child.expect(r'Conferma \(Invio per annullare\): ',timeout=30)
        child.sendline('CANCELLA /dev/vda')
        child.expect(r'\r*\n__MIQA_INSTALL_END__:(\d+)\r*\n',timeout=900)
        install_output=child.before;status=int(child.match.group(1));child.expect(prompt)
        assert status==0 and 'INSTALLAZIONE COMPLETATA' in install_output,install_output[-6000:]
        checks.append('Console installer explicitly confirms and installs onto the disposable 16 GiB virtual disk');print('PASS '+checks[-1],flush=True)
        child.sendline('poweroff'); child.expect(pexpect.EOF, timeout=300)
        checks.append('Graceful live VM poweroff'); print('PASS ' + checks[-1], flush=True)
        child.close()
        disk_args=args.copy();cd=disk_args.index('-cdrom');del disk_args[cd:cd+2];disk_args[disk_args.index('-boot')+1]='c'
        child=pexpect.spawn(disk_args[0],disk_args[1:],encoding='utf-8',timeout=360);child.logfile=log
        child.expect(r'login:');child.sendline('root');child.expect('Password:');child.sendline('igneus');child.expect(r'root@[^\r\n]*[#$] ')
        child.sendline("export PS1='MIQA# '");child.expect(prompt)
        assert 'boot=live' not in command('cat /proc/cmdline')
        for attempt in range(60):
            try:
                status=json.loads(web('api/status'))
                if status['version']=='0.3.0-alpha.9':break
            except OSError:pass
            time.sleep(2)
        else:raise AssertionError('Installed disk HTTPS unavailable')
        assert json.loads(web('api/installer'))['live'] is False
        checks.append('Installed disk boots independently with the ISO detached and serves management HTTPS through the NIC');print('PASS '+checks[-1],flush=True)
        child.sendline('poweroff');child.expect(pexpect.EOF,timeout=300)
        checks.append('Graceful installed VM poweroff');print('PASS '+checks[-1],flush=True)
        with iso.open('rb') as file:
            digest = hashlib.file_digest(file, 'sha256').hexdigest()
        result = {'success': True, 'checks': checks, 'iso': iso.name, 'sha256': digest, 'scope': 'QEMU TCG UEFI live boot; installed product modules exercised with real packets inside isolated guest namespaces. Explicit console installation on a fresh 16 GiB virtual disk and autonomous UEFI disk boot with management HTTPS verified. No BIOS, Secure Boot or physical hardware test.'}
        (ROOT / 'dist/alpha9-iso-networking-qa.json').write_text(json.dumps(result, indent=2) + '\n')
    finally:
        if child.isalive():
            child.terminate(force=True)
        log.close()
