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
import subprocess
import time
import urllib.request
import urllib.error
import tempfile

import pexpect

ROOT = Path(__file__).resolve().parents[1]
assert os.environ.get('MURUS_LAB') == 'YES', 'Explicit disposable VM flag required'
iso = ROOT / 'dist/murus-igneus-0.3.0-alpha.12-devuan-amd64.iso'
assert iso.is_file()
firmware = Path('/usr/share/OVMF')
code = firmware / 'OVMF_CODE_4M.fd'; template = firmware / 'OVMF_VARS_4M.fd'
assert code.is_file() and template.is_file(), 'OVMF 4M required'
checks = []
QA_PASSWORD = 'murus-console-lab-10'
with tempfile.TemporaryDirectory(prefix='murus-iso-qa-') as work:
    disk=Path(work)/'install-disk.raw'
    with disk.open('wb') as file:file.truncate(16*1024**3)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0));web_port=listener.getsockname()[1]
        with socket.socket() as ssh_listener:
            ssh_listener.bind(('127.0.0.1',0));ssh_port=ssh_listener.getsockname()[1]
    variables = Path(work) / 'vars.fd'; shutil.copyfile(template, variables)
    args = ['qemu-system-x86_64', '-machine', 'q35,accel=tcg', '-cpu', 'max', '-smp', '2', '-m', '2048',
            '-drive', 'if=pflash,format=raw,readonly=on,file=' + str(code), '-drive', 'if=pflash,format=raw,file=' + str(variables),
            '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot', '-boot', 'd', '-cdrom', str(iso)]
    args += ['-object','iothread,id=storage-io',
             '-device','virtio-scsi-pci,id=storage-scsi,iothread=storage-io',
             '-drive','file='+str(disk)+',if=none,id=storage-disk,format=raw',
             '-device','scsi-hd,bus=storage-scsi.0,drive=storage-disk']
    for index in range(3):
        args += ['-netdev', f'user,id=n{index}'+(f',hostfwd=tcp:127.0.0.1:{web_port}-:8443,hostfwd=tcp:127.0.0.1:{ssh_port}-:22' if index==0 else ''), '-device', f'virtio-net-pci,netdev=n{index},romfile=']
    child = pexpect.spawn(args[0], args[1:], encoding='utf-8', timeout=360)
    log = (ROOT / 'dist/alpha12-iso-console.log').open('w'); child.logfile = log
    try:
        child.expect(r'login:',timeout=360)  # Drain serial boot output before probing HTTPS.
        # Complete the required password setup through external HTTPS before console login.
        credential_headers={'Authorization':'Basic '+base64.b64encode(b'admin:igneus').decode()}
        external='https://127.0.0.1:'+str(web_port)+'/api/'
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
        for attempt in range(180):
            try:
                with opener.open(urllib.request.Request(external+'auth/status',headers=credential_headers),timeout=3) as response:initial=json.load(response)
                break
            except OSError:time.sleep(2)
        else:raise AssertionError('Initial HTTPS setup unavailable')
        assert initial['password_change_required'] and initial['shared_console_password'],initial
        try:opener.open(urllib.request.Request(external+'configuration',headers=credential_headers),timeout=5)
        except urllib.error.HTTPError as error:assert error.code==403
        else:raise AssertionError('Configuration available before mandatory password change')
        credential_headers.update({'Content-Type':'application/json','X-Murus-Igneus-CSRF':initial['csrf']})
        body=json.dumps({'password':QA_PASSWORD,'confirmation':QA_PASSWORD}).encode()
        with opener.open(urllib.request.Request(external+'auth/password',headers=credential_headers,data=body),timeout=30) as response:assert json.load(response)['ok']
        checks.append('Mandatory first-login password setup blocks configuration and changes the shared web/console password over real HTTPS');print('PASS '+checks[-1],flush=True)
        child.sendline('root'); child.expect('Password:'); child.sendline(QA_PASSWORD)
        child.expect(r'root@[^\r\n]*[#$] ')
        child.sendline("export PS1='MIQA# '")
        prompt = r'(?m)(?:^|\r|\n|\x1b\[\?2004h)MIQA# '
        child.expect(prompt)
        checks.append('UEFI live ISO boot and console login'); print('PASS ' + checks[-1], flush=True)

        previous_password=QA_PASSWORD
        child.sendline('passwd');child.expect(r'New password:',timeout=30)
        QA_PASSWORD='murus-console-next-10';child.sendline(QA_PASSWORD)
        child.expect(r'Retype new password:',timeout=30);child.sendline(QA_PASSWORD);child.expect(prompt,timeout=30)
        new_headers={'Authorization':'Basic '+base64.b64encode(('admin:'+QA_PASSWORD).encode()).decode()}
        with opener.open(urllib.request.Request(external+'auth/status',headers=new_headers),timeout=10) as response:assert not json.load(response)['password_change_required']
        try:opener.open(urllib.request.Request(external+'auth/status',headers={'Authorization':'Basic '+base64.b64encode(('admin:'+previous_password).encode()).decode()}),timeout=10)
        except urllib.error.HTTPError as error:assert error.code==401
        else:raise AssertionError('Old web password survived a console password change')
        checks.append('Console passwd changes are immediately recognized by web authentication and reject the previous password');print('PASS '+checks[-1],flush=True)

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
        probe = 'QA_PASSWORD='+repr(QA_PASSWORD)+'\n'+'''import base64,http.client,json,ssl,time,urllib.request
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
def api(path,data=None):
 h={'Authorization':'Basic '+base64.b64encode(('admin:'+QA_PASSWORD).encode()).decode()}
 if data is not None:h.update({'Content-Type':'application/json','X-Murus-Igneus-CSRF':csrf})
 r=opener.open(urllib.request.Request('https://127.0.0.1:8443/api/'+path,headers=h,data=json.dumps(data).encode() if data is not None else None),timeout=30)
 return json.load(r)
for i in range(60):
 try:s=api('status');break
 except OSError:time.sleep(2)
else:raise AssertionError('HTTPS backend not ready')
assert s['version']=='0.3.0-alpha.12',s
# A separate loopback source verifies the real TLS/Basic gate without locking out the QA client.
def auth_probe(password):
 conn=http.client.HTTPSConnection('127.0.0.1',8443,context=ssl._create_unverified_context(),source_address=('127.0.0.2',0),timeout=10)
 header='Basic '+base64.b64encode(('admin:'+password).encode()).decode()
 conn.request('GET','/api/status',headers={'Authorization':header});r=conn.getresponse();result=(r.status,r.getheader('Retry-After'));r.read();conn.close();return result
for attempt in range(10):assert auth_probe('controlled-incorrect-password')[0]==401
assert auth_probe(QA_PASSWORD)==(429,'60')
assert api('status')['version']=='0.3.0-alpha.12'
print('ISO_HTTPS_BASIC_THROTTLE_OK')
devices=api('interfaces')['interfaces'];assert {row['device'] for row in devices}>={'eth0','eth1','eth2'},devices
mgmt=next(row for row in devices if row['device']==s['management']);assert mgmt['management'] and not mgmt['configurable'] and mgmt['addresses'],mgmt
assert all(row['mac'] for row in devices),devices
print('ISO_KERNEL_INTERFACE_INVENTORY_OK')
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
        checks.append('Real HTTPS interface inventory includes all three Virtio NICs, management reservation, MAC and actual addresses'); print('PASS ' + checks[-1], flush=True)
        checks.append('Real HTTPS backend alpha.12, empty setup and native VLAN preview'); print('PASS ' + checks[-1], flush=True)
        checks.append('Real appliance HTTPS preview/apply starts owned strongSwan and rollback stops it'); print('PASS ' + checks[-1], flush=True)
        checks.append('Real appliance HTTPS parental apply starts resolver and rollback stops it'); print('PASS ' + checks[-1], flush=True)
        remote=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
        def web(path,data=None):
            headers={'Authorization':'Basic '+base64.b64encode(('admin:'+QA_PASSWORD).encode()).decode()}
            if data is not None:headers.update({'Content-Type':'application/json','X-Murus-Igneus-CSRF':remote_csrf})
            request=urllib.request.Request(f'https://127.0.0.1:{web_port}/'+path,headers=headers,data=json.dumps(data).encode() if data is not None else None)
            with remote.open(request,timeout=20) as response:return response.read()
        assert b'install-home' in web('')
        remote_csrf=json.loads(web('api/status'))['csrf']
        inventory=json.loads(web('api/installer'));assert inventory['live'] and any(d['path']=='/dev/sda' for d in inventory['disks']),inventory
        preview=json.loads(web('api/installer/preview',{'disk':'/dev/sda'}));assert preview['confirmation']=='CANCELLA /dev/sda',preview
        checks.append('Management HTTPS and live installer disk preview are reachable from outside the guest through the management NIC');print('PASS '+checks[-1],flush=True)
        command('test -x /usr/sbin/qemu-ga && test ! -e /run/murus-guest-agent.pid')
        checks.append('Live boot without a guest-agent channel leaves qemu-ga stopped')
        info=command('murus-info && murus-install --list')
        assert 'https://' in info and ':8443' in info and '/dev/sda' in info and 'murus-install' in info,info
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
        assert parental_report['success'] and len(parental_report['checks']) == 24, parental_report
        checks += ['Devuan ISO: ' + item for item in parental_report['checks']]
        print('PASS parental packet suite on original ISO: 24 checks', flush=True)
        payload = base64.b64encode(gzip.compress((ROOT / 'tools/validate-dhcp-client-runtime.py').read_bytes())).decode()
        command(': > /tmp/murus-qa/dhcp-client.b64')
        for pos in range(0,len(payload),1000):
            command("printf '%s' '"+payload[pos:pos+1000]+"' >> /tmp/murus-qa/dhcp-client.b64")
        command("python3 -c \"import base64,gzip;from pathlib import Path;Path('/tmp/murus-qa/tools/validate-dhcp-client-runtime.py').write_bytes(gzip.decompress(base64.b64decode(Path('/tmp/murus-qa/dhcp-client.b64').read_bytes())))\"")
        command('MURUS_LAB=YES unshare --mount --net --fork python3 /tmp/murus-qa/tools/validate-dhcp-client-runtime.py',timeout=300)
        dhcp_report=json.loads(re.search(r'MIQA_DHCP=(\{[^\r\n]+\})',command("python3 -c \"import json;print('MIQA_DHCP='+json.dumps(json.load(open('/tmp/murus-qa/dist/dhcp-client-runtime-qa.json'))))\"")).group(1))
        assert dhcp_report['success'] and len(dhcp_report['checks'])==6,dhcp_report
        checks += ['Devuan ISO: '+item for item in dhcp_report['checks']]
        print('PASS DHCP WAN and anti-lockout suite on original ISO: 6 checks',flush=True)
        # Install only onto the fresh sparse disk created by this disposable QEMU fixture.
        child.sendline("murus-install --disk /dev/sda; printf '\\n__MIQA_INSTALL_END__:%s\\n' \"$?\"")
        child.expect(r'Conferma \(Invio per annullare\): ',timeout=30)
        child.sendline('CANCELLA /dev/sda')
        child.expect(r'\r*\n__MIQA_INSTALL_END__:(\d+)\r*\n',timeout=900)
        install_output=child.before;status=int(child.match.group(1));child.expect(prompt)
        assert status==0 and 'INSTALLAZIONE COMPLETATA' in install_output,install_output[-6000:]
        checks.append('Console installer explicitly confirms and installs onto the disposable 16 GiB VirtIO SCSI disk with an I/O thread');print('PASS '+checks[-1],flush=True)
        child.sendline('poweroff'); child.expect(pexpect.EOF, timeout=300)
        checks.append('Graceful live VM poweroff'); print('PASS ' + checks[-1], flush=True)
        child.close()
        disk_args=args.copy();cd=disk_args.index('-cdrom');del disk_args[cd:cd+2];disk_args[disk_args.index('-boot')+1]='c'
        agent_socket = Path(work)/'qga.sock'
        disk_args += ['-device','virtio-serial-pci',
                      '-chardev',f'socket,path={agent_socket},server=on,wait=off,id=guest-agent',
                      '-device','virtserialport,chardev=guest-agent,name=org.qemu.guest_agent.0']
        child=pexpect.spawn(disk_args[0],disk_args[1:],encoding='utf-8',timeout=360);child.logfile=log
        child.expect(r'login:');child.sendline('root');child.expect('Password:');child.sendline(QA_PASSWORD);child.expect(r'root@[^\r\n]*[#$] ')
        child.sendline("export PS1='MIQA# '");child.expect(prompt)
        assert 'boot=live' not in command('cat /proc/cmdline')
        for attempt in range(60):
            try:
                status=json.loads(web('api/status'))
                if status['version']=='0.3.0-alpha.12':break
            except OSError:pass
            time.sleep(2)
        else:raise AssertionError('Installed disk HTTPS unavailable')
        assert json.loads(web('api/installer'))['live'] is False
        checks.append('Installed disk boots independently with the ISO detached and serves management HTTPS through the NIC');print('PASS '+checks[-1],flush=True)
        def agent(execute, arguments=None, reply=True):
            message = {'execute':execute}
            if arguments is not None:
                message['arguments'] = arguments
            with socket.socket(socket.AF_UNIX) as channel:
                channel.settimeout(5)
                channel.connect(str(agent_socket))
                channel.sendall(json.dumps(message).encode() + b'\n')
                if not reply:
                    return None
                with channel.makefile('rb') as stream:
                    result = json.loads(stream.readline())
                assert 'return' in result, result
                return result['return']
        for attempt in range(12):
            try:
                assert agent('guest-ping') == {}
                break
            except (OSError, ValueError):
                time.sleep(1)
        else:
            raise AssertionError('Installed QEMU Guest Agent did not answer ping')
        guest_nics = agent('guest-network-get-interfaces')
        assert {'eth0','eth1','eth2'} <= {row['name'] for row in guest_nics}, guest_nics
        assert any(a['ip-address-type']=='ipv4' for row in guest_nics if row['name']=='eth0'
                   for a in row.get('ip-addresses', [])), guest_nics
        commands = {row['name']:row['enabled'] for row in agent('guest-info')['supported_commands']}
        assert commands.get('guest-shutdown') and not commands.get('guest-exec') and not commands.get('guest-fsfreeze-freeze')
        checks.append('Installed QEMU Guest Agent answers ping and reports management IPv4 via VirtIO; exec and freeze disabled')
        print('PASS '+checks[-1],flush=True)
        key = Path(work)/'qa-ssh'
        wrong_key = Path(work)/'qa-ssh-wrong'
        for path in (key, wrong_key):
            subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(path)],check=True)
        def ssh(identity=key):
            return subprocess.run(['ssh','-F','/dev/null','-p',str(ssh_port),'-i',str(identity),
                                   '-oBatchMode=yes','-oIdentitiesOnly=yes','-oConnectTimeout=4',
                                   '-oStrictHostKeyChecking=accept-new','-oUserKnownHostsFile='+str(Path(work)/'qa-known-hosts'),
                                   'root@127.0.0.1','printf MURUS_SSH_OK'],capture_output=True,text=True,timeout=8)
        ssh_state=json.loads(web('api/admin-ssh'))
        assert ssh_state == {'available':True,'live':False,'running':False},ssh_state
        assert ssh().returncode != 0
        checks.append('OpenSSH is present on installed Devuan but TCP 22 does not offer SSH by default')
        remote_csrf=json.loads(web('api/status'))['csrf']
        initial_config=json.loads(web('api/configuration'))['configuration']
        def apply_config(config,confirm=False):
            plan=json.loads(web('api/configuration/preview',{'configuration':config}))
            assert plan['ready'],plan['blockers']
            ident=json.loads(web('api/apply',{'plan_id':plan['plan_id']}))['id']
            if confirm:assert json.loads(web('api/confirm',{'id':ident}))['ok']
        enabled={**initial_config,'admin_ssh':{'enabled':True,'sources':['10.0.2.2/32'],
                                               'keys':[key.with_suffix('.pub').read_text().strip()]}}
        apply_config(enabled,True)
        success=ssh()
        assert success.returncode==0 and success.stdout=='MURUS_SSH_OK',success.stderr
        rejected=ssh(wrong_key)
        assert rejected.returncode!=0 and 'Permission denied (publickey)' in rejected.stderr,rejected.stderr
        checks.append('Real HTTPS apply enables OpenSSH from the management IPv4 with the authorized Ed25519 key only')
        denied={**enabled,'admin_ssh':{**enabled['admin_ssh'],'sources':['198.51.100.10/32']}}
        apply_config(denied)
        assert ssh().returncode!=0 and json.loads(web('api/admin-ssh'))['running']
        assert json.loads(web('api/rollback',{}))['ok']
        assert ssh().stdout=='MURUS_SSH_OK'
        checks.append('Actual SSH traffic from outside the allowlist is denied and web rollback restores the previous SSH policy')
        command('rc-service murus-igneus restart',timeout=90)
        remote_csrf=json.loads(web('api/status'))['csrf']
        assert ssh().stdout=='MURUS_SSH_OK'
        apply_config(initial_config,True)
        assert not json.loads(web('api/admin-ssh'))['running'] and ssh().returncode!=0
        command('rm -f /etc/murus_igneus/ssh_host_ed25519_key /etc/murus_igneus/ssh_host_ed25519_key.pub')
        checks.append('Confirmed SSH access and host identity survive restart; disabling closes TCP 22')
        print('PASS SSH installed-disk suite: 4 checks',flush=True)
        command(': > /tmp/murus-updates-runtime.b64')
        updates_payload = base64.b64encode(gzip.compress((ROOT/'tools/validate-updates-runtime.py').read_bytes())).decode()
        for pos in range(0,len(updates_payload),1000):
            command("printf '%s' '"+updates_payload[pos:pos+1000]+"' >> /tmp/murus-updates-runtime.b64")
        command("python3 -c \"import base64,gzip;from pathlib import Path;Path('/tmp/validate-updates-runtime.py').write_bytes(gzip.decompress(base64.b64decode(Path('/tmp/murus-updates-runtime.b64').read_bytes())))\"")
        output = command('MURUS_LAB=YES MURUS_UPDATE_DISPOSABLE_VM=YES MURUS_QA_PASSWORD='+QA_PASSWORD+' python3 /tmp/validate-updates-runtime.py', timeout=900)
        update_report = json.loads(re.search(r'MIQA_UPDATES=(\{[^\r\n]+\})',output).group(1))
        assert update_report['success'] and len(update_report['checks'])==6,update_report
        for item in update_report['checks']:
            checks.append('Installed update: '+item);print('PASS '+checks[-1],flush=True)
        agent('guest-shutdown',{'mode':'powerdown'},reply=False)
        child.expect(pexpect.EOF,timeout=300)
        checks.append('Graceful installed VM poweroff via QEMU Guest Agent');print('PASS '+checks[-1],flush=True)
        with iso.open('rb') as file:
            digest = hashlib.file_digest(file, 'sha256').hexdigest()
        result = {'success': True, 'checks': checks, 'iso': iso.name, 'sha256': digest, 'scope': 'QEMU TCG UEFI live boot; installed product modules exercised with real packets inside isolated guest namespaces. Explicit console installation on a fresh 16 GiB VirtIO SCSI disk with an I/O thread and autonomous UEFI disk boot with management HTTPS verified. No BIOS, Secure Boot or physical hardware test.'}
        (ROOT / 'dist/alpha12-iso-networking-qa.json').write_text(json.dumps(result, indent=2) + '\n')
    finally:
        if child.isalive():
            child.terminate(force=True)
        log.close()
