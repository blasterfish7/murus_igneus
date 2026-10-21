"""UEFI ISO boot and native-network acceptance in disposable QEMU. SPDX-License-Identifier: MIT."""
import base64
import gzip
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

import pexpect

ROOT = Path(__file__).resolve().parents[1]
assert os.environ.get('MURUS_LAB') == 'YES', 'Explicit disposable VM flag required'
iso = ROOT / 'dist/murus-igneus-0.3.0-alpha.4-devuan-amd64.iso'
assert iso.is_file()
firmware = Path('/usr/share/OVMF')
code = firmware / 'OVMF_CODE_4M.fd'; template = firmware / 'OVMF_VARS_4M.fd'
assert code.is_file() and template.is_file(), 'OVMF 4M required'
checks = []
with tempfile.TemporaryDirectory(prefix='murus-iso-qa-') as work:
    variables = Path(work) / 'vars.fd'; shutil.copyfile(template, variables)
    args = ['qemu-system-x86_64', '-machine', 'q35,accel=tcg', '-cpu', 'max', '-smp', '2', '-m', '2048',
            '-drive', 'if=pflash,format=raw,readonly=on,file=' + str(code), '-drive', 'if=pflash,format=raw,file=' + str(variables),
            '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot', '-boot', 'd', '-cdrom', str(iso)]
    for index in range(3):
        args += ['-netdev', f'user,id=n{index}', '-device', f'virtio-net-pci,netdev=n{index},romfile=']
    child = pexpect.spawn(args[0], args[1:], encoding='utf-8', timeout=360)
    log = (ROOT / 'dist/alpha4-iso-console.log').open('w'); child.logfile = log
    try:
        child.expect(r'login:'); child.sendline('root'); child.expect('Password:'); child.sendline('igneus')
        child.expect(r'root@[^\r\n]*[#$] ')
        child.sendline("export PS1='MIQA# '")
        prompt = r'(?m)(?:^|\r|\n|\x1b\[\?2004h)MIQA# '
        child.expect(prompt)
        checks.append('UEFI live ISO boot and console login'); print('PASS ' + checks[-1], flush=True)

        def command(text, timeout=180):
            child.sendline(text + "; printf '\\n__MIQA_END__:%s\\n' \"$?\"")
            child.expect(r'\r?\n__MIQA_END__:(\d+)\r?\n', timeout=timeout)
            output = child.before; status = int(child.match.group(1)); child.expect(prompt)
            if status:
                raise RuntimeError('Guest command failed: ' + output[-5000:])
            return output

        # Read the real HTTPS backend, then preview a complete native VLAN plan.
        probe = '''import base64,json,ssl,time,urllib.request
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
assert s['version']=='0.3.0-alpha.4',s
csrf=s['csrf'];c=api('configuration')['configuration'];assert 'dns' in c and 'dhcp' in c and 'port_forwards' in c,c
c['interfaces']=[{'name':'TRUNK','device':'eth2','address':''},{'name':'LAN','device':'eth2.20','address':'198.51.100.1/24','parent':'eth2','vlan_id':20}]
p=api('configuration/preview',{'configuration':c});assert p['ready'],p
assert p['network_ops'][0]['kind']=='vlan',p
print('ISO_HTTPS_ALPHA4_NATIVE_VLAN_PREVIEW_OK')
'''
        encoded = base64.b64encode(probe.encode()).decode()
        command("python3 -c \"import base64;exec(base64.b64decode('" + encoded + "'))\"")
        checks.append('Real HTTPS backend alpha.4, empty setup and native VLAN preview'); print('PASS ' + checks[-1], flush=True)
        command('mkdir -p /tmp/murus-qa/tools /tmp/murus-qa/src && cp -a /usr/lib/murus-igneus /tmp/murus-qa/src/murus_igneus')
        payload = base64.b64encode(gzip.compress((ROOT / 'tools/validate-native-networking.py').read_bytes())).decode()
        command(': > /tmp/murus-qa/runtime.b64')
        for pos in range(0, len(payload), 1000):
            command("printf '%s' '" + payload[pos:pos + 1000] + "' >> /tmp/murus-qa/runtime.b64")
        command("python3 -c \"import base64,gzip;from pathlib import Path;Path('/tmp/murus-qa/tools/validate-native-networking.py').write_bytes(gzip.decompress(base64.b64decode(Path('/tmp/murus-qa/runtime.b64').read_bytes())))\"")
        output = command('MURUS_LAB=YES unshare --mount --net --fork python3 /tmp/murus-qa/tools/validate-native-networking.py', timeout=360)
        runtime = json.loads(re.search(r'MIQA_JSON=(\{[^\r\n]+\})', command("python3 -c \"import json;print('MIQA_JSON='+json.dumps(json.load(open('/tmp/murus-qa/dist/native-networking-qa.json'))))\"")).group(1))
        assert runtime['success'], output
        checks += ['Devuan ISO: ' + item for item in runtime['checks']]
        print('PASS real packet suite on original ISO: ' + str(len(runtime['checks'])) + ' checks', flush=True)
        child.sendline('poweroff'); child.expect(pexpect.EOF, timeout=300)
        checks.append('Graceful live VM poweroff'); print('PASS ' + checks[-1], flush=True)
        result = {'success': True, 'checks': checks, 'iso': iso.name, 'scope': 'QEMU TCG UEFI live boot; installed product modules exercised with real packets inside isolated guest namespaces. No disk installation, Secure Boot or physical hardware test.'}
        (ROOT / 'dist/alpha4-iso-networking-qa.json').write_text(json.dumps(result, indent=2) + '\n')
    finally:
        if child.isalive():
            child.terminate(force=True)
        log.close()
