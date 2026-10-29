#!/usr/bin/env python3
"""Real signed-DEB update/recovery acceptance; destructive DISPOSABLE VM ONLY. MIT."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
import ssl

assert os.environ.get('MURUS_LAB') == 'YES'
assert os.environ.get('MURUS_UPDATE_DISPOSABLE_VM') == 'YES'
assert os.geteuid() == 0
assert not Path('/etc/murus_igneus/live-image').exists(), 'Installed disk required'
assert 'MURUS_ROOT' in subprocess.check_output(['findmnt','-n','-o','LABEL','/'],text=True)
sys.path.insert(0,'/usr/lib/murus-igneus')
import updates
assert updates.compatible_host()
assert not updates.blocked()
assert not updates.TRUST_KEY.exists(), 'Lab must not replace an existing trust key'
checks = []
original_version = updates.installed_version()
original_shadow = next(line for line in Path('/etc/shadow').read_text().splitlines() if line.startswith('root:'))
active = updates.STATE/'active.json'
original_config = active.read_bytes() if active.exists() else None
password = os.environ['MURUS_QA_PASSWORD']
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))


def api(path, data=None):
    headers = {'Authorization':'Basic '+base64.b64encode(('admin:'+password).encode()).decode()}
    if data is not None:
        access = api('auth/status')
        headers.update({'Content-Type':'application/json','X-Murus-Igneus-CSRF':access['csrf']})
    request = urllib.request.Request('https://127.0.0.1:8443/api/'+path,
                                     data=None if data is None else json.dumps(data).encode(),headers=headers)
    with opener.open(request,timeout=20) as response:
        return json.load(response)


def wait_job():
    deadline = time.monotonic()+360
    while time.monotonic() < deadline:
        job = updates.inventory()['job']
        if job and job['state'] not in updates.ACTIVE_STATES and not updates.busy():
            return job
        time.sleep(1)
    raise AssertionError('Update worker did not complete')


def start(path, data):
    try:
        api(path,data)
    except OSError:
        # OpenRC may stop the web listener immediately after worker handoff.
        assert (updates.read(updates.CACHE/'status.json') or {}).get('state') in updates.ACTIVE_STATES
    return wait_job()


def unchanged():
    assert original_shadow == next(line for line in Path('/etc/shadow').read_text().splitlines() if line.startswith('root:'))
    assert original_config == (active.read_bytes() if active.exists() else None)
    assert api('auth/status')['shared_console_password']


with tempfile.TemporaryDirectory(prefix='murus-update-runtime-') as temporary:
    work = Path(temporary)
    updates.command(['openssl','genpkey','-algorithm','ED25519','-out',str(work/'private')])
    updates.command(['openssl','pkey','-in',str(work/'private'),'-pubout','-out',str(updates.TRUST_KEY)])
    updates.TRUST_KEY.chmod(0o600)
    updates.command(['dpkg-repack','murus-igneus'],cwd=work)
    original = next(work.glob('murus-igneus_*.deb'))
    def bundle(suffix, fail=False):
        root = work/suffix; root.mkdir()
        tree = root/'tree'
        updates.command(['dpkg-deb','-R',str(original),str(tree)])
        control = tree/'DEBIAN/control'
        version = original_version+'+'+suffix
        control.write_text('\n'.join('Version: '+version if line.startswith('Version:') else line for line in control.read_text().splitlines())+'\n')
        if fail:
            (tree/'DEBIAN/postinst').write_text('#!/bin/sh\nexit 23\n')
            (tree/'DEBIAN/postinst').chmod(0o755)
        package = root/'murus-igneus.deb'
        updates.command(['dpkg-deb','--build',str(tree),str(package)])
        meta = {'schema':1,'package':'murus-igneus','version':version,'sha256':hashlib.sha256(package.read_bytes()).hexdigest()}
        (root/'manifest.json').write_text(json.dumps(meta))
        updates.command(['openssl','pkeyutl','-sign','-inkey',str(work/'private'),'-rawin','-in',str(root/'manifest.json'),'-out',str(root/'manifest.sig')])
        return {'files':{name:base64.b64encode((root/name).read_bytes()).decode() for name in ('manifest.json','manifest.sig','murus-igneus.deb')}}
    good = bundle('qa1')
    tampered = {'files':{**good['files'],'murus-igneus.deb':base64.b64encode(b'altered').decode()}}
    try:
        api('updates/stage',tampered)
        raise AssertionError('Tampered package was accepted')
    except urllib.error.HTTPError as exc:
        assert exc.code == 400
        assert 'Checksum' in json.loads(exc.read())['error']
    checks.append('Actual HTTPS staging rejects a DEB whose digest differs from the Ed25519-signed manifest')
    preview = api('updates/stage',good)
    result = start('updates/install',{'id':preview['id'],'confirmation':preview['confirmation']})
    assert result['state'] == 'succeeded', result
    assert updates.installed_version() == original_version+'+qa1'
    unchanged()
    checks.append('Actual HTTPS upload and independent worker install a signed DEB and restart OpenRC/HTTPS with credentials and configuration preserved')
    result = start('updates/rollback',{'confirmation':'RIPRISTINA '+original_version})
    assert result['state'] == 'succeeded', result
    assert updates.installed_version() == original_version
    unchanged()
    checks.append('Actual web rollback installs the saved previous DEB and restores its configuration')
    bad = bundle('qa2',fail=True)
    preview = api('updates/stage',bad)
    result = start('updates/install',{'id':preview['id'],'confirmation':preview['confirmation']})
    assert result['state'] == 'failed' and result['recovered'], result
    assert updates.installed_version() == original_version
    unchanged()
    checks.append('A real failing dpkg postinst automatically restores the old package/configuration and returns management HTTPS')
    updates.save(updates.CACHE/'status.json',{'state':'running','action':'install','phase':'QA interruption before package write'})
    assert api('updates')['job']['state'] == 'recovery_required'
    updates.command(['rc-service','murus-igneus','stop'])
    updates.command(['/usr/sbin/murus-update','recover'])
    assert updates.inventory()['job']['state'] == 'succeeded'
    unchanged()
    checks.append('A persisted interrupted job is detected and the console recovery command restarts the actual stopped service')
    updates.TRUST_KEY.unlink()
    assert api('updates')['trust_configured'] is False
    checks.append('The temporary QA signing key is removed; no production signing key is generated or installed')
report = {'success':True,'checks':checks,'scope':'Disposable installed Devuan QEMU VM only; actual Ed25519/HTTPS/dpkg/OpenRC operations. Does not simulate a hard power cut or update the OS/kernel.'}
Path('/tmp/murus-update-runtime-qa.json').write_text(json.dumps(report))
print('MIQA_UPDATES='+json.dumps(report),flush=True)
