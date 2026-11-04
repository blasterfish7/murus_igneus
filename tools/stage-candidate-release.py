"""Preserve validated candidates; explicitly gated alpha.11 distribution after CI."""
import hashlib
import json
import os
import re
import sys
from pathlib import Path
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
REPO = os.environ['GITHUB_REPOSITORY']
assert REPO == 'blasterfish7/murus_igneus'
SHA = os.environ['GITHUB_SHA']; RUN = os.environ['GITHUB_RUN_ID']
assert len(SHA) == 40 and all(c in '0123456789abcdef' for c in SHA) and RUN.isdigit()
assert os.environ['GITHUB_EVENT_NAME'] == 'push' and os.environ['GITHUB_REF'].startswith('refs/heads/')
sys.path.insert(0,str(ROOT/'src/murus_igneus'))
from migration import VERSION
assert re.fullmatch(r'0\.3\.0-alpha\.[0-9]+',VERSION)
LABEL=VERSION.removeprefix('0.3.0-').replace('.','')
ISO_CHECKS=78
API = 'https://api.github.com/repos/' + REPO
PUBLISH = os.environ.get('MURUS_PUBLISH_RELEASE')
if PUBLISH:
    assert PUBLISH == VERSION == '0.3.0-alpha.11'
    assert os.environ['GITHUB_REF'] == 'refs/heads/main'


def request(url, data=None, method='GET', content_type='application/json'):
    if not url.startswith((API + '/', 'https://uploads.github.com/repos/' + REPO + '/releases/')):
        raise ValueError('Unexpected API destination')
    req = urllib.request.Request(url, data=data, method=method, headers={
        'Authorization': 'Bearer ' + os.environ['GH_TOKEN'], 'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': content_type})
    with urllib.request.urlopen(req, timeout=300) as response:
        return json.load(response)


out = ROOT / 'dist'
qa = json.loads((out / (LABEL+'-iso-networking-qa.json')).read_text())
assert qa['success'] and len(qa['checks']) == ISO_CHECKS, qa
iso = out / ('murus-igneus-'+VERSION+'-devuan-amd64.iso')
with iso.open('rb') as f:
    digest = hashlib.file_digest(f, 'sha256').hexdigest()
assert qa['iso'] == iso.name and qa['sha256'] == digest
assert (out / 'SHA256SUMS').read_text().strip() == digest + '  ' + iso.name
files = [iso, out / ('murus-igneus_'+VERSION.replace('-','~',1)+'_all.deb'), out / (LABEL+'-iso-networking-qa.json'),
         out / 'SHA256SUMS', out / 'packages-devuan.tsv', out / 'signature-status.txt', out / 'bootstrap-provenance.json']
if PUBLISH:
    guide = out / 'MURUS-IGNEUS-ALPHA11-LEGGIMI.md'
    guide.write_bytes((ROOT / 'docs/ALPHA11.md').read_bytes())
    update_guide = out / 'UPDATES.md'
    update_guide.write_bytes((ROOT / 'docs/UPDATES.md').read_bytes())
    files.extend([guide, update_guide])
    # The ISO validator checks the original single-ISO checksum file first.
    sums = []
    for file in files:
        if file.name != 'SHA256SUMS':
            with file.open('rb') as stream:
                sums.append(hashlib.file_digest(stream, 'sha256').hexdigest() + '  ' + file.name.replace('~', '-'))
    (out / 'SHA256SUMS').write_text('\n'.join(sums) + '\n')
manifest = {'source_sha': SHA, 'run_id': RUN, 'iso_checks': ISO_CHECKS, 'files': {}}
for file in files:
    assert file.is_file() and file.stat().st_size > 0
    with file.open('rb') as f:
        manifest['files'][file.name.replace('~', '-')] = {'size': file.stat().st_size, 'sha256': hashlib.file_digest(f, 'sha256').hexdigest()}
manifest_path = out / 'candidate-validation.json'; manifest_path.write_text(json.dumps(manifest, indent=2) + '\n'); files.append(manifest_path)
tag = 'v'+VERSION if PUBLISH else 'candidate-'+LABEL+'-' + SHA[:12] + '-' + RUN
existing = request(API + '/releases?per_page=100')
release = next((r for r in existing if r['tag_name'] == tag), None)
if release is None:
    notes = ('Alpha.11: dynamic dashboard, visual network ports and signed application update staging, installation, backup/rollback and interrupted-job recovery. '
             'Original ISO passed 78 UEFI/live/install/cold-boot and actual installed update checks after Python, Chromium and packet suites. '
             'See the attached Italian installation/bootstrap guide. Existing alpha.10 needs manual trusted DEB or new ISO bootstrap. '
             'Production Ed25519 signing/trust is not provisioned by this release; DEB/checksums are not a signed web-update bundle. '
             'Application updates only; no OS/kernel upgrade, HA, HTTPS antivirus inspection or guaranteed hard-power-cut recovery. '
             'Experimental prerelease. No Fortinet code reused. ' if PUBLISH else
             'Private draft preserving the original tested build while Actions artifact storage is full. Not a published release. ')
    body = {'tag_name': tag, 'target_commitish': SHA, 'name': 'Murus Igneus '+VERSION if PUBLISH else 'Validated '+VERSION+' candidate '+SHA[:12],
            'draft': True, 'prerelease': True, 'body': notes+'\n\nSource: '+SHA+'\nCI: https://github.com/'+REPO+'/actions/runs/'+RUN+'\nISO SHA256: `'+digest+'`'}
    release = request(API + '/releases', json.dumps(body).encode(), 'POST')
assert release['draft'] and release['target_commitish'] == SHA
for file in files:
    name = file.name.replace('~', '-')
    with file.open('rb') as f:
        data = f.read()
    expected = 'sha256:' + hashlib.sha256(data).hexdigest()
    old = next((a for a in release['assets'] if a['name'] == name), None)
    if old is None:
        asset = request('https://uploads.github.com/repos/' + REPO + '/releases/' + str(release['id']) + '/assets?name=' + urllib.parse.quote(name), data, 'POST', 'application/octet-stream')
    else:
        asset = old
    assert asset.get('digest') == expected and asset['size'] == len(data), asset
    print('Verified draft asset:', name, expected, flush=True)
if PUBLISH:
    release = request(API+'/releases/'+str(release['id']), json.dumps({'draft':False,'prerelease':True,'make_latest':'false'}).encode(), 'PATCH')
    assert not release['draft'] and release['tag_name'] == tag
print(('PUBLISHED_RELEASE=' if PUBLISH else 'CANDIDATE_DRAFT=') + release['html_url'], flush=True)
with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as f:
    f.write('## '+('Validated release published' if PUBLISH else 'Validated candidate preserved')+'\n\nRelease: '+release['html_url']+'\n\nOriginal ISO SHA256: `'+digest+'`\n')
