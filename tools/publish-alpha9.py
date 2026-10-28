"""Publish the original validated alpha.9 draft; never rebuild or modify ISO/DEB."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

BASE = 'https://api.github.com/repos/blasterfish7/murus_igneus'
TOKEN = os.environ['GH_TOKEN']; TARGET = os.environ['MURUS_RELEASE_TARGET']; DRAFT = int(os.environ['MURUS_DRAFT_ID'])
SOURCE = os.environ['MURUS_TESTED_SOURCE']; RUN = int(os.environ['MURUS_TESTED_RUN']); TAG = 'v0.3.0-alpha.9'
WORK = Path('release-files'); WORK.mkdir(exist_ok=True)


def headers():
    return {'Authorization': 'Bearer ' + TOKEN, 'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'murus-release'}


def api(path, method='GET', data=None):
    h = headers()
    if data is not None:
        data = json.dumps(data).encode(); h['Content-Type'] = 'application/json'
    with urlopen(Request(BASE + path, data=data, headers=h, method=method), timeout=60) as response:
        return json.load(response)


def sha(path):
    with path.open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, h, newurl):
        return None


def download(asset):
    path = WORK / asset['name']; h = headers(); h['Accept'] = 'application/octet-stream'
    try:
        response = build_opener(NoRedirect).open(Request(BASE + '/releases/assets/' + str(asset['id']), headers=h), timeout=60)
    except HTTPError as error:
        assert error.code == 302
        location = error.headers['Location']; assert urlsplit(location).scheme == 'https'
        response = urlopen(Request(location, headers={'User-Agent': 'murus-release'}), timeout=180)
    with response, path.open('wb') as file:
        shutil.copyfileobj(response, file, 1024 * 1024)
    assert path.stat().st_size == asset['size'] and 'sha256:' + sha(path) == asset['digest'], asset['name']
    return path


def upload(release, path):
    name = path.name; data = path.read_bytes()
    existing = next((a for a in api('/releases/' + str(release['id']))['assets'] if a['name'] == name), None)
    if existing is None:
        url = 'https://uploads.github.com/repos/blasterfish7/murus_igneus/releases/' + str(release['id']) + '/assets?name=' + quote(name)
        h = headers(); h['Content-Type'] = 'application/octet-stream'
        with urlopen(Request(url, data=data, headers=h, method='POST'), timeout=90) as response:
            asset = json.load(response)
    else:
        asset = existing
    assert asset['size'] == len(data) and asset['digest'] == 'sha256:' + sha(path)


for target, expected in {'forcesafesearch.google.com':'216.239.38.120','restrict.youtube.com':'216.239.38.120','restrictmoderate.youtube.com':'216.239.38.119'}.items():
    addresses = {r[4][0] for r in socket.getaddrinfo(target, 443, socket.AF_INET, socket.SOCK_STREAM)}
    assert expected in addresses, (target, addresses, expected)
    print('Verified current provider VIP:', target, expected, flush=True)

assert api('/actions/runs/' + str(RUN))['conclusion'] == 'success'
assert api('/actions/runs/' + str(RUN))['head_sha'] == SOURCE
assert api('/git/ref/heads/main')['object']['sha'] == TARGET
compare = api('/compare/' + SOURCE + '...' + TARGET)
assert compare['behind_by'] == 0
assert {f['filename'] for f in compare['files']} <= {'README.md', 'SOURCE_STATUS.md', 'docs/ALPHA9.md', 'docs/ISO-ALPHA9-QA.md', 'docs/qa/alpha9-validation.json'}, 'Runtime differs from tested candidate'
release = api('/releases/' + str(DRAFT)); assert release['draft']
assert release['tag_name'] == 'candidate-alpha9-' + SOURCE[:12] + '-' + str(RUN)
files = {a['name']: download(a) for a in release['assets']}
manifest = json.loads(files['candidate-validation.json'].read_text())
assert manifest['source_sha'] == SOURCE and str(manifest['run_id']) == str(RUN) and manifest['iso_checks'] == 58
for name, meta in manifest['files'].items():
    assert files[name].stat().st_size == meta['size'] and sha(files[name]) == meta['sha256']
iso = files['murus-igneus-0.3.0-alpha.9-devuan-amd64.iso']; deb = files['murus-igneus_0.3.0-alpha.9_all.deb']
qa = json.loads(files['alpha9-iso-networking-qa.json'].read_text())
assert qa['success'] and len(qa['checks']) == 58 and qa['sha256'] == sha(iso) and qa['iso'] == iso.name
assert files['SHA256SUMS'].read_text().strip() == sha(iso) + '  ' + iso.name
trust = json.loads(files['bootstrap-provenance.json'].read_text())
assert trust['package'] == 'devuan-keyring' and trust['verified_installed_files'] is True and trust['keyfiles_sha256']
assert trust['seed_image'] == 'dyne/devuan:excalibur@sha256:10f6138df94c08164f300a2f35f96cd8c8966fc4948550dbe0485149d020248f'
extracted = WORK / 'deb'; subprocess.run(['dpkg-deb', '-x', str(deb), str(extracted)], check=True)
app = extracted / 'usr/lib/murus-igneus'; original = Path('src/murus_igneus')
packaged = list(app.iterdir()); assert len(packaged) == 27
for file in packaged:
    assert file.read_bytes() == (original / file.name).read_bytes(), file.name
assert (extracted / 'usr/sbin/murus-update').stat().st_mode & 0o111
for name in ('murus-info','murus-prepare','murus-serve','murus-update','murus-install'):
    file=extracted/'usr/sbin'/name
    assert file.read_bytes()==(Path('packaging/devuan/files')/name).read_bytes(),name
    assert file.stat().st_mode & 0o111
assert (extracted/'etc/init.d/murus-igneus').read_bytes()==Path('packaging/devuan/files/murus-igneus.initd').read_bytes()
assert (extracted/'etc/profile.d/murus-welcome.sh').read_bytes()==Path('packaging/devuan/files/murus-welcome.sh').read_bytes()
readme = WORK / 'MURUS-IGNEUS-ALPHA9-LEGGIMI.txt'
notes = Path('docs/ALPHA9.md').read_text()
readme.write_text(notes + '\n\nCollaudo della build originale: 216 test Python CI senza skip, 14 controlli Chromium, 13 prove native, 9 IKEv2/WAN, 23 parental e 4 liste HTTPS reali. ISO originale: 58 controlli QEMU UEFI/live, installazione su disco virtuale e avvio autonomo. Tutti i 27 file applicativi del DEB verificati contro i sorgenti. Nessuna ricompilazione nel publisher.\n\nVerificare SHA256SUMS e SHA256SUMS-ALL prima dell’uso.\n', encoding='utf-8')
files[readme.name] = readme
checksums = WORK / 'SHA256SUMS-ALL'; checksums.write_text(''.join(sha(path) + '  ' + name + '\n' for name, path in sorted(files.items())))
files[checksums.name] = checksums
upload(release, readme); upload(release, checksums)
body = notes + '\n\nBuild originale: `' + SOURCE + '` — [CI ' + str(RUN) + '](https://github.com/blasterfish7/murus_igneus/actions/runs/' + str(RUN) + ').\n\n216 test Python senza skip, 14 controlli Chromium, 13 prove native, 9 IKEv2/WAN e 23 parental con traffico reale. ISO originale: 58 controlli QEMU UEFI/live, installazione su disco virtuale e avvio autonomo. Tutti i 27 file applicativi del DEB corrispondono ai sorgenti testati; nessuna ricompilazione nel publisher.\n\nISO SHA256: `' + sha(iso) + '`\n\nDEB SHA256: `' + sha(deb) + '`\n\nAllegati: ISO avviabile, DEB Devuan, checksum, manifesti e guida. Leggere MURUS-IGNEUS-ALPHA9-LEGGIMI.txt prima dell’uso.\n'
for asset in api('/releases/' + str(DRAFT))['assets']:
    assert asset['name'] in files and asset['digest'] == 'sha256:' + sha(files[asset['name']])
assert len(api('/releases/' + str(DRAFT))['assets']) == len(files)
try:
    api('/git/ref/tags/' + TAG)
except HTTPError as error:
    assert error.code == 404
else:
    raise AssertionError('Final tag already exists: do not overwrite it')
assert not any(r['id'] != DRAFT and r['tag_name'] == TAG for r in api('/releases?per_page=100'))
release = api('/releases/' + str(DRAFT), 'PATCH', {'tag_name': TAG, 'target_commitish': TARGET,
    'name': 'Murus Igneus 0.3.0-alpha.9 — Famiglia, installer e nuova amministrazione', 'body': body, 'draft': False, 'prerelease': True})
assert not release['draft'] and release['tag_name'] == TAG
assert api('/git/ref/tags/' + TAG)['object']['sha'] == TARGET
print('PUBLISHED=' + release['html_url'], flush=True)
print('ISO_SHA256=' + sha(iso), flush=True)
print('DEB_SHA256=' + sha(deb), flush=True)
print('VERIFIED_ASSETS=' + str(len(files)), flush=True)

