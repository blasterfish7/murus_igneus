"""Publish only the original, verified alpha.4 artifacts. SPDX-License-Identifier: MIT."""
import hashlib
import json
import os
from pathlib import Path
import shutil
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen
import zipfile

BASE = 'https://api.github.com/repos/blasterfish7/murus_igneus'
TOKEN = os.environ['GH_TOKEN']
TAG = 'v0.3.0-alpha.4'
TARGET = 'ab2b29c1432eb43341f39c59f03110251238054d'
BUILD_SOURCE = '4808ef7fe556c0c1564a01faa7fff4d4e67aca33'
RUN = 39591605617
ISO = 'murus-igneus-0.3.0-alpha.4-devuan-amd64.iso'
DEB = 'murus-igneus_0.3.0-alpha.4_all.deb'
ARTIFACTS = [(12342299949, '0cf1e67828f4a489e3a35f92a163ef42e0bfe9096d7e550458b877aabe67e52b'),
             (12342582273, '7e876b869acf56c1ff4b7de98662ec9bc691d4f0e0580d520a8402be670a8675')]
WORK = Path('release-files'); WORK.mkdir(exist_ok=True)


def headers():
    return {'Authorization': 'Bearer ' + TOKEN, 'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'murus-igneus-release'}


def api(path, method='GET', data=None):
    h = headers()
    if data is not None:
        data = json.dumps(data).encode(); h['Content-Type'] = 'application/json'
    with urlopen(Request(BASE + path, data=data, headers=h, method=method), timeout=60) as response:
        return json.load(response)


def sha(path):
    with path.open('rb') as file: return hashlib.file_digest(file, 'sha256').hexdigest()


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, h, newurl): return None


def download_artifact(ident, expected):
    meta = api('/actions/artifacts/' + str(ident))
    assert not meta['expired'] and meta['digest'] == 'sha256:' + expected
    assert meta['workflow_run']['id'] == RUN and meta['workflow_run']['head_sha'] == BUILD_SOURCE
    request = Request(BASE + '/actions/artifacts/' + str(ident) + '/zip', headers=headers())
    try:
        build_opener(NoRedirect).open(request, timeout=60)
    except HTTPError as error:
        assert error.code == 302
        location = error.headers['Location']
    else:
        raise AssertionError('Expected authenticated artifact redirect')
    assert urlsplit(location).scheme == 'https'
    # Never forward the GitHub token to the signed blob-storage redirect.
    path = WORK / (str(ident) + '.zip')
    with urlopen(Request(location, headers={'User-Agent': 'murus-igneus-release'}), timeout=180) as response, path.open('wb') as file:
        shutil.copyfileobj(response, file, 1024 * 1024)
    assert sha(path) == expected, 'Artifact archive checksum mismatch'
    return zipfile.ZipFile(path)


def copy_member(archive, name, destination=None):
    matches = [item for item in archive.namelist() if item.rsplit('/', 1)[-1] == name]
    assert len(matches) == 1, name
    path = WORK / (destination or name)
    with archive.open(matches[0]) as source, path.open('wb') as target:
        shutil.copyfileobj(source, target, 1024 * 1024)
    return path


run = api('/actions/runs/' + str(RUN))
assert run['conclusion'] == 'success' and run['head_sha'] == BUILD_SOURCE
assert api('/git/ref/heads/main')['object']['sha'] == TARGET
comparison = api('/compare/' + BUILD_SOURCE + '...' + TARGET)
assert comparison['behind_by'] == 0
assert {f['filename'] for f in comparison['files']} <= {'SOURCE_STATUS.md', 'docs/ISO-ALPHA4-QA.md', 'docs/qa/alpha4-validation.json'}, 'Untested runtime changes'

with download_artifact(*ARTIFACTS[0]) as archive:
    iso = copy_member(archive, ISO)
    old_checksums = copy_member(archive, 'SHA256SUMS', 'build-SHA256SUMS')
    report = copy_member(archive, 'alpha4-iso-networking-qa.json')
    manifest = copy_member(archive, 'packages-devuan.tsv')
    signatures = copy_member(archive, 'signature-status.txt')
with download_artifact(*ARTIFACTS[1]) as archive:
    deb = copy_member(archive, 'murus-igneus_0.3.0~alpha.4_all.deb', DEB)
iso_sha = sha(iso)
assert any(line.split() == [iso_sha, ISO] for line in old_checksums.read_text().splitlines())
qa = json.loads(report.read_text())
assert qa['success'] and qa['iso'] == ISO and qa['sha256'] == iso_sha
assert len(qa['checks']) == 14 and 'Graceful live VM poweroff' in qa['checks']
assert 'succeeded' in signatures.read_text().lower()

notes = '''Murus Igneus 0.3.0-alpha.4 — Devuan 6 Excalibur amd64.

Nuove funzioni: VLAN native, DHCP, DNS locale, port forwarding TCP/UDP, sessioni e log dalla GUI. Include installer web, WireGuard, Suricata IPS, proxy antivirus HTTP ClamAV, connettore AI locale e gestione SNMP degli switch.

Collaudo: 124 test Python CI senza skip, controlli GUI con Chromium, 11 verifiche con pacchetti reali e 14 verifiche sulla ISO avviata in UEFI, incluso rollback e spegnimento. Firme ufficiali ClamAV scaricate durante la build. I binari allegati sono quelli originali della build 39591605617, senza ricompilazione.

Accesso GUI: https://IP:8443 — admin / igneus. Console: root / igneus. Importare un backup FortiGate è facoltativo.

Versione sperimentale: installazione su disco della alpha.4, hardware fisico, BIOS/Secure Boot e matrice completa VPN/IPS/antivirus non ricollaudati. Nessuna ispezione antivirus HTTPS. Importazione automatica VLAN/VIP/DHCP FortiGate non supportata. Solo componenti open source e codice indipendente, senza codice/firmware Fortinet.

Estrarre o scrivere il file ISO come immagine di avvio; verificare SHA256SUMS. Il pacchetto DEB richiede Devuan 6 e non è un'immagine avviabile.
'''
guide = WORK / 'MURUS-IGNEUS-ALPHA4-LEGGIMI.txt'
guide.write_text(notes + '''
Configurazione iniziale:
- Scheda eth0 riservata alla gestione: DHCP, con fallback 192.168.56.1/24.
- Dalla GUI è possibile iniziare senza alcun backup.
- VLAN: dichiarare la porta dati padre (es. eth2), poi una nuova interfaccia
  (es. eth2.20) con padre eth2, tag 20 e IPv4/prefisso.
- DHCP: un pool per interfaccia statica; DNS espliciti oppure servizio DNS locale
  abilitato sulla stessa interfaccia. Gateway/pool non devono sovrapporsi.
- DNS: selezionare le interfacce e i resolver IPv4 a monte.
- DNAT: IP pubblico uguale all'IP dell'interfaccia di ingresso, destinazione
  nella subnet interna, TCP/UDP e porta singola. Ogni pubblicazione autorizza
  esplicitamente quel traffico prima delle policy. Nessun hairpin NAT.
- Eseguire Verifica e applica, poi confermare entro 90 secondi; altrimenti
  la configurazione precedente viene ripristinata.
- Installer web: selezionare solo il disco destinato all'appliance. Il disco
  scelto viene cancellato dopo la conferma esplicita prevista dalla pagina.
- AI: modello e Ollama non sono inclusi; serve un server locale compatibile.
- Switch: inventario SNMP; VLAN e PoE degli switch non sono ancora gestiti.

Sorgenti: https://github.com/blasterfish7/murus_igneus
Collaudo: docs/ISO-ALPHA4-QA.md nel repository.
''')
files = [iso, deb, guide, report, manifest, signatures]
checksums = WORK / 'SHA256SUMS'
checksums.write_text(''.join(sha(path) + '  ' + path.name + '\n' for path in files))
files.append(checksums)
expected_assets = {path.name: sha(path) for path in files}

try:
    release = api('/releases/tags/' + TAG)
except HTTPError as error:
    if error.code != 404: raise
    release = None
if release is not None and not release['draft']:
    tag = api('/git/ref/tags/' + TAG)
    assert tag['object']['type'] == 'commit' and tag['object']['sha'] == TARGET
    assert release['prerelease']
    assert {a['name']: a['digest'].removeprefix('sha256:') for a in release['assets']} == expected_assets
    print(json.dumps({'url': release['html_url'], 'already_published': True})); raise SystemExit(0)

try:
    ref = api('/git/ref/tags/' + TAG)
    assert ref['object']['type'] == 'commit' and ref['object']['sha'] == TARGET
except HTTPError as error:
    if error.code != 404: raise
    api('/git/refs', 'POST', {'ref': 'refs/tags/' + TAG, 'sha': TARGET})
if release is None:
    release = api('/releases', 'POST', {'tag_name': TAG, 'target_commitish': TARGET,
                  'name': 'Murus Igneus 0.3.0-alpha.4 — Devuan', 'body': notes,
                  'draft': True, 'prerelease': True, 'make_latest': 'false'})
assert release['draft'] and release['prerelease'] and release['tag_name'] == TAG
existing = {a['name']: a for a in release['assets']}
assert not (set(existing) - set(expected_assets)), 'Unexpected draft assets'
for path in files:
    if path.name in existing:
        asset = existing[path.name]
        assert asset['state'] == 'uploaded' and asset['digest'] == 'sha256:' + expected_assets[path.name]
        continue
    h = headers(); h.update({'Content-Type': 'application/octet-stream', 'Content-Length': str(path.stat().st_size)})
    upload = release['upload_url'].split('{')[0] + '?name=' + quote(path.name)
    with path.open('rb') as file:
        with urlopen(Request(upload, data=file, headers=h, method='POST'), timeout=240) as response:
            asset = json.load(response)
    assert asset['name'] == path.name and asset['state'] == 'uploaded'
    assert asset['digest'] == 'sha256:' + expected_assets[path.name]
    print('Verified asset: ' + path.name, flush=True)
release = api('/releases/' + str(release['id']))
assert len(release['assets']) == len(files)
assert {a['name']: a['digest'].removeprefix('sha256:') for a in release['assets']} == expected_assets
published = api('/releases/' + str(release['id']), 'PATCH', {'draft': False, 'prerelease': True, 'make_latest': 'false'})
assert not published['draft'] and published['prerelease'] and published['published_at']
print(json.dumps({'url': published['html_url'], 'tag_target': TARGET, 'iso_sha256': iso_sha,
                  'assets': expected_assets, 'published_at': published['published_at']}, indent=2))
