"""Publish only the original, verified alpha.5 artifacts. SPDX-License-Identifier: MIT."""
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
TAG = 'v0.3.0-alpha.5'
TARGET = 'ae8b9fcb98c016cc9ac05ef8381862aca4203102'
BUILD_SOURCE = '55ec4ea84c58f0c036cd50ac9a7266a7c96fdd38'
RUN = 39651874250
ISO = 'murus-igneus-0.3.0-alpha.5-devuan-amd64.iso'
DEB = 'murus-igneus_0.3.0-alpha.5_all.deb'
ARTIFACTS = [[12370925454, 'a80f9653c149e93e1e9c44d3b9ed5ca669776a6d0f9e1b1bda46dbdcbbfbe1d3'], [12368724058, '71edc2ff80a1168ac401bb525ee959bfe0243288b9f804faba40d48167312772']]
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
assert {f['filename'] for f in comparison['files']} <= {'SOURCE_STATUS.md', 'docs/ISO-ALPHA5-QA.md', 'docs/qa/alpha5-validation.json'}, 'Untested runtime changes'

with download_artifact(*ARTIFACTS[0]) as archive:
    iso = copy_member(archive, ISO)
    old_checksums = copy_member(archive, 'SHA256SUMS', 'build-SHA256SUMS')
    report = copy_member(archive, 'alpha5-iso-networking-qa.json')
    manifest = copy_member(archive, 'packages-devuan.tsv')
    signatures = copy_member(archive, 'signature-status.txt')
with download_artifact(*ARTIFACTS[1]) as archive:
    deb = copy_member(archive, 'murus-igneus_0.3.0~alpha.5_all.deb', DEB)
iso_sha = sha(iso)
assert any(line.split() == [iso_sha, ISO] for line in old_checksums.read_text().splitlines())
qa = json.loads(report.read_text())
assert qa['success'] and qa['iso'] == ISO and qa['sha256'] == iso_sha
assert len(qa['checks']) == 24 and 'Graceful live VM poweroff' in qa['checks']
signatures_ready = 'succeeded' in signatures.read_text().lower()

notes = "Murus Igneus 0.3.0-alpha.5 — Devuan 6 Excalibur amd64.\n\nAggiunge OpenAI Responses API opzionale accanto a Ollama/Qwen3 locale, aggiorna il contesto AI su VLAN/DHCP/DNS/DNAT, introduce VPN IKEv2 con strongSwan, failover tra due WAN statiche, TOTP, storico persistente policy/DNAT e audit amministrativo. Include il comando murus-update per verificare e installare pacchetti applicativi firmati Ed25519, con snapshot locale di rollback. Restano installer web, WireGuard, Suricata, proxy HTTP ClamAV e gestione SNMP degli switch.\n\nCollaudo: 138 test Python senza skip, 8 controlli Chromium, 11 prove di rete precedenti e 9 nuove prove IKEv2/WAN con pacchetti reali. La ISO originale supera 24 controlli in QEMU UEFI, compresi test di rete e spegnimento. Artefatti originali della build 39651874250, senza ricompilazione.\n\nAccesso GUI: https://IP:8443 — admin / igneus. Console: root / igneus. Importazione backup FortiGate facoltativa. Interfaccia eth0 riservata alla gestione: DHCP, fallback 192.168.56.1/24.\n\nOpenAI: selezionare il provider nella pagina Assistente AI, indicare un modello disponibile nel proprio progetto e la propria chiave API, poi autorizzare esplicitamente l'invio dei dati. Servizio esterno opzionale con propria quota/costi; il client è open source. Nessuna chiamata live OpenAI è stata eseguita nel collaudo: test con risposte controllate. Ollama richiede server e modello separati. Le proposte AI non applicano modifiche automaticamente.\n\nIPsec: IKEv2/PSK/AES256-SHA256-DH14, IPv4 e peer statici. Ogni tunnel autorizza tutto il traffico tra i due selettori prima delle policy; IPS resta applicato. Prove fra due strongSwan, nessun collaudo con apparato FortiGate. Doppia WAN: tre successi/fallimenti ICMP consecutivi, preferenza nell'ordine; le sessioni esistenti possono interrompersi. Non è SD-WAN o HA.\n\nTOTP: configurare dalla pagina Amministrazione, conservare il segreto e verificare l'ora dell'appliance. Recovery console root: rimuovere /etc/murus_igneus/mfa.json e riavviare il servizio. Storico massimo 30 giorni o 20.000 eventi; in modalità live senza persistenza si perde al riavvio.\n\nAggiornamenti: murus-update opera da console sulla sola applicazione, non su kernel/OS. Richiede una chiave pubblica di fiducia installata fuori banda in /etc/murus_igneus/update.pub; nessuna chiave privata di produzione è inclusa. Verifica crittografica e manomissione collaudate; installazione/rollback applicativi non ancora collaudati integralmente. Nessuna firma Secure Boot o aggiornamento atomico A/B dell'intero sistema.\n\nVersione alpha: installazione su disco della alpha.5, hardware, BIOS/Secure Boot, gestione switch in scrittura e matrice completa VPN/IPS/AV non ricollaudati. Nessuna ispezione antivirus HTTPS, RBAC, clustering HA o importazione automatica VPN/VLAN/VIP/DHCP FortiGate. Nessun codice o firmware Fortinet riutilizzato.\n\nVerificare SHA256SUMS prima di scrivere la ISO come immagine di avvio. Dal web installer, il disco selezionato viene cancellato solo dopo la conferma esplicita della pagina. Dopo una modifica firewall confermare entro 90 secondi, altrimenti viene ripristinata la configurazione precedente. Il DEB richiede Devuan 6 e non è avviabile.\n\nDettagli: docs/ALPHA5.md e docs/ISO-ALPHA5-QA.md nel repository.\n"
notes += '\nFirme ClamAV: ' + signatures.read_text().strip() + '\n'
guide = WORK / 'MURUS-IGNEUS-ALPHA5-LEGGIMI.txt'
guide.write_text(notes)
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
                  'name': 'Murus Igneus 0.3.0-alpha.5 — Devuan', 'body': notes,
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
