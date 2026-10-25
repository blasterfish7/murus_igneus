"""Publish the original validated alpha.7 draft; never rebuild or modify ISO/DEB."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

BASE = 'https://api.github.com/repos/blasterfish7/murus_igneus'
TOKEN = os.environ['GH_TOKEN']; TARGET = os.environ['MURUS_RELEASE_TARGET']; DRAFT = int(os.environ['MURUS_DRAFT_ID'])
SOURCE = '64a4b5dad271bd0ea86e2c19822a5b6974c10105'; RUN = 40207093633; TAG = 'v0.3.0-alpha.7'
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


assert api('/actions/runs/' + str(RUN))['conclusion'] == 'success'
assert api('/actions/runs/' + str(RUN))['head_sha'] == SOURCE
assert api('/git/ref/heads/main')['object']['sha'] == TARGET
compare = api('/compare/' + SOURCE + '...' + TARGET)
assert compare['behind_by'] == 0
assert {f['filename'] for f in compare['files']} <= {'SOURCE_STATUS.md', 'docs/ISO-ALPHA7-QA.md', 'docs/qa/alpha7-validation.json'}, 'Runtime differs from tested candidate'
release = api('/releases/' + str(DRAFT)); assert release['draft']
assert release['tag_name'] == 'candidate-alpha7-' + SOURCE[:12] + '-' + str(RUN)
files = {a['name']: download(a) for a in release['assets']}
manifest = json.loads(files['candidate-validation.json'].read_text())
assert manifest['source_sha'] == SOURCE and str(manifest['run_id']) == str(RUN) and manifest['iso_checks'] == 44
for name, meta in manifest['files'].items():
    assert files[name].stat().st_size == meta['size'] and sha(files[name]) == meta['sha256']
iso = files['murus-igneus-0.3.0-alpha.7-devuan-amd64.iso']; deb = files['murus-igneus_0.3.0-alpha.7_all.deb']
qa = json.loads(files['alpha7-iso-networking-qa.json'].read_text())
assert qa['success'] and len(qa['checks']) == 44 and qa['sha256'] == sha(iso) and qa['iso'] == iso.name
assert files['SHA256SUMS'].read_text().strip() == sha(iso) + '  ' + iso.name
extracted = WORK / 'deb'; subprocess.run(['dpkg-deb', '-x', str(deb), str(extracted)], check=True)
app = extracted / 'usr/lib/murus-igneus'; original = Path('src/murus_igneus')
packaged = list(app.iterdir()); assert len(packaged) == 27
for file in packaged:
    assert file.read_bytes() == (original / file.name).read_bytes(), file.name
assert (extracted / 'usr/sbin/murus-update').stat().st_mode & 0o111
for name in ('murus-info','murus-prepare','murus-serve','murus-update'):
    file=extracted/'usr/sbin'/name
    assert file.read_bytes()==(Path('packaging/devuan/files')/name).read_bytes(),name
    assert file.stat().st_mode & 0o111
assert (extracted/'etc/init.d/murus-igneus').read_bytes()==Path('packaging/devuan/files/murus-igneus.initd').read_bytes()
readme = WORK / 'MURUS-IGNEUS-ALPHA7-LEGGIMI.txt'
readme.write_text('''MURUS IGNEUS 0.3.0-alpha.7 — DEVUAN 6 EXCALIBUR AMD64

ISO originale, avviabile. Nessun codice o firmware Fortinet riutilizzato.
Corregge il limite Basic (memoria limitata, tentativi concorrenti, scadenza),
il rollback con errori iniziali/servizi/nft e la segnalazione di esiti incompleti
nella GUI/API. Include il testo murus-info corretto proposto da Claude.
Verificare SHA256SUMS prima di scrivere l'immagine; SHA256SUMS-ALL contiene
anche i digest degli altri allegati. Il DEB richiede Devuan 6, non è avviabile.

Accesso GUI: https://IP:8443 — admin / igneus. Console: root / igneus.
eth0 è riservata alla gestione: DHCP, fallback 192.168.56.1/24.
Importazione FortiGate facoltativa: è possibile configurare tutto da zero.
Cambiare le credenziali. L'installer web cancella il disco selezionato solo
dopo la conferma esplicita della pagina. Dopo modifiche firewall confermare
entro 90 secondi o avviene il rollback.

PARENTAL CONTROL
1. Configurare LAN/WAN, routing e policy Internet. Il traffico dei dispositivi
   deve attraversare Murus: una VM fuori dal percorso non filtra né misura.
2. Usare prenotazioni DHCP e MAC Wi-Fi stabile, oppure una VLAN/SSID dedicata.
3. Aprire Parental control e scaricare le liste delle categorie desiderate.
4. Creare profili, indicare IP o subnet, categorie/social e fasce consentite.
5. Abilitare il reporting locale se desiderato; salvare, verificare, applicare
   e confermare. Aggiornare il report dopo almeno 10 secondi.
6. Usare Pausa ora/Riprendi sui profili già attivi. Non riavvia rete/VPN/UTM.

REPORTING
24 ore/7 giorni, selezione IP/subnet, upload/download IPv4 inoltrati, andamento
orario, pacchetti bloccati dal parental e primi 100 domini DNS richiesti/filtrati.
CSV e cancellazione con conferma. Dati solo locali, raccolta disattivata di
default, nessun URL o contenuto HTTPS registrato. Conservazione fino a 7 giorni,
50.000 righe e database 32 MiB; a volumi elevati lo storico può essere più breve.
In modalità live senza persistenza i dati si perdono al riavvio.

DNS non significa visite o tempo nelle app. I byte non sono attribuiti ai siti.
Subnet aggregate; proxy HTTP locale escluso dai byte. Cache, DoH/VPN sconosciuti,
IP fuori dai profili, rete mobile e traffico fuori da Murus possono lasciare
lacune. Nessun riconoscimento completo di Instagram o certificazione categorie.
Campioni ogni 10 secondi; riavvio/applicazione possono perdere l'ultimo intervallo.

COLLAUDO E LIMITI
178 test Python CI senza skip, 10 controlli Chromium, 12 prove native,
9 prove IKEv2/WAN, 17 prove parental e 4 liste HTTPS reali. La ISO originale
supera 44 controlli UEFI/live in QEMU, usando i moduli realmente installati.
27 file applicativi del DEB confrontati con i sorgenti collaudati.

Alpha sperimentale. Installazione su disco della alpha.7, BIOS/Secure Boot,
hardware fisico, interoperabilità FortiGate, switch in scrittura e matrice
completa IPS/AV/VPN non collaudati. Nessuna ispezione antivirus HTTPS o HA.
L'aggiornamento firmato riguarda l'applicazione, non l'intero OS; installazione
e rollback completi dell'aggiornamento non sono collaudati. Le prove proxy
parental usano uno scanner controllato, non certificano il motore ClamAV.

Restano OpenAI Responses API opzionale, Ollama, WireGuard, IKEv2, doppia WAN,
TOTP, Suricata, proxy HTTP ClamAV e gestione SNMP. OpenAI richiede chiave propria,
consenso e quota/costi del servizio; nessuna chiamata live OpenAI nel collaudo.
Ollama richiede server e modello separati. Le proposte AI non si applicano da sole.

Dettagli nel repository: docs/PARENTAL.md, docs/ISO-ALPHA7-QA.md,
docs/ALPHA7.md per le correzioni e docs/ALPHA5.md per le funzioni precedenti e relative limitazioni.
''', encoding='utf-8')
files[readme.name] = readme
checksums = WORK / 'SHA256SUMS-ALL'; checksums.write_text(''.join(sha(path) + '  ' + name + '\n' for name, path in sorted(files.items())))
files[checksums.name] = checksums
upload(release, readme); upload(release, checksums)
body = '''Murus Igneus 0.3.0-alpha.7 — Devuan 6 Excalibur amd64.

Completa le correzioni di Claude: limite Basic 10 credenziali errate/60 s per IP, atomico e con memoria limitata a 1.024 peer × 10 timestamp; scadenza degli errori; rollback con operazioni di recupero controllate, pending sempre liberato, fallback di sicurezza tentato e GUI/API che riportano esito incompleto. Le credenziali di laboratorio sono conservate.

Mantiene parental control IPv4: profili IP/subnet, filtri DNS HaGeZi e social, eccezioni, orari settimanali, pausa immediata e prenotazioni DHCP. Reporting facoltativo solo locale: 24 ore/7 giorni, byte upload/download, andamento orario, pacchetti bloccati dal parental, richieste/domini DNS filtrati, CSV e cancellazione. Nessun URL, contenuto HTTPS o tempo nelle app registrato. Reporting disattivato per impostazione predefinita; conservazione massima 7 giorni/50.000 righe/database 32 MiB.

Accesso: https://IP:8443 — admin / igneus. Console root / igneus. eth0 gestione DHCP con fallback 192.168.56.1/24. Importazione FortiGate facoltativa. Configurare prima rete/routing/policy; Murus deve essere il gateway dei dispositivi. Aprire Parental control, scaricare le categorie, creare i profili con IP stabili, abilitare eventualmente reporting e applicare/confermare la bozza. Dopo 10 secondi aggiornare il report.

DNS non equivale a visite o tempo nelle app; i byte non sono attribuiti ai siti. Subnet aggregate, proxy locale escluso dai byte. DoH/VPN sconosciuti, cache, IP fuori dal profilo, rete mobile e traffico fuori da Murus possono lasciare lacune. Nessun controllo completo delle applicazioni o certificazione categorie.

Collaudo: 178 test Python senza skip, 10 controlli Chromium, 12 prove native, 9 IKEv2/WAN, 17 parental con pacchetti reali e 4 download HTTPS reali. ISO originale: 44 controlli QEMU UEFI/live e spegnimento. Tutti i 27 file applicativi del DEB corrispondono ai sorgenti testati. Nessuna ricompilazione nel publisher. Il manifesto candidate-validation.json identifica sorgente e build originale.

Restano OpenAI Responses opzionale, Ollama, WireGuard, IKEv2, failover WAN, TOTP, Suricata, proxy HTTP ClamAV e SNMP. OpenAI richiede chiave/consenso/quota propri; nessuna chiamata live OpenAI nel collaudo. Le proposte AI non applicano modifiche automaticamente.

Alpha: installazione su disco della alpha.7, hardware, BIOS/Secure Boot, FortiGate, scrittura switch e matrice completa UTM non collaudati. Nessuna ispezione antivirus HTTPS o HA. Aggiornamenti firmati solo dell'applicazione: installazione/rollback completi non ricollaudati. Il laboratorio parental usa uno scanner proxy controllato. Nessun codice o firmware Fortinet riutilizzato.

Verificare SHA256SUMS (ISO) o SHA256SUMS-ALL (allegati). Leggere MURUS-IGNEUS-ALPHA7-LEGGIMI.txt, docs/ALPHA7.md e docs/PARENTAL.md prima dell'uso. L'installer web cancella il disco solo dopo conferma esplicita; modifiche firewall da confermare entro 90 secondi. Senza persistenza, configurazione e report live si perdono al riavvio.

ISO SHA256: `%s`
DEB SHA256: `%s`
''' % (sha(iso), sha(deb))
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
    'name': 'Murus Igneus 0.3.0-alpha.7 — Correzioni autenticazione e rollback', 'body': body, 'draft': False, 'prerelease': True})
assert not release['draft'] and release['tag_name'] == TAG
assert api('/git/ref/tags/' + TAG)['object']['sha'] == TARGET
print('PUBLISHED=' + release['html_url'], flush=True)
print('ISO_SHA256=' + sha(iso), flush=True)
print('DEB_SHA256=' + sha(deb), flush=True)
print('VERIFIED_ASSETS=' + str(len(files)), flush=True)

