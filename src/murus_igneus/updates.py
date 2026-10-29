"""Offline Ed25519-signed application package updates and local rollback. SPDX-License-Identifier: MIT."""
import argparse
import base64
import fcntl
import re
import secrets
import socket
import stat
import ssl
import time
import urllib.request
import urllib.error
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

TRUST_KEY = Path('/etc/murus_igneus/update.pub')
CACHE = Path('/var/lib/murus-igneus/updates')


def command(args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=180, **kwargs).stdout.strip()


def verify(directory, key=None):
    key = Path(key) if key is not None else TRUST_KEY
    directory = Path(directory)
    manifest = directory / 'manifest.json'; signature = directory / 'manifest.sig'; package = directory / 'murus-igneus.deb'
    for path, limit in ((manifest, 4096), (signature, 64), (package, 8 * 1024 * 1024)):
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= limit:
            raise ValueError('Bundle di aggiornamento non valido')
    if key.is_symlink() or not key.is_file() or key.stat().st_uid != os.geteuid() or key.stat().st_mode & 0o022 or signature.stat().st_size != 64:
        raise ValueError('Chiave pubblica Ed25519 mancante o firma non valida')
    # Enforce Ed25519, not just any algorithm accepted by pkeyutl.
    public = command(['openssl', 'pkey', '-pubin', '-in', str(key), '-text', '-noout'])
    if 'ED25519' not in public.upper():
        raise ValueError('È richiesta una chiave pubblica Ed25519')
    command(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', str(key), '-rawin', '-in', str(manifest), '-sigfile', str(signature)])
    meta = json.loads(manifest.read_text())
    if not isinstance(meta, dict) or set(meta) != {'schema', 'package', 'version', 'sha256'} or meta['schema'] != 1 or meta['package'] != 'murus-igneus':
        raise ValueError('Manifest non supportato')
    if not isinstance(meta['version'], str) or not re.fullmatch(r'[0-9][0-9A-Za-z.+:~_-]{0,79}', meta['version']) or not isinstance(meta['sha256'], str) or not re.fullmatch(r'[a-f0-9]{64}', meta['sha256']):
        raise ValueError('Versione o digest nel manifest non validi')
    if hashlib.sha256(package.read_bytes()).hexdigest() != meta['sha256']:
        raise ValueError('Checksum pacchetto non corrispondente alla firma')
    for field, expected in [('Package', 'murus-igneus'), ('Version', meta['version']), ('Architecture', 'all')]:
        if command(['dpkg-deb', '-f', str(package), field]) != expected:
            raise ValueError('Metadati DEB non corrispondenti al manifest')
    return meta


STATE = Path('/etc/murus_igneus')
LIVE = Path('/etc/murus_igneus/live-image')
OS_RELEASE = Path('/etc/os-release')
EXTRA_CONFIG = {'defaults':Path('/etc/default/murus-igneus'), 'sysctl':Path('/etc/sysctl.d/90-murus-igneus.conf')}
RELEASES_URL = 'https://api.github.com/repos/blasterfish7/murus_igneus/releases?per_page=50'
ACTIVE_STATES = {'queued', 'running', 'recovering'}
WEB_PACKAGE_LIMIT = 4 * 1024 * 1024


def private_cache():
    if CACHE.is_symlink():
        raise ValueError('Directory aggiornamenti non valida')
    CACHE.mkdir(mode=0o700, parents=True, exist_ok=True)
    CACHE.chmod(0o700)


def save(path, data):
    """Durable journal: publish complete content, then sync the parent directory."""
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.update-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream, ensure_ascii=False)
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def read(path):
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        return None


@contextmanager
def locked():
    private_cache()
    fd = os.open(CACHE/'update.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Aggiornamento già in corso') from None
        yield fd
    finally:
        os.close(fd)


def busy():
    if not CACHE.exists():
        return False
    try:
        with locked():
            return False
    except ValueError:
        return True


def blocked():
    try:
        job = read(CACHE/'status.json') or {}
        return busy() or job.get('state') in ACTIVE_STATES | {'recovery_required'}
    except (OSError, ValueError):
        return True


def installed_version():
    try:
        return command(['dpkg-query', '-W', '-f=${Version}', 'murus-igneus'])
    except (OSError, subprocess.SubprocessError):
        return None


def compatible_host():
    try:
        values = dict(line.split('=', 1) for line in OS_RELEASE.read_text().splitlines() if '=' in line)
        return values.get('ID', '').strip('"') == 'devuan' and values.get('VERSION_CODENAME', '').strip('"') == 'excalibur'
    except OSError:
        return False


def inventory():
    job = read(CACHE/'status.json')
    if job and job.get('state') in ACTIVE_STATES and not busy():
        job = {**job, 'state': 'recovery_required', 'error': 'Operazione interrotta. Ripristinare lo snapshot dalla pagina o dalla console.'}
    rollback = read(CACHE/'rollback.json')
    trusted = TRUST_KEY.is_file() and not TRUST_KEY.is_symlink()
    return {'installed_version': installed_version(), 'supported': compatible_host() and not LIVE.exists(),
            'live': LIVE.exists(), 'trust_configured': trusted,
            'job': job, 'busy': busy(), 'rollback_available': bool(rollback),
            'rollback_version': rollback.get('version') if rollback else None,
            'scope': 'Solo applicazione Murus Igneus. Sistema Devuan, kernel e firme UTM restano separati.'}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Redirect del catalogo release non consentito')


def releases(channel, current=None):
    if channel not in ('stable', 'experimental'):
        raise ValueError('Canale non valido')
    request = urllib.request.Request(RELEASES_URL, headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'Murus-Igneus-Updates'})
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=10) as response:
            data = response.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError('Catalogo release troppo grande')
        rows = json.loads(data)
        if not isinstance(rows, list):
            raise ValueError('Catalogo release non valido')
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403, 404):
            raise ValueError('Catalogo non accessibile: repository privato, autorizzazione assente o limite GitHub. È possibile caricare un bundle firmato offline.') from None
        raise ValueError('Catalogo GitHub non disponibile') from None
    current = current or installed_version()
    result = []
    for row in rows:
        tag = row.get('tag_name', '')
        if row.get('draft') or (channel == 'stable' and row.get('prerelease')) or not re.fullmatch(r'v[0-9][0-9A-Za-z.+~_-]{0,79}', tag):
            continue
        version = re.sub(r'-(alpha|beta|rc)', r'~\1', tag[1:])
        newer = bool(current) and subprocess.run(['dpkg', '--compare-versions', version, 'gt', current], capture_output=True).returncode == 0
        result.append({'tag': tag, 'version': version, 'prerelease': bool(row.get('prerelease')),
                       'newer': newer, 'notes': str(row.get('body') or '')[:10000],
                       'url': 'https://github.com/blasterfish7/murus_igneus/releases/tag/'+tag})
    return {'channel': channel, 'releases': result[:20], 'automatic_install': False}


def preflight(directory):
    if not compatible_host() or LIVE.exists():
        raise ValueError('Installazione aggiornamenti disponibile solo su Devuan 6 Excalibur installato su disco')
    meta = verify(directory)
    current = installed_version()
    if not current or subprocess.run(['dpkg', '--compare-versions', meta['version'], 'gt', current], capture_output=True).returncode:
        raise ValueError('Versione non più recente: usare il ripristino per tornare indietro')
    if shutil.disk_usage(CACHE).free < 256 * 1024 * 1024:
        raise ValueError('Servono almeno 256 MiB liberi per backup e aggiornamento')
    if command(['dpkg', '--audit']):
        raise ValueError('Riparare lo stato dei pacchetti Devuan prima di aggiornare')
    return meta


def stage(data):
    with locked():
        if (read(CACHE/'status.json') or {}).get('state') in ACTIVE_STATES | {'recovery_required'}:
            raise ValueError('Ripristinare prima l’operazione precedente')
        if set(data) != {'files'} or not isinstance(data['files'], dict) or set(data['files']) != {'manifest.json', 'manifest.sig', 'murus-igneus.deb'}:
            raise ValueError('Selezionare manifest.json, manifest.sig e murus-igneus.deb')
        with tempfile.TemporaryDirectory(dir=CACHE) as temporary:
            work = Path(temporary)
            for name, limit in (('manifest.json',4096), ('manifest.sig',64), ('murus-igneus.deb',WEB_PACKAGE_LIMIT)):
                value = data['files'][name]
                if not isinstance(value, str) or len(value) > 4*((limit+2)//3):
                    raise ValueError('Bundle oltre i limiti consentiti')
                try:
                    content = base64.b64decode(value, validate=True)
                except ValueError:
                    raise ValueError('Contenuto bundle non valido') from None
                if not 0 < len(content) <= limit:
                    raise ValueError('Dimensione bundle non valida')
                (work/name).write_bytes(content); (work/name).chmod(0o600)
            meta = preflight(work)
            ident = secrets.token_hex(16)
            save(work/'preview.json', {'id':ident, 'expires':time.time()+1800, 'meta':meta})
            old = CACHE/'staged'
            if old.exists():
                shutil.rmtree(old)
            work.rename(old)
        return {'id':ident, **meta, 'confirmation':'AGGIORNA '+meta['version']}


def launch(action, data):
    if action not in ('install', 'rollback', 'recover'):
        raise ValueError('Operazione non valida')
    with locked() as fd:
        job = read(CACHE/'status.json') or {}
        if action == 'install':
            if job.get('state') in ACTIVE_STATES | {'recovery_required'}:
                raise ValueError('Ripristinare prima l’operazione interrotta')
            preview = read(CACHE/'staged/preview.json') or {}
            if data.get('id') != preview.get('id') or time.time() > preview.get('expires', 0):
                raise ValueError('Verifica bundle scaduta: caricare nuovamente i file')
            meta = preflight(CACHE/'staged')
            if data.get('confirmation') != 'AGGIORNA '+meta['version']:
                raise ValueError('Conferma aggiornamento non valida')
        elif action == 'recover':
            if job.get('state') not in ACTIVE_STATES | {'recovery_required'} or data.get('confirmation') != 'RECUPERA SERVIZIO':
                raise ValueError('Nessuna operazione interrotta da recuperare o conferma non valida')
            if not compatible_host() or LIVE.exists():
                raise ValueError('Recupero disponibile solo sul sistema Devuan installato')
            meta = {'version':job.get('version')}
        else:
            if job.get('state') in ACTIVE_STATES | {'recovery_required'}:
                raise ValueError('Usare prima il recupero dell’operazione interrotta')
            meta = read(CACHE/'rollback.json')
            if not meta or data.get('confirmation') != 'RIPRISTINA '+meta['version']:
                raise ValueError('Conferma ripristino non valida o snapshot assente')
            if not compatible_host() or LIVE.exists():
                raise ValueError('Ripristino disponibile solo sul sistema Devuan installato')
        ident = secrets.token_hex(16)
        recovery_fields = {'package_changed':True, 'snapshot_directory':meta['directory']} if action == 'rollback' else {}
        save(CACHE/'status.json', {'id':ident, 'action':action, 'state':'queued', 'phase':'Avvio operazione indipendente dal servizio web', 'started':time.time(), 'version':meta['version'], 'recovery_job':job if action == 'recover' else None, **recovery_fields})
        try:
            # Inherit the flock's open file description. The worker survives web/OpenRC restarts.
            subprocess.Popen(['/usr/bin/python3', str(Path(__file__).resolve()), 'worker', action, '--lock-fd', str(fd)],
                             pass_fds=(fd,), start_new_session=True, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
        except Exception:
            save(CACHE/'status.json', {'id':ident, 'state':'failed', 'phase':'Avvio non riuscito', 'started':time.time()})
            raise
        return {'id':ident, 'state':'queued'}


def phase(message, **fields):
    value = read(CACHE/'status.json') or {}
    save(CACHE/'status.json', {**value, **fields, 'phase':message, 'updated':time.time()})


def sync_tree(directory):
    """Reject links and bound config snapshots; never follow a user-selected path."""
    total = 0
    count = 0
    for path in directory.rglob('*'):
        count += 1
        if count > 4096:
            raise ValueError('Troppi file nella configurazione da salvare')
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError('Configurazione contiene collegamenti o file speciali non supportati')
        if path.is_file():
            total += path.stat().st_size
            if total > 128*1024*1024:
                raise ValueError('Configurazione oltre il limite di backup di 128 MiB')
            with path.open('rb') as stream:
                os.fsync(stream.fileno())
    for folder in [path for path in directory.rglob('*') if path.is_dir()] + [directory]:
        directory_fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


def snapshot():
    destination = CACHE/('snapshot-'+secrets.token_hex(16))
    destination.mkdir(mode=0o700)
    try:
        command(['dpkg-repack', 'murus-igneus'], cwd=destination)
        packages = list(destination.glob('murus-igneus_*.deb'))
        if len(packages) != 1:
            raise ValueError('Snapshot del pacchetto precedente non disponibile')
        packages[0].rename(destination/'previous.deb')
        # Check source before copying, then sync the complete snapshot before dpkg.
        sync_tree(STATE)
        shutil.copytree(STATE, destination/'configuration')
        extras = destination/'extras'; extras.mkdir(mode=0o700)
        extra_meta = {}
        for name, source in EXTRA_CONFIG.items():
            if source.is_symlink():
                raise ValueError('File di configurazione esterno non valido')
            extra_meta[name] = {'exists':source.exists()}
            if source.exists():
                if not source.is_file() or source.stat().st_size > 1024*1024:
                    raise ValueError('File di configurazione esterno oltre il limite')
                shutil.copy2(source, extras/name)
                extra_meta[name].update({'mode':source.stat().st_mode & 0o777, 'uid':source.stat().st_uid, 'gid':source.stat().st_gid})
        save(destination/'extra-config.json', extra_meta)
        sync_tree(destination)
        value = {'directory':destination.name, 'version':installed_version(),
                 'sha256':hashlib.sha256((destination/'previous.deb').read_bytes()).hexdigest()}
        save(destination/'snapshot.json', value)
        save(CACHE/'rollback.json', value)
        return value
    except Exception:
        shutil.rmtree(destination)
        raise


def rollback_snapshot():
    meta = read(CACHE/'rollback.json')
    if not meta or not re.fullmatch(r'snapshot-[a-f0-9]{32}', meta.get('directory', '')):
        raise ValueError('Snapshot locale assente o non valido')
    root = CACHE/meta['directory']
    package = root/'previous.deb'
    if root.is_symlink() or package.is_symlink() or hashlib.sha256(package.read_bytes()).hexdigest() != meta['sha256']:
        raise ValueError('Snapshot locale non integro')
    sync_tree(root/'configuration')
    return meta, root


def management_ready(timeout=45, require_marker=False):
    deadline = time.monotonic()+timeout
    # Loopback is reachable locally even when INPUT restricts remote data ports.
    context = ssl._create_unverified_context()
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(('127.0.0.1',8443), timeout=2) as sock:
                with context.wrap_socket(sock, server_hostname='localhost') as tls:
                    tls.sendall(b'GET /api/auth/status HTTP/1.0\r\nHost: localhost\r\n\r\n')
                    if tls.recv(1024).startswith(b'HTTP/1.0 401'):
                        if require_marker:
                            health = read(CACHE/'health.json') or {}
                            job = read(CACHE/'status.json') or {}
                            if health.get('job') != job.get('id'):
                                raise ValueError('La nuova versione non conferma lo stato di avvio')
                            if not health.get('ok'):
                                raise ValueError('Configurazione salvata non attivata dalla nuova versione')
                        return
        except (OSError, ssl.SSLError):
            pass
        time.sleep(1)
    raise ValueError('Amministrazione HTTPS non disponibile dopo il riavvio')


def restore():
    meta, root = rollback_snapshot()
    phase('Ripristino del pacchetto e della configurazione salvata', state='recovering')
    try:
        command(['rc-service','murus-igneus','stop'])
    except subprocess.CalledProcessError:
        pass
    # Restore files into a fresh sibling, then switch directories while web is stopped.
    temporary = STATE.with_name('.murus-restore-'+secrets.token_hex(8))
    shutil.copytree(root/'configuration', temporary)
    sync_tree(temporary)
    old = STATE.with_name('.murus-before-restore-'+secrets.token_hex(8))
    if STATE.exists():
        STATE.rename(old)
    try:
        temporary.rename(STATE)
        directory_fd = os.open(STATE.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        if old.exists():
            old.rename(STATE)
        raise
    if old.exists():
        shutil.rmtree(old)
    extra_meta = read(root/'extra-config.json') or {}
    for name, target in EXTRA_CONFIG.items():
        info = extra_meta.get(name)
        if info is None:
            raise ValueError('Snapshot dei file di avvio incompleto')
        if target.is_symlink():
            raise ValueError('Destinazione configurazione esterna non valida')
        if info['exists']:
            target.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix='.murus-config-', dir=target.parent)
            try:
                with os.fdopen(fd,'wb') as stream:
                    stream.write((root/'extras'/name).read_bytes()); stream.flush(); os.fsync(stream.fileno())
                os.chmod(temporary,info['mode']); os.chown(temporary,info['uid'],info['gid'])
                os.replace(temporary,target)
            finally:
                Path(temporary).unlink(missing_ok=True)
        else:
            target.unlink(missing_ok=True)
    command(['dpkg','--force-confold','--force-confdef','-i',str(root/'previous.deb')])
    command(['rc-service','murus-igneus','start'])
    management_ready()
    if installed_version() != meta['version']:
        raise ValueError('Versione ripristinata non corrispondente allo snapshot')


def transaction(action, directory=None):
    changed = False
    service_touched = False
    try:
        if action == 'recover':
            previous = (read(CACHE/'status.json') or {}).get('recovery_job') or {}
            for _ in range(10):
                if previous.get('action') != 'recover':
                    break
                previous = previous.get('recovery_job') or {}
            else:
                raise ValueError('Registro di recupero non valido: intervenire dalla console')
            if previous.get('package_changed'):
                backup = read(CACHE/'rollback.json') or {}
                if backup.get('directory') != previous.get('snapshot_directory'):
                    raise ValueError('Snapshot dell’operazione interrotta non corrispondente')
                restore()
            else:
                command(['rc-service','murus-igneus','start'])
                management_ready()
            phase('Operazione interrotta recuperata', state='succeeded')
            return
        if action == 'rollback':
            restore()
            phase('Pacchetto e configurazione precedenti ripristinati', state='succeeded')
            return
        directory = Path(directory)
        meta = preflight(directory)
        phase('Arresto servizio per backup coerente', state='running')
        service_touched = True
        command(['rc-service','murus-igneus','stop'])
        phase('Backup del pacchetto e della configurazione')
        try:
            saved = snapshot()
        except Exception:
            command(['rc-service','murus-igneus','start'])
            management_ready()
            service_touched = False
            raise
        phase('Installazione del pacchetto firmato', package_changed=True, snapshot_directory=saved['directory'])
        changed = True
        command(['dpkg','--force-confold','--force-confdef','-i',str(directory/'murus-igneus.deb')])
        phase('Riavvio e verifica amministrazione HTTPS')
        command(['rc-service','murus-igneus','start'])
        management_ready(require_marker=True)
        if installed_version() != meta['version']:
            raise ValueError('Versione installata non corrispondente al bundle')
        phase('Aggiornamento applicativo completato', state='succeeded')
    except Exception as exc:
        if changed:
            try:
                restore()
            except Exception as recovery:
                phase('Ripristino incompleto: intervenire dalla console', state='recovery_required', error=str(exc)[:300], recovery_error=str(recovery)[:300])
                raise exc from recovery
            phase('Aggiornamento fallito; versione e configurazione precedenti ripristinate', state='failed', error=str(exc)[:500], recovered=True)
        else:
            phase('Operazione non completata', state='recovery_required' if service_touched or action in ('rollback','recover') else 'failed', error=str(exc)[:500])
        raise


def install(directory):
    with locked():
        if (read(CACHE/'status.json') or {}).get('state') in ACTIVE_STATES | {'recovery_required'}:
            raise ValueError('Ripristinare prima l’operazione precedente')
        # Never install from the caller's mutable directory after verification.
        with tempfile.TemporaryDirectory(dir=CACHE) as temporary:
            work = Path(temporary)
            for name, limit in (('manifest.json',4096),('manifest.sig',64),('murus-igneus.deb',8*1024*1024)):
                fd = os.open(Path(directory)/name,os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(fd,'rb') as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        raise ValueError('File bundle non regolare')
                    content = stream.read(limit+1)
                if not 0 < len(content) <= limit:
                    raise ValueError('Dimensione bundle non valida')
                (work/name).write_bytes(content); (work/name).chmod(0o600)
            save(CACHE/'status.json', {'id':secrets.token_hex(16), 'state':'running', 'action':'install', 'started':time.time()})
            transaction('install', work)


def rollback():
    with locked():
        if (read(CACHE/'status.json') or {}).get('state') in ACTIVE_STATES | {'recovery_required'}:
            raise ValueError('Usare recover per l’operazione interrotta')
        meta = read(CACHE/'rollback.json') or {}
        save(CACHE/'status.json', {'package_changed':True, 'snapshot_directory':meta.get('directory'), 'state':'recovering', 'action':'rollback', 'started':time.time()})
        transaction('rollback')


def main():
    parser = argparse.ArgumentParser(description='Aggiornamenti firmati della sola applicazione Murus Igneus')
    parser.add_argument('action', choices=['verify','install','rollback','recover','status','worker'])
    parser.add_argument('bundle', nargs='?')
    parser.add_argument('--lock-fd', type=int)
    args = parser.parse_args()
    if args.action not in ('verify','status') and os.geteuid() != 0:
        parser.error('Operazione riservata a root')
    if args.action == 'verify':
        if not args.bundle:
            parser.error('Indicare la directory bundle')
        print(json.dumps(verify(args.bundle)))
    elif args.action == 'status':
        print(json.dumps(inventory(), ensure_ascii=False))
    elif args.action == 'install':
        if not args.bundle:
            parser.error('Indicare la directory bundle')
        install(args.bundle)
    elif args.action == 'rollback':
        rollback()
    elif args.action == 'recover':
        with locked():
            previous = read(CACHE/'status.json') or {}
            if previous.get('state') not in ACTIVE_STATES | {'recovery_required'}:
                raise ValueError('Nessuna operazione interrotta da recuperare')
            save(CACHE/'status.json', {'action':'recover','state':'recovering','recovery_job':previous})
            transaction('recover')
    else:
        if args.lock_fd is None or args.bundle not in ('install','rollback','recover'):
            parser.error('Worker non valido')
        try:
            transaction(args.bundle, CACHE/'staged' if args.bundle == 'install' else None)
        finally:
            os.close(args.lock_fd)



def mark_health(ok):
    private_cache()
    job = read(CACHE/'status.json') or {}
    save(CACHE/'health.json', {'job':job.get('id'), 'ok':bool(ok), 'pid':os.getpid(), 'time':time.time()})

if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        raise SystemExit('Aggiornamento fallito: '+str(exc)) from None
