"""Offline Ed25519-signed application package updates and local rollback. SPDX-License-Identifier: MIT."""
import argparse
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


def verify(directory, key=TRUST_KEY):
    directory = Path(directory)
    manifest = directory / 'manifest.json'; signature = directory / 'manifest.sig'; package = directory / 'murus-igneus.deb'
    for path, limit in ((manifest, 4096), (signature, 64), (package, 8 * 1024 * 1024)):
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= limit:
            raise ValueError('Bundle di aggiornamento non valido')
    if not key.is_file() or signature.stat().st_size != 64:
        raise ValueError('Chiave pubblica Ed25519 mancante o firma non valida')
    # Enforce Ed25519, not just any algorithm accepted by pkeyutl.
    public = command(['openssl', 'pkey', '-pubin', '-in', str(key), '-text', '-noout'])
    if 'ED25519' not in public.upper():
        raise ValueError('È richiesta una chiave pubblica Ed25519')
    command(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', str(key), '-rawin', '-in', str(manifest), '-sigfile', str(signature)])
    meta = json.loads(manifest.read_text())
    if not isinstance(meta, dict) or set(meta) != {'schema', 'package', 'version', 'sha256'} or meta['schema'] != 1 or meta['package'] != 'murus-igneus':
        raise ValueError('Manifest non supportato')
    if hashlib.sha256(package.read_bytes()).hexdigest() != meta['sha256']:
        raise ValueError('Checksum pacchetto non corrispondente alla firma')
    for field, expected in [('Package', 'murus-igneus'), ('Version', meta['version']), ('Architecture', 'all')]:
        if command(['dpkg-deb', '-f', str(package), field]) != expected:
            raise ValueError('Metadati DEB non corrispondenti al manifest')
    return meta


def replace_file(source, target):
    temporary = target.with_suffix('.tmp'); shutil.copyfile(source, temporary); temporary.chmod(0o600); temporary.replace(target)


def install(directory):
    CACHE.mkdir(mode=0o700, parents=True, exist_ok=True); CACHE.chmod(0o700)
    with tempfile.TemporaryDirectory(dir=CACHE) as work:
        work = Path(work)
        # Verify the root-owned snapshot, preventing a source-bundle TOCTOU.
        for name in ('manifest.json', 'manifest.sig', 'murus-igneus.deb'):
            source = Path(directory) / name
            if source.is_symlink() or source.stat().st_size > 8 * 1024 * 1024:
                raise ValueError('File bundle non valido')
            shutil.copyfile(source, work / name)
        meta = verify(work)
        current = command(['dpkg-query', '-W', '-f=${Version}', 'murus-igneus'])
        if subprocess.run(['dpkg', '--compare-versions', meta['version'], 'gt', current]).returncode:
            raise ValueError('Versione non più recente: per ripristinare usare rollback')
        # Build the rollback package before changing the running installation.
        command(['dpkg-repack', 'murus-igneus'], cwd=work)
        previous = next(p for p in work.glob('murus-igneus_*.deb'))
        install_package(work / 'murus-igneus.deb', previous)
        replace_file(previous, CACHE / 'previous.deb')
        (CACHE / 'previous.sha256').write_text(hashlib.sha256(previous.read_bytes()).hexdigest()); (CACHE / 'previous.sha256').chmod(0o600)
        print('Applicazione aggiornata a ' + meta['version'] + '. Snapshot locale disponibile per rollback.')


def install_package(package, restore):
    running = subprocess.run(['rc-service', 'murus-igneus', 'status'], capture_output=True).returncode == 0
    if running:
        command(['rc-service', 'murus-igneus', 'stop'])
    try:
        command(['dpkg', '-i', str(package)])
        if running:
            command(['rc-service', 'murus-igneus', 'start'])
    except Exception:
        command(['dpkg', '-i', str(restore)])
        if running:
            command(['rc-service', 'murus-igneus', 'start'])
        raise


def rollback():
    previous = CACHE / 'previous.deb'
    if hashlib.sha256(previous.read_bytes()).hexdigest() != (CACHE / 'previous.sha256').read_text().strip():
        raise ValueError('Snapshot locale non integro')
    with tempfile.TemporaryDirectory(dir=CACHE) as work:
        command(['dpkg-repack', 'murus-igneus'], cwd=work)
        current = next(Path(work).glob('murus-igneus_*.deb'))
        install_package(previous, current)
    print('Snapshot applicativo precedente ripristinato; configurazione e sistema operativo conservati.')


def main():
    parser = argparse.ArgumentParser(description='Aggiornamento offline firmato della sola applicazione Murus Igneus')
    parser.add_argument('action', choices=['verify', 'install', 'rollback'])
    parser.add_argument('bundle', nargs='?'); args = parser.parse_args()
    if args.action != 'verify' and os.geteuid() != 0:
        parser.error('Installazione e rollback richiedono root')
    import fcntl
    if args.action == 'verify':
        if not args.bundle:
            parser.error('Indicare la directory bundle')
        print(json.dumps(verify(args.bundle))); return
    CACHE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (CACHE / 'update.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.action == 'install':
            if not args.bundle:
                parser.error('Indicare la directory bundle')
            install(args.bundle)
        else:
            rollback()


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        raise SystemExit('Aggiornamento fallito: ' + str(exc)) from None
