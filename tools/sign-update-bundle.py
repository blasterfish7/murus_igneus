#!/usr/bin/env python3
"""Create an offline application bundle with an operator-supplied Ed25519 key. MIT."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src/murus_igneus'))
import updates


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', type=Path)
    parser.add_argument('--key', required=True, type=Path, help='Existing private signing key; never included in the bundle')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Output directory already exists')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=args.output.parent) as temporary:
        work = Path(temporary)
        shutil.copyfile(args.package, work/'murus-igneus.deb')
        meta = {'schema':1, 'package':'murus-igneus',
                'version':updates.command(['dpkg-deb','-f',str(args.package),'Version']),
                'sha256':hashlib.sha256((work/'murus-igneus.deb').read_bytes()).hexdigest()}
        (work/'manifest.json').write_text(json.dumps(meta, sort_keys=True)+'\n')
        updates.command(['openssl','pkey','-in',str(args.key),'-pubout','-out',str(work/'signer.pub')])
        updates.command(['openssl','pkeyutl','-sign','-inkey',str(args.key),'-rawin','-in',str(work/'manifest.json'),'-out',str(work/'manifest.sig')])
        updates.verify(work, work/'signer.pub')
        # Public key delivery/provisioning remains a separate trust decision.
        (work/'signer.pub').unlink()
        work.rename(args.output)
    print(json.dumps(meta))


if __name__ == '__main__':
    main()
