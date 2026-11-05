# Signed application updates

[Italiano](UPDATES.md) · **English** · [Documentation](INDEX.md)

**Sistema → Aggiornamenti** updates Murus Igneus on installed Devuan 6 Excalibur. It is unavailable in live mode and does not update Devuan, the kernel, bootloader or firmware.

## Release catalog and trust

Checking the GitHub catalog is manual. The stable channel excludes prereleases; the experimental channel includes alpha/beta. Release notes are plain text. No downloads or installations start automatically. Private repositories may return 403/404; use an offline bundle in that case. The appliance does not store a GitHub token for this feature.

From the console, provision a trusted Ed25519 public key in `/etc/murus_igneus/update.pub`. It must be owned by root and not writable by group or others. Verify the key through an independent channel. A public key shipped alongside an untrusted download is not proof of its authenticity. Keep the private key on the signing machine, outside the appliance and repository. CI does not generate a production signing key.

A maintainer with a private key can create a bundle:

```sh
python3 tools/sign-update-bundle.py murus-igneus_VERSION_all.deb --key /private/signing.pem --output bundle-VERSION
```

Upload the resulting `manifest.json`, `manifest.sig` (64-byte binary signature) and `murus-igneus.deb`. The signed manifest includes schema, package name, Debian version and SHA-256. The verifier also checks DEB name, version and architecture. Unsigned checksums, writable trust keys and packages at the same or an older version are rejected. Older versions without an updates page need a one-time bootstrap from a trusted ISO or manual DEB installation.

## Web installation

1. Upload all three files. The DEB limit is 4 MiB, and the manifest limit is 4096 bytes.
2. Review version, signature, digest and metadata.
3. Type the exact confirmation shown. It begins with `AGGIORNA` and includes the Debian version.
4. Wait for the backup, installation and return of HTTPS. Forwarding is interrupted during the restart.

Verification expires after 30 minutes or on another successful upload. The operation uses the confirmed configuration, not the browser draft. Pending changes, maintenance jobs and switch/parental tasks block updates. During update or recovery, other API writes and automatic parental feed refresh are blocked.

An independent worker survives web restart and records progress atomically in `/var/lib/murus-igneus/updates/status.json`. The service stops before snapshots are taken: the previous DEB with its local digest, `/etc/murus_igneus`, `/etc/default/murus-igneus` and `/etc/sysctl.d/90-murus-igneus.conf`. Snapshots stay local and root-only and can include secrets. At least 256 MiB free is required; configuration is limited to 128 MiB and 4096 entries. Symlinks and special files are rejected. Existing conffiles are kept. Missing system dependencies cause the upgrade to fail; the updater does not install them automatically.

The worker verifies the installed DEB version, HTTPS and successful startup with the saved configuration. A handled failure restores the prior package and configuration. Failed recovery blocks further changes and is recorded.

## Rollback and interrupted jobs

Manual rollback requires the exact `RIPRISTINA` prompt with the target version. It restores the snapshot configuration as well as the package, so confirmed changes made after the snapshot are lost.

For **Recupero necessario**, type `RECUPERA SERVIZIO`. If the package had not been written, this restarts the service. Otherwise it restores the specific snapshot for the interrupted operation. If HTTPS is unavailable, use the console:

```sh
murus-update status
murus-update recover
```

Other commands: `murus-update verify DIRECTORY`, `murus-update install DIRECTORY` and `murus-update rollback`. Console installation also uses a verified private copy of the bundle. Normal updates leave the shared console password intact; `/etc/shadow` is outside application snapshots. There is no A/B OS mechanism or guarantee of automatic recovery after power loss, disk failure or filesystem corruption.

## Verification

Tests exercise Ed25519 and real DEBs, HTTP authorization and CSRF, independent locking and controlled failures. Chromium uses controlled responses. `tools/validate-updates-runtime.py` is for the disposable installed Devuan VM only: it actually changes packages, restarts OpenRC/HTTPS, injects a failing postinst and tests rollback and console recovery with a temporary key.

ClamAV signatures and Suricata rules are managed from UTM; Devuan APT updates are separate.
