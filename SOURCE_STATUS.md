# Validation status — 0.3.0-alpha

Source integrates a Devuan 6 Excalibur ISO builder, native `.deb`/OpenRC service,
a live web disk installer, WireGuard, Suricata NFQUEUE IPS and ClamAV-backed
explicit HTTP download proxy. The firewall can be configured without a backup.

Verified: 47 automated tests, application/JavaScript/shell syntax and `.deb`
build. Tests cover configuration/migration, CSRF, VPN route conflicts, IPS queue
compilation and destructive installer confirmation checks.

A first hybrid BIOS/UEFI ISO was generated on GitHub Actions and its downloaded
SHA-256 matched. In a disposable QEMU BIOS VM, the live system booted,
authenticated HTTPS responded and installer inventory found the blank 10 GiB
disk. With integration fixes applied to the live VM, actual traffic checks
passed for HTTP forwarding/SNAT, deny and rollback, Suricata HTTP signature
blocking, engine-termination fail-closed behavior, WireGuard handshake and
policy-controlled VPN-to-LAN traffic including deny/rollback.

Disk installation, installed-system reboot and UEFI boot tests are pending.
Official ClamAV definitions and AV proxy functional checks are pending:
the build environment's database download returned HTTP 403; VM network is restricted in this environment (public DNS is unavailable).
The builder attempts an official signature download separately and records
its result in `signature-status.txt`. No complete malware protection is claimed without signatures.
`tools/validate-devuan-runtime.py` reproduces traffic checks only in an explicitly
flagged disposable live VM; it must not run on real networks.

Only signed Devuan `main` packages enter the fresh target filesystem. The build
rejects non-free/contrib sections and firmware/microcode package names. No
Fortinet code or firmware is used.

Antivirus covers proxy HTTP downloads only (20 MiB); no HTTPS decryption.
IPsec, FortiGate VPN conversion and AI are not implemented. See docs/DEVUAN.md.
