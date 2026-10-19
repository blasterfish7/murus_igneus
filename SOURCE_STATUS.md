# Validation status — 0.3.0-alpha

Source integrates a Devuan 6 Excalibur ISO builder, native `.deb`/OpenRC service,
a live web disk installer, WireGuard, Suricata NFQUEUE IPS and ClamAV-backed
explicit HTTP download proxy. The firewall can be configured without a backup.

Verified: 45 automated tests, application/JavaScript/shell syntax and `.deb`
build. Tests cover configuration/migration, CSRF, VPN route conflicts, IPS queue
compilation and destructive installer confirmation checks.

A first BIOS/UEFI ISO was built successfully on GitHub Actions and its SHA-256
was verified after download. Real VM testing is in progress. Successful unit tests do
not establish VPN handshakes, actual IPS/antivirus blocking, boot or disk-install
correctness. This branch remains experimental until those checks are recorded.

Only signed Devuan `main` packages enter the fresh target filesystem. The build
rejects non-free/contrib sections and firmware/microcode package names. No
Fortinet code or firmware is used.

Antivirus covers proxy HTTP downloads only (20 MiB); no HTTPS decryption.
IPsec, FortiGate VPN conversion and AI are not implemented. See docs/DEVUAN.md.
