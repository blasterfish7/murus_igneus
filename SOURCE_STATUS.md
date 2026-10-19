# Validation status — 0.3.0-alpha

Source integrates a Devuan 6 Excalibur ISO builder, native `.deb`/OpenRC service,
a live web disk installer, WireGuard, Suricata NFQUEUE IPS and ClamAV-backed
explicit HTTP download proxy. The firewall can be configured without a backup.

Verified: 48 automated tests, application/JavaScript/shell syntax and `.deb`
build. Tests cover configuration/migration, CSRF, VPN route conflicts, IPS queue
compilation and destructive installer confirmation checks.

A first hybrid BIOS/UEFI ISO was generated on GitHub Actions and its downloaded
SHA-256 matched. In a disposable QEMU BIOS VM, the live system booted,
authenticated HTTPS responded and installer inventory found the blank 10 GiB
disk. With integration fixes applied to the live VM, actual traffic checks
passed for HTTP forwarding/SNAT, deny and rollback, Suricata HTTP signature
blocking, engine-termination fail-closed behavior, WireGuard handshake and
policy-controlled VPN-to-LAN traffic including deny/rollback.

The web installer backend completed GPT BIOS/EFI/ext4 installation on a
disposable 10 GiB disk. The installed system then booted in BIOS mode without
the ISO; confirmed physical interface configuration/NAT and the VPN server key
were preserved, and the live-only installer was disabled.

UEFI boot, browser installation flow and full ClamAV proxy checks are pending.
The official ClamAV database download succeeded in the GitHub build, so that
build includes validated official signatures. The local VM environment cannot
resolve public DNS directly; bundled databases permit offline traffic tests.
`tools/validate-devuan-runtime.py` reproduces traffic checks only in an explicitly
flagged disposable live VM; it must not run on real networks.

Only signed Devuan `main` packages enter the fresh target filesystem. The build
rejects non-free/contrib sections and firmware/microcode package names. No
Fortinet code or firmware is used.

Antivirus covers proxy HTTP downloads only (20 MiB); no HTTPS decryption.
IPsec, FortiGate VPN conversion and AI are not implemented. See docs/DEVUAN.md.
