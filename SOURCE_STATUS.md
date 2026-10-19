# Verification status — 0.3.0-alpha

Verified 2026-10-19. Laboratory software, not a production release.

## Delivered build

Source commit: `01362b615107f288c4e302cf013747d17e2e3380`.
Actions: https://github.com/blasterfish7/murus_igneus/actions/runs/39308263309

ISO: `murus-igneus-0.3.0-alpha-devuan-amd64.iso`, 459872256 bytes.
SHA-256: `2a69f85c5956488b102d7a3c8e6cb305fade952340a027d88335d7d0d37f46c4`.

Devuan 6 Excalibur / OpenRC, freshly bootstrapped from signed main packages.
Official ClamAV main/daily/bytecode downloads and database validation succeeded.
No test-only signature database was substituted.

## Completed checks

48 automated tests pass locally and in Actions, plus syntax and native .deb checks.
Coverage includes translation, CSRF, management reservation, VPN route conflicts,
the distribution Suricata configuration, installer confirmation and refusal of
encoded HTTP responses that cannot be inspected as clear content.

Actual traffic tests in disposable QEMU networks passed:

- Native configuration without a backup; HTTP forwarding, SNAT, deny and rollback.
- Suricata allowing clean HTTP, blocking a bundled attack signature, and dropping
  forwarded traffic after the IPS engine is terminated.
- WireGuard handshake, policy-controlled VPN-to-LAN traffic, deny and rollback.
- Real ClamAV with official databases: clean proxy downloads allowed, EICAR and a
  blocked domain refused; no content delivered after terminating clamd.

The final ISO booted in UEFI under QEMU TCG, 2 vCPU / 6 GiB RAM / three VirtIO NICs.
Browser checks passed for configuration from scratch, preview/apply/confirm,
VPN key display, VPN policy selection, enabling VPN/IPS/antivirus together and
exact disk-erasure confirmation. DHCP remained on management only.

The full database loaded in about 82 seconds under emulation. Startup now allows
five minutes instead of timing out at 60 seconds.

The web installer completed GPT BIOS/EFI/ext4 installation on a disposable 10 GiB
disk. The final installed system booted in UEFI without the ISO. Checks confirmed:

- Root on /dev/vda3 and OpenRC service started.
- Exact native configuration and WireGuard server key preserved.
- Policy IDs 10/20, SNAT, forwarding and the IPS queue restored.
- WireGuard, Suricata, clamd and proxy active after reboot.
- Clean/EICAR scanning correct after reboot.
- Live-only installer disabled on the installed system.

BIOS live/disk boot was also verified on an earlier Devuan candidate using the
same installer. Traffic checks include the startup-timeout correction tested in
the live VM and delivered in the final build. These are functional lab checks,
not performance, broad hardware-compatibility or security-audit results.

## Limits

Antivirus covers explicit proxy HTTP GET/HEAD downloads up to 20 MiB.
Encoded/partial responses and CONNECT are refused. HTTPS antivirus inspection
is unavailable. Proxy requests use their own client/destination ACLs rather than
forwarding policies. The two local IPS signatures have limited coverage;
community rules retain their original alert/drop actions.

ClamAV from the Devuan repository is 1.4.3; FreshClam recommends 1.4.6.
Address this version gap before considering production use. Initial credentials
are public: admin / igneus, console root / igneus. IPsec, FortiGate VPN conversion,
HA, VLAN configuration, IPv6 and AI are not implemented.

No Fortinet code, firmware or assets are included. Original MIT notices are
preserved alongside repository licensing. See docs/DEVUAN.md and docs/PROVENANCE.md.

tools/validate-devuan-runtime.py replaces configuration and creates namespaces:
run it only in an explicitly flagged disposable live VM, never on a real network.
It does not erase a disk.
