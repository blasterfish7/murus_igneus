# Devuan 6 Excalibur / OpenRC

Murus Igneus 0.3.0-alpha now has a Debian-format package for an **existing Devuan
6 Excalibur amd64 laboratory VM** and a fresh ISO builder with live web installer.
See `SOURCE_STATUS.md` for current build and runtime verification status.

## Distribution and software provenance

Use the `excalibur`, `excalibur-updates` and `excalibur-security` suites from
`deb.devuan.org/merged`, **main only**, as in `packaging/devuan/sources.list`.
Use the official `devuan-keyring` and APT signature verification. Never enable
`trusted=yes`, unauthenticated installation or mixed Debian/Ubuntu repositories.

The official Devuan live ISOs include non-free firmware. Therefore, merely
remastering an unmodified live ISO does not satisfy this project's free-software
requirement. The Murus builder instead bootstraps a fresh root from signed main
packages and rejects non-free/contrib and firmware/microcode package names.
The builder seed is not copied into the target image.

References:
- https://www.devuan.org/os/releases
- https://www.devuan.org/os/packages
- https://www.devuan.org/os/install

## Build the package

On a machine with Python 3 and `dpkg-deb`:

```sh
sh packaging/devuan/build-deb.sh
```

This creates `dist/murus-igneus_0.3.0~alpha.2_all.deb`. Building the package does
not require root, a chroot, network access, or changes to the host firewall.
The payload preserves the MIT attribution of the recovered application code
alongside the repository's GPL-3 license file. It includes no Alpine installer,
firmware, credentials, VPN keys or development disk images.

## Install on a dedicated Devuan VM

Install Devuan 6 Excalibur first. Configure APT as above, including the signed
security and updates suites. Follow the Devuan/OpenRC transition instructions
if the machine does not yet use OpenRC. This package is not for a general-purpose
host: starting its service applies an IPv4 default-deny firewall and manages
forwarding on that VM.

```sh
sudo apt update
sudo apt install ./dist/murus-igneus_0.3.0~alpha.2_all.deb
ip -br address
sudo editor /etc/default/murus-igneus
```

Set `MURUS_MANAGEMENT_INTERFACE` to the actual management port, for example
`ens18` or `enp1s0`. Its existing IPv4 address is preserved. Only if it has no
IPv4 address is `MURUS_MANAGEMENT_FALLBACK=192.168.56.1/24` added. Existing host
network configuration and default routes are not rewritten by the package.

Package installation deliberately does not start the firewall. Once its
management interface is configured and the console is available:

```sh
sudo rc-update add murus-igneus default
sudo rc-service murus-igneus start
sudo /usr/sbin/murus-info
```

Open `https://MANAGEMENT-IP:8443`. The initial web login is `admin` / `igneus`,
matching the development branch's existing choice. An existing web password is
preserved. The Devuan root password is never changed by this package.
TLS certificates and `/etc/murus_igneus/active.json` are generated/persisted on
the installed filesystem. Logs are written to `/var/log/murus-igneus.log`.

## What was checked

- Building and inspecting the `.deb` payload and executable/root ownership modes.
- Existing configuration translator regression tests.
- HTTP preview requests using the corrected `X-Murus-Igneus-CSRF` header,
  rejection of incorrect tokens, configurable/reserved management interface.
- Python and shell syntax and JavaScript syntax/header construction.

See `SOURCE_STATUS.md` for the VM evidence for each build. Automated tests and
QEMU checks do not establish compatibility with every physical NIC or platform.

## ISO build

Run only in an isolated privileged Devuan builder, never on a workstation:

```sh
bash tools/build-devuan-iso.sh
```

Outputs under `dist/`: hybrid BIOS/UEFI amd64 ISO, `SHA256SUMS` and
`packages-devuan.tsv`. GitHub Actions builds on branch pushes. The builder
attempts an official ClamAV database download (five-minute limit) and records
the outcome in `signature-status.txt`; an unavailable download does not imply
antivirus coverage. Set `MURUS_FETCH_SIGNATURES=0` to explicitly skip it. Secure Boot is
not provided. Management is the first NIC (`eth0`), DHCP with a
`192.168.56.1/24` fallback. The second and third NICs are configured in the UI.
A fresh ISO uses root / `igneus` and web admin / `igneus`.

Boot the ISO, open HTTPS management on port 8443 and choose configuration from
scratch or optional backup import. Use **Installa su disco** to list unmounted
disks of at least 8 GiB, preview the operation and type `CANCELLA /dev/DEVICE`
for the exact selected disk. The installer erases the whole disk, installs GPT
BIOS/EFI boot and ext4, and copies confirmed configuration, keys and signatures.
After successful completion, power off, remove the ISO and boot the disk.
Live-session changes are otherwise temporary.

## VPN and UTM scope

- WireGuard: server key stays on the appliance; enter client public keys and
  specific remote CIDRs. The synthetic VPN interface participates in policies.
  IPsec and FortiGate VPN conversion are not included.
- Suricata: inline IPv4 forwarding inspection after policy filtering, NFQUEUE
  without bypass. If the engine stops, queued traffic is dropped. Two local HTTP
  signatures are included; download community rules for broader coverage.
  Community rules retain their original alert/drop actions; downloading them
  does not automatically turn every alert into a blocking rule.
- ClamAV: explicit HTTP proxy on the selected data NIC, port 3128, client CIDR
  and destination ACLs, domain blocking, GET/HEAD downloads up to 20 MiB.
  Download official definitions before enabling it. Content is delivered only
  after a successful clean scan. Encoded/partial upstream responses are refused
  rather than delivered without inspecting their complete clear representation.
  CONNECT and HTTPS antivirus inspection are
  unavailable. Proxy-originated traffic uses its own destination ACL rather
  than forwarding policies.
- Signature updates run as visible background jobs. Reapply the configuration
  to reload updated signatures. A local Ollama/Qwen3 connector and SNMP switch management are included; see [setup](AI-SWITCHES.md).

Real VM validation is tracked separately in `SOURCE_STATUS.md`.

## Disposable VM traffic checks

With three NICs and no connection to a production LAN, run from the serial
console of a disposable live VM:

```sh
MURUS_LAB=YES python3 tools/validate-devuan-runtime.py
```

The script creates network namespaces/veth interfaces, replaces the appliance
configuration and checks actual forwarding, rollback, IPS and WireGuard. It
also attempts official ClamAV updates and proxy/EICAR tests. For an offline
network-only run, explicitly add `MURUS_SKIP_SIGNATURE_UPDATE=YES`; this skips
antivirus verification and is reported as such. The test never selects or
erases a disk.

