# Devuan 6 Excalibur / OpenRC

Murus Igneus 0.3.0-alpha now has a Debian-format package for an **existing Devuan
6 Excalibur amd64 laboratory VM**. This is a packaging and service migration;
it is not a bootable ISO or a verified replacement for the previous Alpine ISO.

## Distribution and software provenance

Use the `excalibur`, `excalibur-updates` and `excalibur-security` suites from
`deb.devuan.org/merged`, **main only**, as in `packaging/devuan/sources.list`.
Use the official `devuan-keyring` and APT signature verification. Never enable
`trusted=yes`, unauthenticated installation or mixed Debian/Ubuntu repositories.

The official Devuan live ISOs include non-free firmware. Therefore, merely
remastering an unmodified live ISO does not satisfy this project's free-software
requirement. The future Murus ISO must bootstrap from signed main packages, or
remove non-free components and verify both the root filesystem and initramfs.
No such image is included or claimed as tested here.

References:
- https://www.devuan.org/os/releases
- https://www.devuan.org/os/packages
- https://www.devuan.org/os/install

## Build the package

On a machine with Python 3 and `dpkg-deb`:

```sh
sh packaging/devuan/build-deb.sh
```

This creates `dist/murus-igneus_0.3.0~alpha.1_all.deb`. Building the package does
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
sudo apt install ./dist/murus-igneus_0.3.0~alpha.1_all.deb
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

These checks do not replace boot/runtime tests on Devuan. OpenRC startup,
VirtIO naming, networking, real packet filtering/NAT, reboot persistence and
service failure/rollback behavior still require VM regression testing.

## Outstanding requested functionality

- ISO builder and bootable ISO, with a web disk-installation workflow.
- WireGuard/IPsec VPN integrated with policies, routes and protected keys.
- Suricata IPS, antivirus with ClamAV and signature updates, traffic/proxy
  integration, filtering and accurate protection status in the GUI.
- HTTPS file scanning requires an explicit TLS inspection design and certificate
  deployment. Installing antivirus packages alone does not inspect transit TLS.

VPN, UTM and AI remain planned, not operational features in this package.
