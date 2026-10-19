# Murus Igneus 0.3.0-alpha

Experimental independent open-source IPv4 firewall on Devuan 6 Excalibur / OpenRC.
No Fortinet code, firmware or assets are used. Original MIT application notices
are preserved alongside the repository GPL-3 license.

The native editor can configure a firewall from scratch; importing a supported
subset of a plaintext FortiGate backup is optional. Features include nftables
policies/SNAT, static routing, confirmed apply with rollback, WireGuard peers,
Suricata inline IPS and an explicit HTTP download proxy using ClamAV.

`tools/build-devuan-iso.sh` builds a fresh system from signed Devuan `main`
packages. The live interface includes a disk installer requiring the exact
selected disk to be confirmed before erasure. A separate `.deb` build supports
existing dedicated Devuan VMs.

ClamAV scanning applies only to HTTP GET/HEAD downloads through the proxy,
up to 20 MiB. HTTPS antivirus inspection, IPsec and AI are not implemented.
ClamAV requires official signature downloads; the two bundled local IPS rules
provide limited coverage until community rules are downloaded.

See [the Devuan guide](docs/DEVUAN.md) and [validation status](SOURCE_STATUS.md).
The lab web login is `admin` / `igneus`; a fresh ISO also uses root / `igneus`.
The `.deb` preserves existing credentials and never changes the root password.
