# Murus Igneus 0.3.0-alpha

Experimental open-source IPv4 firewall targeting **Devuan 6 Excalibur / OpenRC**.

The recovered application source is committed under `src/murus_igneus/`.
It provides a native configuration editor and conservative import of a subset
of text FortiGate backups. IPv4 policies, static routing, SNAT and rollback come
from the original OpenWall laboratory prototype; they require renewed runtime
verification after migration and rebranding.

A `.deb` build and native OpenRC service are now provided in `packaging/devuan/`.
See [docs/DEVUAN.md](docs/DEVUAN.md). The package targets an already installed
Devuan laboratory VM and is not started automatically during installation.

**No Devuan bootable ISO has been built or validated.** A web disk installer,
VPN, UTM/Suricata/ClamAV and AI are planned and not implemented in this alpha.
The known lab password is not suitable for exposed or production deployments.
Original MIT application attribution is preserved alongside repository notices.
