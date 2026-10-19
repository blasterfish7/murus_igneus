# Devuan packaging

Target: **Devuan 6 Excalibur, OpenRC, nftables and Python**. Build with:

```sh
sh packaging/devuan/build-deb.sh
```

The generated `.deb` can be installed on an existing, dedicated Devuan VM.
It includes the independent application and native OpenRC service, configurable
management port and fallback address. It does not change the root password and
does not start the firewall during installation.

Only official signed Devuan `main` repositories are intended. The existing
Alpine disk installer under `legacy/` is excluded from the package.

See [the Devuan guide](../../docs/DEVUAN.md) for installation and limitations.
An ISO builder/web disk installer and the VPN/UTM integration are still pending.
