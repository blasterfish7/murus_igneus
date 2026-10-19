# Source status — 0.3.0-alpha

The development branch contains recovered/rebranded OpenWall application files
and translator tests. The complete original build/integration environment is
not reproduced here. Original MIT notices are preserved in the application
source alongside the repository's GPL-3 license.

New Devuan support consists of a buildable `.deb`, an OpenRC service, management
interface configuration and packaging/HTTP regression checks. The target is
Devuan 6 Excalibur using signed `main` packages only. This is not a statement
that an installed Devuan appliance has passed VM/boot/runtime validation.

No Devuan bootable ISO, web disk installer, VPN, UTM or AI is implemented or
validated by this branch. In particular, antivirus packages alone do not scan
transit traffic. The initial lab credential is `admin` / `igneus`; existing web
credentials and the Devuan console/root password are preserved.

See `docs/DEVUAN.md` for exact build, installation, checks and remaining work.
