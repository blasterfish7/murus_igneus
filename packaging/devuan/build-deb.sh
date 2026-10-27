#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
umask 022
root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
output=${1:-"$root/dist"}
mkdir -p "$output"
output=$(CDPATH='' cd -- "$output" && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM
install -d "$stage/DEBIAN" "$stage/usr/lib/murus-igneus" "$stage/usr/sbin" "$stage/etc/init.d" "$stage/etc/default" "$stage/usr/share/doc/murus-igneus" "$stage/etc/sysctl.d"
for file in __init__.py server.py configuration.py migration.py security.py avproxy.py jobs.py installer.py networking.py traffic.py parental_report.py parental.py parental.js eventlog.py authentication.py enterprise.py enterprise.js updates.py network.js tasks.py assistant.py switches.py management.js index.html app.js style.css LICENSE-MIT; do
    install -m 0644 "$root/src/murus_igneus/$file" "$stage/usr/lib/murus-igneus/$file"
done
for file in murus-serve murus-prepare murus-info murus-update murus-install; do
    install -m 0755 "$root/packaging/devuan/files/$file" "$stage/usr/sbin/$file"
done
install -d "$stage/etc/profile.d"
install -m 0644 "$root/packaging/devuan/files/murus-welcome.sh" "$stage/etc/profile.d/murus-welcome.sh"
install -m 0755 "$root/packaging/devuan/files/murus-igneus.initd" "$stage/etc/init.d/murus-igneus"
install -m 0644 "$root/packaging/devuan/files/murus-igneus.default" "$stage/etc/default/murus-igneus"
install -m 0644 "$root/packaging/devuan/files/90-murus-igneus.conf" "$stage/etc/sysctl.d/90-murus-igneus.conf"
install -m 0644 "$root/LICENSE" "$stage/usr/share/doc/murus-igneus/LICENSE-GPL-3"
install -m 0644 "$root/src/murus_igneus/LICENSE-MIT" "$stage/usr/share/doc/murus-igneus/LICENSE-MIT"
install -m 0644 "$root/docs/DEVUAN.md" "$stage/usr/share/doc/murus-igneus/DEVUAN.md"
install -m 0644 "$root/docs/AI-SWITCHES.md" "$stage/usr/share/doc/murus-igneus/AI-SWITCHES.md"
install -m 0644 "$root/docs/NATIVE-NETWORKING.md" "$stage/usr/share/doc/murus-igneus/NATIVE-NETWORKING.md"
install -m 0644 "$root/docs/ALPHA9.md" "$stage/usr/share/doc/murus-igneus/ALPHA9.md"
install -m 0644 "$root/docs/ALPHA8.md" "$stage/usr/share/doc/murus-igneus/ALPHA8.md"
install -m 0644 "$root/docs/ALPHA7.md" "$stage/usr/share/doc/murus-igneus/ALPHA7.md"
install -m 0644 "$root/docs/ALPHA5.md" "$stage/usr/share/doc/murus-igneus/ALPHA5.md"
install -m 0644 "$root/docs/PARENTAL.md" "$stage/usr/share/doc/murus-igneus/PARENTAL.md"
cat > "$stage/DEBIAN/control" <<'EOF'
Package: murus-igneus
Version: 0.3.0~alpha.9
Section: net
Priority: optional
Architecture: all
Maintainer: Murus Igneus contributors
Depends: python3 (>= 3.11), nftables, iproute2, openssl, conntrack, kmod, wireguard-tools, strongswan-charon, strongswan-swanctl, libcharon-extra-plugins, libstrongswan-standard-plugins, iputils-ping, dpkg-repack, ca-certificates, tzdata, suricata, suricata-update, clamav, clamav-daemon, clamav-freshclam, python3-yaml, snmp, dnsmasq-base, rsync, fdisk, parted, dosfstools, e2fsprogs, grub-pc-bin, grub-efi-amd64-bin, grub2-common, openrc, init-system-helpers
Description: Experimental IPv4 firewall management for Devuan 6 Excalibur
 Independent configuration editor and conservative configuration importer.
 Includes an OpenRC service. Includes VPN, IPS, HTTP antivirus, local AI connector and SNMP switch management.
EOF
cat > "$stage/DEBIAN/conffiles" <<'EOF'
/etc/default/murus-igneus
/etc/sysctl.d/90-murus-igneus.conf
EOF
cat > "$stage/DEBIAN/preinst" <<'EOF'
#!/bin/sh
set -eu
. /etc/os-release
[ "${ID:-}" = devuan ] && [ "${VERSION_CODENAME:-}" = excalibur ] || {
    echo 'Murus Igneus alpha requires Devuan 6 Excalibur.' >&2; exit 1;
}
EOF
cat > "$stage/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -eu
case "${1:-}" in
    remove|upgrade|deconfigure)
        if command -v rc-service >/dev/null 2>&1; then
            if rc-service murus-igneus status >/dev/null 2>&1; then
                rc-service murus-igneus stop
            fi
        fi ;;
esac
EOF
cat > "$stage/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -eu
if [ "${1:-}" = configure ]; then
    echo 'Package installed. Configure /etc/default/murus-igneus, then:'
    echo '  rc-update add murus-igneus default'
    echo '  rc-service murus-igneus start'
    echo 'No service was started and no root password was modified.'
fi
EOF
chmod 0755 "$stage/DEBIAN/preinst" "$stage/DEBIAN/prerm" "$stage/DEBIAN/postinst"
dpkg-deb --root-owner-group --build "$stage" "$output/murus-igneus_0.3.0~alpha.9_all.deb"


