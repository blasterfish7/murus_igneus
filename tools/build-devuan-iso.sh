#!/bin/bash
# Build in an isolated privileged Devuan Excalibur VM/container, never on a workstation.
# SPDX-License-Identifier: MIT
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
source /etc/os-release
[[ ${ID:-} == devuan ]] || { echo 'An isolated Devuan builder is required'; exit 1; }
[[ $EUID == 0 ]] || { echo 'Root in an isolated builder is required'; exit 1; }
project=$(cd -- "$(dirname -- "$0")/.." && pwd)
work=${MURUS_BUILD_DIR:-/var/tmp/murus-build}
root=$work/root
iso=$work/iso
out=${MURUS_OUTPUT_DIR:-$project/dist}
[[ ! -e $root && ! -e $iso ]] || { echo 'Use a new empty build directory'; exit 1; }
mkdir -p "$work" "$out"
cp "$project/packaging/devuan/sources.list" /etc/apt/sources.list
rm -f /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources
apt-get update
apt-get install -y --no-install-recommends devuan-keyring debootstrap gnupg ca-certificates squashfs-tools xorriso grub-pc-bin grub-efi-amd64-bin grub2-common mtools dosfstools python3 xz-utils
# Native Devuan debootstrap performs release signature verification. No non-free repository is enabled.
debootstrap --force-check-gpg --variant=minbase --include=devuan-keyring excalibur "$root" http://deb.devuan.org/merged
cleanup() {
    mountpoint -q "$root/dev" && umount -R "$root/dev" || true
    mountpoint -q "$root/proc" && umount -R "$root/proc" || true
    mountpoint -q "$root/sys" && umount -R "$root/sys" || true
}
trap cleanup EXIT
cp "$project/packaging/devuan/sources.list" "$root/etc/apt/sources.list"
cp /etc/resolv.conf "$root/etc/resolv.conf"
cat > "$root/usr/sbin/policy-rc.d" <<'POLICY'
#!/bin/sh
exit 101
POLICY
chmod 755 "$root/usr/sbin/policy-rc.d"
for name in dev proc sys; do
    mount --rbind "/$name" "$root/$name"
    mount --make-rslave "$root/$name"
done
chroot "$root" apt-get update
chroot "$root" apt-get install -y --no-install-recommends linux-image-amd64 live-boot initramfs-tools sysvinit-core openrc ifupdown isc-dhcp-client kmod python3 python3-yaml snmp dnsmasq-base nftables iproute2 openssl conntrack wireguard-tools strongswan-charon strongswan-swanctl libcharon-extra-plugins libstrongswan-standard-plugins iputils-ping dpkg-repack suricata suricata-update clamav clamav-daemon clamav-freshclam rsync fdisk parted dosfstools e2fsprogs grub-pc-bin grub-efi-amd64-bin grub2-common ca-certificates curl
bash "$project/packaging/devuan/build-deb.sh" "$out"
cp "$out/murus-igneus_0.3.0~alpha.5_all.deb" "$root/tmp/murus.deb"
chroot "$root" dpkg -i /tmp/murus.deb
rm "$root/tmp/murus.deb"
# A signed ClamAV database can be distributed with the lab ISO when its official
# download is available. An unavailable upstream must not be reported as coverage.
if [[ ${MURUS_FETCH_SIGNATURES:-1} == 1 ]]; then
    chroot "$root" python3 -c "import sys;sys.path.insert(0,'/usr/lib/murus-igneus');import security;security.update_command('clamav')"
    if timeout 300 chroot "$root" freshclam --config-file=/run/murus-igneus/freshclam.conf --stdout > "$out/clamav-build.log" 2>&1; then
        printf 'Official ClamAV signature update succeeded during build.\n' > "$out/signature-status.txt"
    else
        printf 'Official ClamAV signature download unavailable. Download signatures from UTM before enabling antivirus.\n' > "$out/signature-status.txt"
        # Do not distribute a build server's CDN cooldown state to another host.
        rm -f "$root/var/lib/clamav/freshclam.dat" "$root/var/lib/clamav/mirrors.dat"
    fi
else
    printf 'Build-time signature download explicitly skipped.\n' > "$out/signature-status.txt"
fi
cat "$out/signature-status.txt"
printf 'murus\n' > "$root/etc/hostname"
printf '127.0.0.1 localhost\n127.0.1.1 murus\n' > "$root/etc/hosts"
cat > "$root/etc/network/interfaces" <<'NETWORK'
auto lo
iface lo inet loopback
auto eth0
iface eth0 inet dhcp
NETWORK
mkdir -p "$root/etc/dhcp/dhclient-enter-hooks.d" "$root/etc/murus_igneus"
printf 'if [ "$interface" = eth0 ]; then new_routers=""; fi\n' > "$root/etc/dhcp/dhclient-enter-hooks.d/murus-management"
printf 'timeout 10;\nretry 30;\ninitial-interval 1;\n' > "$root/etc/dhcp/dhclient.conf"
printf 'root:igneus\n' | chroot "$root" chpasswd
printf 'igneus\n' > "$root/etc/murus_igneus/admin.password"
chmod 700 "$root/etc/murus_igneus"
chmod 600 "$root/etc/murus_igneus/admin.password"
touch "$root/etc/murus_igneus/live-image"
printf '\nT0:2345:respawn:/sbin/agetty -L ttyS0 115200 vt100\n' >> "$root/etc/inittab"
chroot "$root" rc-update add murus-igneus default
# Murus owns these processes and starts them only after validated configuration.
for service in suricata clamav-daemon clamav-freshclam strongswan strongswan-starter; do
    chroot "$root" update-rc.d "$service" disable
done
# Enable the network service at boot; package defaults are retained for other base services.
chroot "$root" update-rc.d networking defaults
chroot "$root" update-initramfs -u -k all
chroot "$root" apt-get clean
rm "$root/usr/sbin/policy-rc.d"
rm -f "$root/etc/ssh/ssh_host_"* "$root/var/lib/dbus/machine-id"
: > "$root/etc/machine-id"
# Audit installed package sections, before generating the image and initramfs manifest.
chroot "$root" dpkg-query -W '-f=${binary:Package}\t${Version}\t${Section}\n' > "$out/packages-devuan.tsv"
if grep -E '(^|[[:space:]])(non-free|contrib)(/|[[:space:]]|$)' "$out/packages-devuan.tsv"; then echo 'Non-free package rejected'; exit 1; fi
if grep -E '^(firmware-|.*microcode)' "$out/packages-devuan.tsv"; then echo 'Hardware firmware package rejected'; exit 1; fi
cleanup
mkdir -p "$iso/live" "$iso/boot/grub"
cp -L "$root"/boot/vmlinuz-* "$iso/boot/vmlinuz"
cp -L "$root"/boot/initrd.img-* "$iso/boot/initrd"
cp "$out/packages-devuan.tsv" "$iso/"
cp "$out/signature-status.txt" "$iso/"
# Do not capture pseudo filesystems, build caches, logs or per-machine secrets.
mksquashfs "$root" "$iso/live/filesystem.squashfs" -noappend -comp xz -processors 2 -wildcards -e 'dev/*' 'proc/*' 'sys/*' 'run/*' 'tmp/*' 'var/cache/apt/archives/*' 'var/log/*'
cat > "$iso/boot/grub/grub.cfg" <<'GRUB'
set timeout=2
serial --unit=0 --speed=115200
terminal_input console serial
terminal_output console serial
menuentry 'Murus Igneus 0.3.0-alpha.5 / Devuan 6 (live + web installer)' {
  linux /boot/vmlinuz boot=live ip=frommedia net.ifnames=0 console=tty0 console=ttyS0,115200
  initrd /boot/initrd
}
GRUB
grub-mkrescue --compress=xz -o "$out/murus-igneus-0.3.0-alpha.5-devuan-amd64.iso" "$iso"
(cd "$out" && sha256sum murus-igneus-0.3.0-alpha.5-devuan-amd64.iso > SHA256SUMS)
echo 'MURUS ISO BUILD COMPLETE'



