# Murus Igneus 0.3.0-alpha.12

[Italiano](ALPHA12.md) · **English** · [Documentation](INDEX.md)

This release adds optional management SSH and scheduled social filters independent of permanent categories.

## Install from ISO

Boot the amd64 Devuan ISO in UEFI mode. Connect to `https://MANAGEMENT-IP:8443` from a machine that can reach the management network. The management interface is normally `eth0`; use a separate data port for WAN. The initial web user is `admin`, the console user is `root`, and the initial password is `igneus`. Set a new password of at least eight characters at first login; the web and console passwords are shared. Importing a FortiGate backup is optional.

Select **Installa su disco**, preview the target and type the requested confirmation. This erases the selected disk. After the installer finishes, power off, disconnect the ISO and boot from disk.

## Upgrade an existing alpha.11 installation

Back up the configuration and take a VM snapshot if applicable. Download the DEB, verify its SHA-256 against the trusted release's `SHA256SUMS`, and copy it to the appliance. Run from the root console:

```sh
rc-service murus-igneus stop
dpkg --force-confold --force-confdef -i ./murus-igneus_0.3.0-alpha.12_all.deb
rc-service murus-igneus start
```

The internal Debian version is `0.3.0~alpha.12`. The restart briefly interrupts web administration and forwarding. The manual procedure does not invoke automatic rollback from the signed update system.

## SSH and parental controls

- **SSH:** OpenSSH comes with the new ISO. On a previous installation, install `openssh-server` if missing and [stop and disable the distribution service](ADMIN-SSH.en.md) before enabling Murus SSH. Set the IPv4 allowlist and public keys in **Amministrazione → Accesso SSH**. Apply, test and confirm within 90 seconds. SSH starts disabled and is unavailable in the live session.
- **Family:** choose services to block during scheduled hours. The preset blocks WhatsApp and Instagram Mon–Fri, 15:00–19:00 in the profile timezone. Select the adult category and download its list to keep it active throughout the day. DNS blocking may not interrupt existing sessions or cached addresses. See [Parental controls](PARENTAL.en.md).

A DEB and checksums do not constitute a signed web update bundle. See [Signed application updates](UPDATES.en.md) for trust setup and upload. This prerelease does not update Devuan or its kernel.
