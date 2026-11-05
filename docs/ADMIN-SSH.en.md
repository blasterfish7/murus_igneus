# Management SSH access

[Italiano](ADMIN-SSH.md) · **English** · [Documentation](INDEX.md)

The alpha.12 ISO includes OpenSSH. SSH is off by default and can be enabled once Murus is installed on disk. In **Amministrazione → Accesso SSH**, enter authorized IPv4 sources or networks and Ed25519 public keys. Prefer a /32 for a single administrator workstation. To generate a key on that workstation:

```sh
ssh-keygen -t ed25519
```

Paste only the public key (`.pub`). Save the draft, preview and apply it, then try `ssh root@MANAGEMENT_IP` before confirming within 90 seconds. Root access requires the matching private key; password authentication, keyboard-interactive authentication and SSH forwarding are disabled. TCP 22 is reachable only on the IPv4 management interface and from the specified sources. The host key is generated on the installed system the first time SSH is started.

For upgrades from an ISO without OpenSSH, install `openssh-server` from the console. Murus runs a dedicated sshd process. If the package started the distribution service, stop it with `service ssh stop` and disable it with `update-rc.d ssh disable` before applying. Keep the local console available for troubleshooting and recovery.
