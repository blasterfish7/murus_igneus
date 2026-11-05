# Murus Igneus on Proxmox VE

[Italiano](PROXMOX.it.md) · **English** · [Documentation](INDEX.md)

Use a lab VM alongside the existing firewall. Separate the WAN and LAN test bridges. Do not enable Murus DHCP on a segment that already has a DHCP server.

| VM setting | Starting profile |
| --- | --- |
| Machine / BIOS | q35 / OVMF, EFI disk, Secure Boot off |
| Disk | SCSI disk on **VirtIO SCSI single**, I/O thread enabled; 16 GiB for the lab |
| CPU and RAM | 2 vCPUs and 2 GiB fixed to start. Size for observed IDS/IPS and antivirus load. |
| Network | Three VirtIO NICs for management, WAN and LAN on separate segments. Management must be reachable from your PC. Verify device mapping by MAC in Murus. |
| Guest Agent | **Options → QEMU Guest Agent**, VirtIO transport, backup freeze/thaw disabled |

The **development** [PR #16](https://github.com/blasterfish7/murus_igneus/pull/16) adds Guest Agent integration and QEMU installation checks with VirtIO SCSI and an I/O thread. This is separate from the published alpha.12 ISO, whose QEMU checks used VirtIO Block. Neither test measures throughput on physical Proxmox/KVM hardware.

## Guest Agent (development)

The proposed ISO bundles Devuan's `qemu-guest-agent` and the OpenRC service `murus-guest-agent`. The service starts only when the VirtIO channel `org.qemu.guest_agent.0` is present. It does not listen on TCP. It supports ping, inventory and shutdown; guest command execution, file access and freeze/thaw are disabled.

After enabling the channel, power the VM off and start it again. Check from the node with `qm agent VMID ping` and from the appliance console with `rc-service murus-guest-agent status`. The agent reports addresses to the host.

If upgrading with a DEB containing the new service, install `qemu-guest-agent` from Devuan. Stop and disable the distribution SysV agent if present so only one process owns the channel. Register the Murus service with `rc-update add murus-guest-agent default` and start it with `rc-service murus-guest-agent start`.

## Measure before enabling multiqueue

Use two lab endpoints on opposite sides of the firewall. Configure routing and a TCP policy for port 5201. Run `iperf3 -s` on the server and `iperf3 -c SERVER_IP -t 30` on the client. Repeat with `-R` and with `-P 4`. Record throughput, retransmits and CPU use on both host and guest. Repeat with and without IDS/IPS, keeping NICs, rules and paths the same. If one queue appears to be the bottleneck, compare two queues under the same test. Change one setting at a time.
