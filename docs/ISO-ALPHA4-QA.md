# Alpha.4 acceptance — 2026-10-21

Source/build commit: `4808ef7fe556c0c1564a01faa7fff4d4e67aca33`.
[Successful build and acceptance run](https://github.com/blasterfish7/murus_igneus/actions/runs/39591605617).

## Results

- **124 Python CI tests passed without skips**, including actual Net-SNMP protocol fixtures.
  The local run executed 124 tests with three Net-SNMP cases skipped because the local tools were absent.
- Static/syntax checks and both Node UI regression runners passed.
- **Five real Chromium GUI checks passed** (Chromium 153.0.8010.0): create physical/VLAN
  interfaces, DHCP, DNS and DNAT through the forms; validate the full draft using the
  real HTTP backend compiler; render/filter status data; no JavaScript page exceptions.
  That browser fixture disables system application and supplies controlled runtime status.
- **Eleven real-packet Linux checks passed** in an isolated namespace: tagged VLAN
  forwarding; TCP DNAT; denied unauthorized source and direct internal access;
  DNS forwarding and WAN DNS blocking; DHCP discover/offer/request/ack with gateway
  and DNS options and lease persistence; actual conntrack NAT tuples; manual VLAN
  and publication rollback; real 90-second automatic rollback; confirmed state file.
- **The original generated ISO passed 14 VM acceptance checks**: UEFI live boot,
  real HTTPS backend with native VLAN preview, the same eleven packet checks using
  modules installed in the live image, and graceful VM poweroff. The guest tests use
  isolated network namespaces with veth VLAN clients; they do not exercise physical NICs.
- The CI DEB archive digest was verified; all **19 packaged application files** matched
  the local source byte-for-byte.
- The build log records a successful official ClamAV signature update. This is a
  database-download result, not a new end-to-end antivirus detection test on alpha.4.

VM: QEMU TCG, OVMF 4M UEFI without Secure Boot, two vCPUs, 2048 MiB RAM and
three VirtIO NICs. No target installation disk was attached. The VM is powered off.

## Download and checksums

[Download the ISO artifact ZIP](https://github.com/blasterfish7/murus_igneus/actions/runs/39591605617/artifacts/12342299949),
then extract `murus-igneus-0.3.0-alpha.4-devuan-amd64.iso`.
The artifact expires on 2026-11-04; it is an Actions build artifact, not a new GitHub Release.

The ZIP includes `SHA256SUMS` for the ISO, its embedded
`alpha4-iso-networking-qa.json` acceptance report, package manifest and signature status.
The image digest in the embedded report is computed from the exact image booted by QEMU.

**Artifact ZIP** SHA-256 reported by GitHub (distinct from the ISO image checksum):

```
0cf1e67828f4a489e3a35f92a163ef42e0bfe9096d7e550458b877aabe67e52b
```

[Structured validation record](qa/alpha4-validation.json) preserves the CI evidence,
including the browser and namespace reports. ISO acceptance flags in that record
are taken from the successful job and its PASS markers; the detailed embedded ISO
report and image checksum are available inside the downloadable artifact.

## Scope and remaining acceptance

No alpha.4 disk installation/disk-only reboot, BIOS, Secure Boot, physical hardware
or physical-switch write acceptance was performed. The complete forwarded VPN,
IPS and HTTP-antivirus matrix and real-model AI quality were not retested here.
Historical alpha.3 installation and antivirus results remain specific to alpha.3.
No HTTPS antivirus inspection is implemented.

Native VLAN/DHCP/DNS/DNAT support does not enable automatic conversion of unsupported
FortiGate VLAN/VIP/DHCP backup sections. The conservative importer still blocks them.
New application code is independent; only open-source components are integrated.
