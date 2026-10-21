# Native networking — 0.3.0-alpha.4 (work in validation)

Adds VLAN interfaces, DHCP pools, local DNS forwarding, explicit TCP/UDP port
forwarding and a bounded read-only connection/event view. Native settings share
the existing apply/confirm/rollback transaction and are preserved by installation.
Only independent application code and open-source system components are used.
See [native networking](docs/NATIVE-NETWORKING.md) for ordering, limits and tests.

Local regression suite: 123 tests; three protocol tests require Net-SNMP tools
that are absent locally. CI executes those tools and a new real-packet namespace
acceptance job before producing the alpha.4 ISO. No alpha.4 ISO boot/install or
physical-hardware acceptance has yet been recorded. The following alpha.3 record
is historical and must not be interpreted as an alpha.4 test result.

# ISO alpha.3 acceptance — 2026-10-21

The original ISO from source `f7517ea456a751c0e0e7e08675d56c5de5903349`
has now completed real UEFI live boot, native configuration apply/confirm/rollback,
Chromium GUI checks, web installation on a disposable 10 GiB disk and disk-only
UEFI boot without an ISO. VPN/UTM configuration, AI settings and private SNMP
credentials survived installation. The installed WireGuard key predates boot;
the tunnel interface, IPS, ClamAV and proxy were ready. Real ClamAV/proxy tests
accepted clean content, blocked EICAR and rejected upstream HTTP 304 responses,
both live and installed. The installed VM completed shutdown and is powered off.

ISO SHA-256:
`cac1e14d3a82740e3332c43fa3bd81de86444eaf6cffa61c2415fa0223c57e26`.

Environment: QEMU 8.2.2 TCG, OVMF UEFI (no Secure Boot), 2 vCPU, 3072 MiB RAM,
three VirtIO NICs and Chromium 153.0.8010.0. There are 17 recorded acceptance
checks; these are distinct from the 101 CI tests below.

Observation: live shutdown exceeded the initial 90-second lab deadline. That VM
was force-stopped after installer success, sync and target unmount, then the same
disk was booted independently. Installed shutdown completed with a longer wait.
OpenRC's existing udev real/virtual-service warning remains; gzip was used when
zstd was absent. No ISO/source changes were needed for the acceptance run.

AI used a controlled HTTP fixture, not a real model. No physical-switch writes,
full forwarded VPN/IPS/NAT traffic matrix, Secure Boot, BIOS or physical hardware
compatibility test was performed. HTTP proxy checks originated in the guest with
a LAN source address; they are not an external physical-client path test.

See [the acceptance report](docs/ISO-ALPHA3-QA.md) and
[structured results](docs/qa/alpha3-iso-validation.json) for exact scope and observations.

# Debug fixes — 0.3.0-alpha.3

These source changes follow the published alpha.2 release; they do not modify
that release's ISO, package, tag, or historical test evidence below.

Reproduced regressions and fixes:

- Refuse firewall activation before executing any commands while a switch task
  is running. The reverse exclusion already existed.
- Invalidate cached port state before sending a SET. Both lost SET replies and
  lost read-back responses now leave an explicit unknown state, not old telemetry.
- Keep an AI response tied to the exact submitted draft. Duplicate submissions
  cannot change that association; a superseded task unlocks the form and requests
  a new question.
- Reject incomplete AI configurations and partial VPN/UTM sections instead of
  silently filling omitted sections with empty/default values.
- Remove conditional HTTP cache headers and reject upstream 304 responses; the
  antivirus proxy requires a full response body for each proxied download.
- Use the runtime VERSION constant in the security-aware configuration compiler.

Validation of source commit `f7517ea456a751c0e0e7e08675d56c5de5903349`:
[Actions run 39407442852](https://github.com/blasterfish7/murus_igneus/actions/runs/39407442852)
completed successfully: both test and ISO jobs passed. The test job passed all
101 Python tests without skips, including actual Net-SNMP v2c/v3
agent reads and wrong-credential rejection. The Node.js AI UI regressions,
Python lint, syntax checks and native package build passed. Locally, 98 Python
tests passed and 3 SNMP tests were skipped because the client/agent tools were
absent. The final local package was compared byte-for-byte against all packaged
application source files.

The final run produced both alpha.3 artifacts:

- `murus-igneus-devuan-alpha`, artifact `12257532533`, containing the native
  `murus-igneus_0.3.0~alpha.3_all.deb` package.
- `murus-igneus-devuan-iso`, artifact `12257179355`, containing the ISO,
  `SHA256SUMS`, package manifest and signature/build logs. ISO generation and
  upload succeeded; official ClamAV signature update succeeded during build.

These are GitHub Actions artifacts with 14-day retention, not a new GitHub
Release. The alpha.2 prerelease and its tag/binaries were not replaced.

Regression coverage includes actual local management/proxy HTTP requests,
deterministic SNMP lost-reply simulations and a Node.js simulated-DOM regression
for AI draft ownership. These are not physical-switch or real-model accuracy
tests. Alpha.3 ISO boot/installation acceptance is now recorded above. Historical
VPN/UTM traffic results below still refer to the earlier builds explicitly named.

# Previous delivered build — 0.3.0-alpha.2

Verified 2026-10-20 (Europe/Rome). Laboratory software, not a production release.

## Delivered build

Build source: `e749f34fb5ab5e497197241e8c1879a62555cbe4`.
Actions: https://github.com/blasterfish7/murus_igneus/actions/runs/39339700961
PR: https://github.com/blasterfish7/murus_igneus/pull/5

ISO: `murus-igneus-0.3.0-alpha.2-devuan-amd64.iso`, 472274944 bytes.
SHA-256: `fa3ee325e358401563e5350588b0cdec84833855f1de1310a849888b953b74ba`.

Package: `murus-igneus_0.3.0~alpha.2_all.deb`, 60312 bytes.
SHA-256: `52f16678adac14d34db2b48ffb8c94de020073f63d8021af8605be0aff21d9f3`.

Fresh signed-main Devuan 6 Excalibur / OpenRC. SNMP client package included;
Ollama runtime and model weights are not bundled. Official ClamAV main/daily/
bytecode downloads and database validation succeeded during the build.
The engine remains Devuan 1.4.3; FreshClam recommends 1.4.6. This gap is open.

## Completed alpha.2 checks

- 94 automated tests pass locally and in Actions, with no skips in the full
  tool-equipped run. Includes real loopback Net-SNMP v2c and v3 SHA/AES tests.
- Python lint/compile, JavaScript/shell syntax, .deb metadata and package/source
  comparison pass. Artifact ZIP and ISO checksums were verified after download.
- Browser checks pass for AI settings/check/chat, switch inventory and ports,
  protected uplinks and typed one-use port confirmation, with no JavaScript
  errors. These UI paths use controlled local API fixtures.
- Separately, actual Net-SNMP clients and a local agent passed GET/walk and SET
  round trips for v2c and encrypted v3. SET targets were synthetic ifAdminStatus
  values, never host interfaces or physical switches.
- Real Ollama 0.40.6 with Qwen3:4b on CPU returned analysis. It also produced
  incorrect interpretations and invalid configuration proposals; those were
  refused by the native validator. Real-model valid-proposal quality remains
  unverified. Deterministic draft facts are shown separately from model output;
  all proposals still require validation and explicit human review/application.
- The exact delivered ISO booted in UEFI under QEMU TCG, 2 vCPU / 3 GiB RAM /
  three VirtIO NICs. Live AI/SNMP APIs, installed SNMP tools, secret redaction
  and 0600 credential-file permissions were verified.
- The live web installer completed on a disposable 10 GiB disk. After shutdown,
  the disk booted in UEFI with no ISO attached. AI endpoint settings and SNMP
  inventory/credentials persisted, while credentials remained absent from API
  output. The installer correctly reports a non-live installed system.
- All test VMs were powered off after validation.

## Scope and limits

This update reconciles the Claude TLS, CSRF, version, management-route and nested group fixes with the functional Devuan VPN/UTM/web installer implementation.
Other integration branches were not overwritten or merged.

Switch management is manual inventory, IF-MIB/LLDP monitoring and explicit
Ethernet admin-state up/down. No VLAN, trunk, LAG, PoE, firmware or FortiLink
adoption. Physical-switch compatibility is unverified. Port SET has no automatic
rollback; permanent save depends on the switch.

The new ISO installation/API tests do not re-attest every previous VPN/IPS/AV
traffic test. Those alpha.1 results below are historical evidence for the
existing stack, not measurements of the alpha.2 binary. HTTPS antivirus and
IPsec remain absent. See [setup and boundaries](docs/AI-SWITCHES.md).

---

# Previous delivered build — 0.3.0-alpha.1

Verified 2026-10-19. Laboratory software, not a production release.

## Delivered build

Source commit: `01362b615107f288c4e302cf013747d17e2e3380`.
Actions: https://github.com/blasterfish7/murus_igneus/actions/runs/39308263309

ISO: `murus-igneus-0.3.0-alpha-devuan-amd64.iso`, 459872256 bytes.
SHA-256: `2a69f85c5956488b102d7a3c8e6cb305fade952340a027d88335d7d0d37f46c4`.

Devuan 6 Excalibur / OpenRC, freshly bootstrapped from signed main packages.
Official ClamAV main/daily/bytecode downloads and database validation succeeded.
No test-only signature database was substituted.

## Completed checks

48 automated tests pass locally and in Actions, plus syntax and native .deb checks.
Coverage includes translation, CSRF, management reservation, VPN route conflicts,
the distribution Suricata configuration, installer confirmation and refusal of
encoded HTTP responses that cannot be inspected as clear content.

Actual traffic tests in disposable QEMU networks passed:

- Native configuration without a backup; HTTP forwarding, SNAT, deny and rollback.
- Suricata allowing clean HTTP, blocking a bundled attack signature, and dropping
  forwarded traffic after the IPS engine is terminated.
- WireGuard handshake, policy-controlled VPN-to-LAN traffic, deny and rollback.
- Real ClamAV with official databases: clean proxy downloads allowed, EICAR and a
  blocked domain refused; no content delivered after terminating clamd.

The final ISO booted in UEFI under QEMU TCG, 2 vCPU / 6 GiB RAM / three VirtIO NICs.
Browser checks passed for configuration from scratch, preview/apply/confirm,
VPN key display, VPN policy selection, enabling VPN/IPS/antivirus together and
exact disk-erasure confirmation. DHCP remained on management only.

The full database loaded in about 82 seconds under emulation. Startup now allows
five minutes instead of timing out at 60 seconds.

The web installer completed GPT BIOS/EFI/ext4 installation on a disposable 10 GiB
disk. The final installed system booted in UEFI without the ISO. Checks confirmed:

- Root on /dev/vda3 and OpenRC service started.
- Exact native configuration and WireGuard server key preserved.
- Policy IDs 10/20, SNAT, forwarding and the IPS queue restored.
- WireGuard, Suricata, clamd and proxy active after reboot.
- Clean/EICAR scanning correct after reboot.
- Live-only installer disabled on the installed system.

BIOS live/disk boot was also verified on an earlier Devuan candidate using the
same installer. Traffic checks include the startup-timeout correction tested in
the live VM and delivered in the final build. These are functional lab checks,
not performance, broad hardware-compatibility or security-audit results.

## Limits

Antivirus covers explicit proxy HTTP GET/HEAD downloads up to 20 MiB.
Encoded/partial responses and CONNECT are refused. HTTPS antivirus inspection
is unavailable. Proxy requests use their own client/destination ACLs rather than
forwarding policies. The two local IPS signatures have limited coverage;
community rules retain their original alert/drop actions.

ClamAV from the Devuan repository is 1.4.3; FreshClam recommends 1.4.6.
Address this version gap before considering production use. Initial credentials
are public: admin / igneus, console root / igneus. IPsec, FortiGate VPN conversion,
HA, VLAN configuration, IPv6 and AI are not implemented.

No Fortinet code, firmware or assets are included. Original MIT notices are
preserved alongside repository licensing. See docs/DEVUAN.md and docs/PROVENANCE.md.

tools/validate-devuan-runtime.py replaces configuration and creates namespaces:
run it only in an explicitly flagged disposable live VM, never on a real network.
It does not erase a disk.


