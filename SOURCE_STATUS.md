# Alpha.8 acceptance — 2026-10-27 UTC

Tested combined source: `bf328cc0dfff2d4a3877004d14f16aa6d1ab8e98`.
[CI run 40504087723 passed](https://github.com/blasterfish7/murus_igneus/actions/runs/40504087723): 191 Python tests without skips, 10 Chromium checks, management TLS/transaction-lock fixture, 13 native/9 enterprise/17 parental packet checks and four real HTTPS feed downloads. The original ISO passes 46 UEFI/live checks using installed modules, including responsive management HTTPS and actual kernel verification of an already absent route before restoring working DNAT.

Includes PR9 responsive status snapshots and PR10 corrected to verify network postconditions instead of ignoring command failures. Real conntrack/sysctl errors remain failures with safety fallback. Historical drafts #1/#4 are closed, branches preserved.

ISO: `murus-igneus-0.3.0-alpha.8-devuan-amd64.iso`, 475123712 bytes, SHA256 `ffc6778201699ebf5a4677be7a7d986f0a1f66bbdce393ce64a8c58c4a5a0972`.
DEB: 101916 bytes, SHA256 `554be9fce716be5b1ba3076b0cdeaabc5c10b88c853b4dee380a930838f4c6e8`.

Original tested artifacts preserved in a private draft; final publication pending. Details: [ALPHA8](docs/ALPHA8.md), [ISO QA](docs/ISO-ALPHA8-QA.md), [structured summary](docs/qa/alpha8-validation.json). No new disk installation, hardware/Secure Boot or complete UTM efficacy claim. No Fortinet code/firmware.

---

# Published release — 0.3.0-alpha.7

PR #8 is merged into main. [Download the alpha.7 prerelease](https://github.com/blasterfish7/murus_igneus/releases/tag/v0.3.0-alpha.7): original tested ISO, DEB, guide, checksums and acceptance report. Alpha.6 and previous published assets are preserved.
Tag target: `0d4aee5f8af4d4b0000c2101b09ae2a9df859d2a`; tested build source: `64a4b5dad271bd0ea86e2c19822a5b6974c10105`. Only QA documentation differs at the release target. [Publisher run 40208249111](https://github.com/blasterfish7/murus_igneus/actions/runs/40208249111) verified original build/ISO/DEB hashes, the 44-check ISO report, all 27 application files, installed command/init scripts and all nine uploaded asset digests before publication.

ISO SHA256: `44c2af50e1a5df6dd4335a36fcee5a58133bfc5c0091bfb2cf556c0bb594115e`.
DEB SHA256: `cf07bbec444c185e71cccf99e87656ed4ff6ab87703b6391c89c3c899419d4b6`.

Setup and limits: [ALPHA7](docs/ALPHA7.md), [parental/reporting](docs/PARENTAL.md), [ISO QA](docs/ISO-ALPHA7-QA.md).

# Alpha.7 acceptance — 2026-10-25 UTC

Tested source: `64a4b5dad271bd0ea86e2c19822a5b6974c10105`.
[CI run 40207093633 passed](https://github.com/blasterfish7/murus_igneus/actions/runs/40207093633): 178 Python tests without skips, 10 Chromium checks, 12 native/9 enterprise/17 parental packet checks and four real HTTPS category downloads. The original ISO passes 44 UEFI/live checks, including the actual HTTPS Basic throttle, IPsec/parental apply/rollback and a real invalid nft restoration with blocked transit and released pending state.

Completes Claude PR #8 with bounded/atomic password failure tracking, exceptional rollback recovery, truthful GUI/API recovery results, corrected murus-info and branch-independent draft preservation when Actions artifacts cannot be uploaded. Version alpha.7 preserves published alpha.6.

ISO: `murus-igneus-0.3.0-alpha.7-devuan-amd64.iso`, 475041792 bytes, SHA256 `44c2af50e1a5df6dd4335a36fcee5a58133bfc5c0091bfb2cf556c0bb594115e`.
DEB: 100320 bytes, SHA256 `cf07bbec444c185e71cccf99e87656ed4ff6ab87703b6391c89c3c899419d4b6`.

Original artifacts preserved in a private draft and now published without rebuilding. The publisher verified 27 packaged application files, installed scripts and all nine asset digests. Scope and limitations: [ALPHA7](docs/ALPHA7.md), [ISO acceptance](docs/ISO-ALPHA7-QA.md), [structured summary](docs/qa/alpha7-validation.json). No alpha.7 disk installation, hardware/Secure Boot or complete UTM efficacy claim. No Fortinet code/firmware.

---

# Published release — 0.3.0-alpha.6

PR #7 is merged into main. [Download the alpha.6 prerelease](https://github.com/blasterfish7/murus_igneus/releases/tag/v0.3.0-alpha.6): original ISO, DEB, setup guide, checksums and acceptance report.
Tag target: `bef489b88c7e837e04e597042a9b770f0c45e7bc`; tested build source: `fe201577f6e3b4d8f39f2391935076c826dedcca`. Only QA documentation differs at the release target. [Publisher run 40137816448](https://github.com/blasterfish7/murus_igneus/actions/runs/40137816448) verified original build/ISO/DEB hashes, the 42-check ISO report, all 27 packaged application files and all nine uploaded asset digests before publication.

ISO SHA256: `eb48a856c22ec9eab7127e9e57ea0739bf25e8e6f7d0337a585e1bc9ac63663f`.
DEB SHA256: `72011485a83e4c4d7e38010e9571d7381b9fcab40d6e81f06913a6c567324bfb`.

Reporting is opt-in: Parental control → Abilita reporting locale → save, preview, apply and confirm. Use stable client IPs and Murus as the gateway. Details and limitations below.

# Alpha.6 acceptance — 2026-10-24 UTC

Tested source: `fe201577f6e3b4d8f39f2391935076c826dedcca`.
[CI run 40136817311 passed](https://github.com/blasterfish7/murus_igneus/actions/runs/40136817311): 167 Python tests without skips, 10 Chromium checks, 11 native/9 enterprise/17 parental packet checks and four actual HTTPS category feed downloads. The original ISO passes 42 QEMU UEFI/live checks using its installed modules, including actual root HTTPS IPsec/parental apply and rollback.

Adds optional local parental reporting (24 hours/7 days, per-IP/subnet forwarded IPv4 counters, parental drops, DNS request/filter aggregates, CSV and clear) alongside parental profiles, category/service filtering, weekly schedules, immediate pause and DHCP reservations. No Fortinet code/firmware.

ISO: `murus-igneus-0.3.0-alpha.6-devuan-amd64.iso`, 475041792 bytes, SHA256 `eb48a856c22ec9eab7127e9e57ea0739bf25e8e6f7d0337a585e1bc9ac63663f`.
Original DEB: 98432 bytes, SHA256 `72011485a83e4c4d7e38010e9571d7381b9fcab40d6e81f06913a6c567324bfb`.

The original build was preserved in a draft after Actions artifact quota rejection and is now published without rebuilding. The publisher verified all 27 packaged application files against the tested source and all nine release asset digests. Details: [parental setup/reporting](docs/PARENTAL.md), [ISO acceptance and limits](docs/ISO-ALPHA6-QA.md), [structured summary](docs/qa/alpha6-validation.json). DNS requests are not visits/time in apps; bytes are not attributed to sites. No alpha.6 disk installation, physical hardware, Secure Boot or full UTM efficacy claim.

---

# Published release — 0.3.0-alpha.5

PR #6 is merged into main. [Download the alpha.5 prerelease](https://github.com/blasterfish7/murus_igneus/releases/tag/v0.3.0-alpha.5).
Tag target: `ae8b9fcb98c016cc9ac05ef8381862aca4203102`; tested build source: `55ec4ea84c58f0c036cd50ac9a7266a7c96fdd38`. Only acceptance documentation changed after testing. [Publisher run 39654082948](https://github.com/blasterfish7/murus_igneus/actions/runs/39654082948) verified original build archives, ISO checksum/embedded 24-check report and all seven uploaded asset digests before publishing.

ISO SHA-256: `7bbceee7a1bdde8e47b909c46c22e2effa1c9c5f1836dcf6f33239c8c659fc81`.
DEB SHA-256: `a8e2a8434da887315a5b8795b3a6beec8ae0e5ef7b8950d6ba4cafb643765776`.

# Alpha.5 acceptance — 2026-10-21

Candidate source: `55ec4ea84c58f0c036cd50ac9a7266a7c96fdd38`.
[CI and original ISO acceptance passed](https://github.com/blasterfish7/murus_igneus/actions/runs/39651874250): 138 Python tests without skips, 8 Chromium checks, 11 native and 9 enterprise packet checks; 24 checks inside the original UEFI live ISO. Includes real appliance HTTPS IPsec apply/rollback, beyond the isolated protocol laboratory. All 24 packaged application files match the tested source.

Adds optional OpenAI Responses integration, corrected AI context, IKEv2/strongSwan selector VPN, static dual-WAN failover, TOTP, bounded persistent packet/audit history and offline signed application package update tooling. No Fortinet code or firmware.

ISO SHA-256: `7bbceee7a1bdde8e47b909c46c22e2effa1c9c5f1836dcf6f33239c8c659fc81`.

Detailed scope, evidence and limitations: [ALPHA5](docs/ALPHA5.md), [ISO QA](docs/ISO-ALPHA5-QA.md), [machine-readable report](docs/qa/alpha5-validation.json). The signed updater does not update the whole OS; no live OpenAI request, real FortiGate interoperability or alpha.5 disk installation is claimed.

---

# Published release — 0.3.0-alpha.4

PR #5 is merged into `main`. [Download the alpha.4 prerelease](https://github.com/blasterfish7/murus_igneus/releases/tag/v0.3.0-alpha.4)
with the original verified ISO, DEB, checksums and acceptance report. The release
tag points to merge commit `ab2b29c1432eb43341f39c59f03110251238054d`; runtime
source is identical to the tested build commit below. The release publisher
verified the original artifact archives, ISO manifest and embedded QA report,
then checked every uploaded asset digest before publication.

ISO SHA-256: `531b64addf529390517ae95afd03c18e413e2d45f10959c02708d876df7c621e`.

# Native networking — 0.3.0-alpha.4 acceptance (2026-10-21)

Build/source commit: `4808ef7fe556c0c1564a01faa7fff4d4e67aca33`.
[CI build and acceptance succeeded](https://github.com/blasterfish7/murus_igneus/actions/runs/39591605617).

Adds native VLAN interfaces, DHCP pools, local DNS forwarding, explicit TCP/UDP
port forwarding and a bounded read-only connection/event view. Native settings
share the existing apply/confirm/90-second rollback transaction. The installer
copies the new lease directory alongside the existing confirmed configuration.
Independent code and open-source system components only; no Fortinet code/firmware.

Validation: 124 Python CI tests passed without skips; static/syntax and both Node
UI regression suites passed; five real Chromium GUI checks passed; eleven real
namespace traffic checks passed both on the runner and inside the generated ISO.
The ISO completed UEFI live boot, real HTTPS native preview and graceful poweroff
(14 VM acceptance checks total). All 19 application files in the CI DEB matched
local source byte-for-byte. Official ClamAV signature download succeeded in build.

The alpha.4 image remains experimental. Disk installation/disk-only reboot,
physical hardware, BIOS/Secure Boot and the full forwarded VPN/IPS/antivirus
matrix were not retested for this version. Native feature support does not imply
FortiGate VLAN/VIP/DHCP import support. The historical alpha.3 record below applies
only to alpha.3.

See [native networking](docs/NATIVE-NETWORKING.md),
[alpha.4 acceptance](docs/ISO-ALPHA4-QA.md) and
[structured results](docs/qa/alpha4-validation.json).

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




