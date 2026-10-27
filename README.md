# Murus Igneus

Independent open-source IPv4 firewall for Devuan 6 Excalibur / OpenRC.

[Download the alpha.8 prerelease](https://github.com/blasterfish7/murus_igneus/releases/tag/v0.3.0-alpha.8): bootable ISO, DEB, guide, SHA256 checksums and original ISO acceptance report.

Includes a native web configuration editor and disk installer, optional FortiGate text-backup import, nftables policies/NAT, VLANs, DHCP/DNS, static routing and confirmed apply/rollback. VPNs include WireGuard and static IKEv2/PSK with strongSwan; two static WANs support ICMP-based failover. Suricata IPS and a ClamAV explicit HTTP download proxy provide experimental UTM integration. HTTPS content inspection and HA are not implemented.

The assistant supports local Ollama/Qwen3 and optional OpenAI Responses API with explicit data-sharing consent and a user-supplied API key. OpenAI is an external hosted service; the client code is open source. Local model/runtime are installed separately. SNMP switch inventory, LLDP/port monitoring and confirmed port up/down remain available. Administration adds TOTP, bounded persistent packet/audit history and an offline signed application package update tool.

Parental control adds per-IP/subnet profiles, category/service DNS filters, weekly schedules, immediate pause and DHCP reservations. Optional local reporting shows 24-hour/7-day forwarded IPv4 volumes, hourly trends, parental drops and DNS request/filter aggregates, with CSV and history clearing. DNS requests do not prove visits or time in apps; bytes are not attributed to sites. Data stays local for up to 7 days/50,000 rows/32 MiB.

Alpha.7 completes the Claude review fixes: bounded atomic Basic login throttling (10 errors/60 seconds per IP), expired-attempt cleanup, exceptional rollback recovery, explicit incomplete-recovery results in the GUI/API, corrected console information and tested ISO preservation even when Actions artifact storage is full.

Alpha.8 integrates responsive status polling during service activation and verified idempotent network rollback. Failed undo commands are tolerated only after kernel readback confirms the intended state; real conntrack/forwarding failures remain errors. Configuration changes remain serialized.

Validated: 191 Python tests without skips, 10 Chromium checks, 39 packet checks, four real HTTPS category downloads, a TLS management/transaction-lock fixture and 46 original UEFI ISO checks, including already-absent route recovery, actual HTTPS Basic throttling, invalid nft recovery and real appliance IPsec/parental apply/rollback. All 27 packaged application files match the tested source. This remains an alpha: disk installation of this version, hardware/FortiGate interoperability, full signed update installation/rollback, live OpenAI model quality and a complete UTM efficacy/performance matrix are not claimed.

No Fortinet code, firmware or assets are reused.

See [alpha.8 changes and limits](docs/ALPHA8.md), [parental setup and reporting](docs/PARENTAL.md), [alpha.8 ISO acceptance](docs/ISO-ALPHA8-QA.md), [previous feature setup/limits](docs/ALPHA5.md), [native networking](docs/NATIVE-NETWORKING.md), [AI and switches](docs/AI-SWITCHES.md), [Devuan build/install](docs/DEVUAN.md) and [source/verification status](SOURCE_STATUS.md).
