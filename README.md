# Murus Igneus

Independent open-source IPv4 firewall for Devuan 6 Excalibur / OpenRC.

[Download the alpha.5 prerelease](https://github.com/blasterfish7/murus_igneus/releases/tag/v0.3.0-alpha.5): bootable ISO, DEB, guide, SHA256 checksums and original ISO acceptance report.

Includes a native web configuration editor and disk installer, optional FortiGate text-backup import, nftables policies/NAT, VLANs, DHCP/DNS, static routing and confirmed apply/rollback. VPNs include WireGuard and static IKEv2/PSK with strongSwan; two static WANs support ICMP-based failover. Suricata IPS and a ClamAV explicit HTTP download proxy provide experimental UTM integration. HTTPS content inspection and HA are not implemented.

The assistant supports local Ollama/Qwen3 and optional OpenAI Responses API with explicit data-sharing consent and a user-supplied API key. OpenAI is an external hosted service; the client code is open source. Local model/runtime are installed separately. SNMP switch inventory, LLDP/port monitoring and confirmed port up/down remain available. Administration adds TOTP, bounded persistent packet/audit history and an offline signed application package update tool.

Validated: 138 Python tests without skips, 8 Chromium checks, 20 packet checks and 24 original UEFI ISO checks, including real appliance IPsec apply/rollback. This remains an alpha: disk installation of this version, hardware/FortiGate interoperability, full signed update installation/rollback, live OpenAI model quality and a complete UTM efficacy/performance matrix are not claimed.

No Fortinet code, firmware or assets are reused.

See [alpha.5 setup and limitations](docs/ALPHA5.md), [ISO acceptance](docs/ISO-ALPHA5-QA.md), [native networking](docs/NATIVE-NETWORKING.md), [AI and switches](docs/AI-SWITCHES.md), [Devuan build/install](docs/DEVUAN.md) and [source/verification status](SOURCE_STATUS.md).
