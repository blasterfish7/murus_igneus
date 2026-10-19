# Murus Igneus

Independent open-source IPv4 firewall for Devuan 6 Excalibur / OpenRC.

The experimental branch includes a native web configuration editor, optional
FortiGate text-backup import, nftables policies/SNAT, static routing, confirmed
apply/rollback, a live web disk installer, WireGuard and Suricata/ClamAV
integration. Antivirus covers explicit proxy HTTP downloads; HTTPS inspection
and IPsec are not implemented. A local Ollama/Qwen3 AI assistant and
SNMPv2c/v3 switch inventory, port/LLDP monitoring and confirmed port up/down
are available in alpha.2. The model/runtime must be installed separately. No Fortinet code or firmware is used.

See [AI and switch setup](docs/AI-SWITCHES.md), [alpha features](README-ALPHA.md), [Devuan build/install guide](docs/DEVUAN.md)
and [verification status](SOURCE_STATUS.md) before using a build.

