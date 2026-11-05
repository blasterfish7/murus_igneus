# AI assistant and local switches

[Italiano](AI-SWITCHES.md) · **English** · [Documentation](INDEX.md)

## AI assistant

Open **Assistente AI** on the HTTPS management interface. Murus can use a separate Ollama server on a trusted private network with Qwen3 0.6b, 1.7b, 4b or 8b. The MIT runtime and Apache-2.0 model weights are separate from Murus; they are not bundled or downloaded automatically. Run the local server with `OLLAMA_NO_CLOUD=1`. If listening on the LAN, set `OLLAMA_HOST` to the private address and port 11434 and restrict access to the firewall. Its plain HTTP API does not by itself provide authentication or encryption.

1. Enter `http://PRIVATE-IP:11434` (or `http://127.0.0.1:11434` if installed locally), choose a model and save.
2. Use **Verifica modello** before enabling the assistant. A separate machine avoids competing with IPS and antivirus for RAM and CPU.
3. Questions can include the configuration draft, validation output and switch telemetry. Policy logs are optional. Password files and VPN private keys are not read for this purpose.
4. To request a proposed configuration, explicitly allow it. The result must pass the Murus validator. Loading it changes only the draft; inspect it in **Verifica e applica** before applying and confirming.

Recent releases also offer an optional hosted OpenAI Responses API provider. Select it only if you accept sending selected context to the provider and supply your own API key. Structured credentials are removed, but IPs, names, logs and free text can still be sensitive. The OpenAI service is external; its client in Murus is open source.

AI can make mistakes. It does not run shell commands, apply firewall policies, operate switches or replace IPS/antivirus. One task runs at a time; timeout is 120 seconds for analysis and 240 seconds for proposals. Murus does not keep a persistent chat history. A result replaced by a concurrent session requires a new request.

## Local switch inventory and port changes

In **Switch locali**, enter a private IPv4 address, UDP port (default 161), and credentials already configured on the switch. Supported methods: SNMPv3 authPriv with SHA/AES or SNMPv2c (plaintext community). Up to 32 manually added devices; there is no discovery scan. Credentials are stored in `/etc/murus_igneus/switches.json` (0600) and are not returned by APIs or sent to AI. Leave password fields empty when editing to retain them. See the [Italian guide](AI-SWITCHES.md) for accepted characters.

**Leggi stato** reads IF-MIB port indices, admin/operational state, nominal speed and cumulative 32-bit counters. Counters can wrap and do not show instantaneous throughput. LLDP neighbors appear only if the MIB is exposed; LLDP indices can differ from IF-MIB. A failed read invalidates old telemetry.

1. Protect management, uplink and aggregation indices in **porte protette**.
2. Enable writing explicitly and grant only the necessary switch permissions for `ifAdminStatus`.
3. Preview a port change. Murus rereads the device and issues a single-use token valid 120 seconds.
4. Enter the displayed confirmation. The backend rechecks device identity, state and configuration, performs one SET and verifies the final state.

Switch writes have **no automatic rollback**. A timeout after SET can leave the outcome uncertain: reread before retrying. Persistence depends on the switch vendor; Murus does not issue proprietary save commands. VLAN, trunk, LAG, PoE, STP, firmware and FortiLink adoption are outside scope.

AI and switch settings are separate from firewall draft exports. The installer copies state; changes in a non-persistent live session are lost at reboot. Existing settings are retained on package upgrade. Net-SNMP is supplied by Devuan `main`. See the [Italian guide](AI-SWITCHES.md) for upstream references.
