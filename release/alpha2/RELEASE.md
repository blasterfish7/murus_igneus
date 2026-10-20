## Murus Igneus 0.3.0-alpha.2 — Devuan amd64

Prerelease sperimentale da laboratorio. ISO installabile su PC/VM x86_64, basata su Devuan 6 Excalibur. Codice originale e componenti open source; nessun codice o firmware Fortinet riutilizzato.

### Funzioni
- Installer web e configurazione da zero; importazione backup FortiGate facoltativa.
- Firewall nftables, VPN WireGuard, IPS Suricata e antivirus ClamAV tramite proxy HTTP.
- Assistente AI nella GUI tramite Ollama/Qwen locale: runtime e modello da installare separatamente. Le proposte passano dalla bozza e richiedono applicazione e conferma manuali.
- Switch locali via SNMPv2c/v3: inventario, stato porte, contatori, LLDP e comandi up/down con anteprima e conferma testuale. Scrittura disabilitata di default.

### Avvio
Aprire `https://IP-gestione:8443`. GUI: `admin / igneus`; console: `root / igneus`. eth0 usa DHCP o fallback `192.168.56.1/24`. Leggere la guida allegata prima dell'installazione su disco.

### Collaudi e limiti
94 test automatici superati. Verificati avvio UEFI, installer web, riavvio dal disco e persistenza AI/SNMP. SNMP provato su agente di laboratorio, inclusi SET su porta emulata; compatibilità con switch fisici ancora da verificare.
Le risposte reali Qwen3:4b hanno mostrato errori e proposte non valide, rifiutate dal validatore: le proposte AI restano sperimentali. Nessuna gestione VLAN, PoE o FortiLink. Nessuna ispezione antivirus HTTPS. ClamAV incluso 1.4.3, mentre FreshClam raccomanda 1.4.6: limite aperto. La suite completa di traffico VPN/UTM della alpha.1 non è stata ripetuta sulla alpha.2.

### Provenienza
Binari originali della [build verificata 39339700961](https://github.com/blasterfish7/murus_igneus/actions/runs/39339700961), commit `e749f34fb5ab5e497197241e8c1879a62555cbe4`. Nessuna ricompilazione per questa release. Sviluppo nella [PR #5](https://github.com/blasterfish7/murus_igneus/pull/5), ancora separata dai rami principali.

Verificare i file con il manifest SHA-256 allegato.
