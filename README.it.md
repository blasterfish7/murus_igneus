# Murus Igneus

[English](README.md) · **Italiano** · [Latine](README.la.md) · [Documentazione / Documentation](docs/INDEX.md)

Firewall IPv4 indipendente e open source per Devuan 6 Excalibur con OpenRC. Si installa da ISO o da pacchetto DEB e si gestisce via HTTPS. L'importazione di backup testuali FortiGate è facoltativa: puoi partire da una configurazione vuota. Il progetto non riutilizza codice, firmware o risorse Fortinet.

[Scarica la prerelease alpha.12](https://github.com/blasterfish7/murus_igneus/releases/tag/v0.3.0-alpha.12) · [Installazione e aggiornamento](docs/ALPHA12.md)

- **Rete:** policy nftables, NAT, VLAN, DHCP/DNS, WAN DHCP, rotte statiche, VPN WireGuard e IKEv2, failover per due WAN statiche.
- **Amministrazione:** configurazione in bozza con verifica, conferma entro 90 secondi e rollback. SSH con chiave Ed25519 sulla sola interfaccia di gestione, spento di default; TOTP facoltativo. Aggiornamenti applicativi firmati con backup e recupero.
- **Famiglia:** profili per dispositivo, filtro DNS per categorie, orari Internet e fasce social indipendenti, modalità compiti, pausa e report locali. I blocchi DNS non interrompono necessariamente connessioni aperte e non coprono traffico su rete mobile.
- **UTM sperimentale:** Suricata IPS e proxy antivirus ClamAV per HTTP. Nessuna ispezione del contenuto HTTPS. Assistente Ollama locale o OpenAI facoltativo e inventario switch SNMP.

Per una prima prova usa una VM dedicata, con console disponibile e interfacce separate per gestione e traffico. Consulta le [guide tecniche](docs/INDEX.md) per prerequisiti, limiti e collaudi. La documentazione è disponibile in italiano e inglese; i comandi e le etichette dell'interfaccia sono riportati come appaiono nel prodotto.
