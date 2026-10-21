# Collaudo ISO alpha.3 — 21 ottobre 2026

**Esito: verifiche funzionali superate, con osservazioni sullo spegnimento in emulazione.**
La ISO originale è stata avviata in UEFI, installata dalla pagina web su un disco
virtuale vuoto e il disco è stato avviato senza ISO collegata. Non è stata
ricompilata o modificata l'immagine durante il collaudo.

## Identità dell'immagine

- ISO: `murus-igneus-0.3.0-alpha.3-devuan-amd64.iso`, 472274944 byte.
- SHA-256: `cac1e14d3a82740e3332c43fa3bd81de86444eaf6cffa61c2415fa0223c57e26`.
- Sorgenti: `f7517ea456a751c0e0e7e08675d56c5de5903349`.
- [Build originale 39407442852](https://github.com/blasterfish7/murus_igneus/actions/runs/39407442852), artefatto ISO `12257179355`.
- Verificati sia il digest dell'archivio scaricato sia il checksum della ISO.

Ambiente: QEMU 8.2.2 con emulazione TCG, OVMF UEFI senza Secure Boot,
2 vCPU, 3072 MiB RAM, disco VirtIO vuoto da 10 GiB, tre interfacce VirtIO e
reti virtuali isolate. Browser Chromium 153.0.8010.0.

## Verifiche eseguite

| Verifica | Esito e dettaglio |
| --- | --- |
| Avvio live UEFI | Kernel 6.12.113 e servizio di gestione alpha.3 avviati. |
| Accesso HTTPS | Autenticazione richiesta; POST senza token CSRF rifiutato. |
| Configurazione da zero | Bozza iniziale vuota verificata, applicata e confermata, senza backup FortiGate. |
| Rollback | Modifica delle interfacce applicata temporaneamente e annullata; regole precedenti ripristinate. |
| Connettore AI | Verifica modello e domanda tramite risposta HTTP controllata compatibile con Ollama; nessuna applicazione automatica. |
| Switch | Inventario SNMPv3 salvato; password escluse dall'API; file credenziali con permessi 0600; client Net-SNMP installati. |
| VPN e UTM live | WireGuard, Suricata IPS, ClamAV e proxy HTTP attivati. |
| Antivirus live | Scansioni ClamAV reali: contenuto pulito accettato, EICAR bloccato. Proxy: HTTP 200 per il file pulito, 403 per EICAR e 502 per il 304 a monte. |
| Interfaccia web live | Pagine AI, switch, VPN e UTM controllate nel browser senza eccezioni JavaScript. |
| Installer web | Conferma errata rifiutata dal server e pulsante disabilitato nel browser; conferma esatta del disco seguita dall'installazione completata. |
| Avvio dal disco | Seconda VM avviata con il solo disco installato, senza unità ISO; root su /dev/vda3 tramite UUID. |
| Persistenza | Configurazione VPN/UTM, impostazioni AI e inventario/credenziali SNMP presenti dopo il riavvio; credenziali ancora private. |
| WireGuard installato | Tunnel con IPv4 configurato e chiave privata 0600, con data precedente a questo avvio: non rigenerata al boot. |
| UTM installato | IPS, ClamAV e proxy pronti; ripetute con successo scansioni pulito/EICAR e prove HTTP 200/403/502. |
| Web installato | Pagine funzionanti senza eccezioni JavaScript; installer indisponibile sul sistema installato. |
| Arresto finale | Spegnimento del sistema installato completato; VM di prova spenta. |

I risultati strutturati contengono [17 verifiche di accettazione](qa/alpha3-iso-validation.json).
Non sono ulteriori test unitari: i 101 test della build originale restano
un'evidenza distinta.

## Osservazioni

Lo spegnimento della sessione live ha superato il limite iniziale di 90 secondi
dello script di prova. La VM è stata fermata dopo che l'installer aveva completato
sincronizzazione e smontaggio della destinazione. Il collaudo è proseguito sullo
stesso disco, senza reinstallazione. Lo spegnimento successivo del sistema
installato è stato atteso fino al completamento con un limite più ampio.
Avvio, attivazione UTM e installazione hanno richiesto diversi minuti in TCG:
questi tempi non misurano le prestazioni su KVM o hardware fisico.

Restano visibili avvisi OpenRC relativi al nome `udev` reale/virtuale. La generazione
dell'initramfs ha utilizzato gzip perché zstd non era installato. Questi avvisi
non hanno impedito l'installazione o il successivo avvio dal disco.
ClamAV incluso resta 1.4.3; la raccomandazione FreshClam per 1.4.6, già documentata,
non viene risolta da questo collaudo.

## Limiti delle prove

L'AI è stata verificata con un server HTTP controllato, senza modello reale:
non è una verifica dell'accuratezza delle risposte o delle proposte Qwen3.
Nessun comando è stato inviato a switch fisici; compatibilità dei modelli e SET
su porte reali restano da verificare.

Per VPN/IPS sono stati verificati avvio e ripristino dei servizi, non una nuova
matrice completa di traffico inoltrato, NAT o handshake WireGuard. Le prove del
proxy HTTP sono richieste reali originate nel guest con indirizzo sorgente LAN,
verso un server di test controllato: non equivalgono a una prova con un client
fisico esterno attraverso le interfacce di rete. Nessun test di antivirus HTTPS,
Secure Boot, avvio BIOS o compatibilità hardware fisica.

La Release pubblicata alpha.2 non è stata modificata. Questa evidenza riguarda
esclusivamente l'artefatto alpha.3 identificato sopra.
