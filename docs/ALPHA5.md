# Alpha.5: sviluppo e collaudo

Questa modifica prepara la alpha.5; la release pubblicata rimane alpha.4 finché il nuovo artefatto non viene collaudato e pubblicato. Solo codice originale e componenti open source della distribuzione; nessun codice, firmware o asset Fortinet.

## Assistente

Provider locale Ollama/Qwen3 conservato, senza runtime o pesi nella ISO. Provider OpenAI opzionale con Responses API, HTTPS verificato, destinazione fissa api.openai.com, chiave root-only `/etc/murus_igneus/openai.key` mai restituita dall’API. Richiede consenso esplicito all’invio di domanda, bozza e telemetria. `store:false` non è una promessa di assenza di qualsiasi conservazione lato servizio. Nessun tool remoto, nessuna applicazione automatica, limite configurabile 256–8192 token di risposta. I costi dipendono dal modello e dalla quota del progetto OpenAI; non esiste un tetto monetario implementato nell’appliance. Chiave vuota: conserva; eliminazione esplicita: rimuove. Client open source, servizio OpenAI esterno non open source.

Aggiornato il prompt su VLAN/DHCP/DNS/DNAT e aggiunti conteggi verificati delle autorizzazioni DNAT/IPsec. Credenziali strutturate rimosse dal contesto; redazione del testo libero soltanto best effort. IP, nomi e descrizioni possono restare riservati. Le proposte conservano le PSK dei peer esistenti sul server solo se identità e indirizzo del peer non cambiano; nuovo peer richiede una PSK locale valida. Test provider con risposte controllate: non dimostrano qualità del modello né una chiamata live al servizio.

## IKEv2

strongSwan charon/swanctl dedicato, socket VICI separato; nella ISO il servizio di distribuzione ipsec è disabilitato per lasciare il controllo a Murus. Installando il solo DEB su un sistema dedicato, fermare/disabilitare un eventuale servizio ipsec preesistente prima di abilitare i tunnel Murus; non gestire in parallelo due daemon. configurazione runtime privata. Massimo 16 tunnel IPv4 con peer statico e PSK di 20–128 caratteri. IKE/ESP AES256-SHA256-MODP2048, trap policy, DPD 30s. Selettore locale direttamente attestato su una LAN dati, selettore remoto non sovrapposto. Ogni tunnel autorizza il traffico tra i selettori in entrambe le direzioni, prima delle policy native; deve essere esplicitamente abilitato. Regole legate a interfacce e reqid XFRM, blocco delle coppie non cifrate, esenzione SNAT. La successiva catena IPS resta applicata. Non è importazione VPN FortiGate, né client mobile, VTI, IKEv1, certificati o supporto di ogni scenario interoperabile.

Su sistemi con profili AppArmor strongSwan attivi, autorizzare `/run/murus-igneus/** rw,` nelle estensioni locali dei profili charon e swanctl e ricaricarli: il pacchetto non disabilita AppArmor né modifica profili locali già amministrati. Il laboratorio CI autorizza soltanto i percorsi temporanei del test.

## Due WAN statiche

Due WAN dichiarate, preferenza nell’ordine, 1–2 destinazioni ICMP esterne per linea. Tre successi/fallimenti consecutivi cambiano lo stato, controlli ogni 5s più durata delle prove. Una destinazione raggiungibile mantiene sana la linea. Rotta principale dedicata protocollo 186/metrica 18080, tabelle e regole 18081/18082 per le prove con sorgente specifica. Collisioni con rotte default esterne e tabelle/regole esistenti bloccano l’avvio. Reverse-path filtering portato a loose sulle WAN e ripristinato allo stop. Nessuna linea sana: default unreachable. Le policy devono autorizzare entrambe le WAN. Le vecchie connessioni possono interrompersi: niente bilanciamento, persistenza sessioni, SLA applicativi o migrazione automatica IPsec. Nessun ripristino di connessioni HA.

## MFA e log

Password amministratore più TOTP RFC6238 a 6 cifre, finestra ±30s, protezione replay persistente, massimo 5 tentativi TOTP/minuto per sorgente, sessioni di 15 minuti legate all’IP, cookie Secure/HttpOnly/SameSite=Strict. Enrollment a due passi: attivazione solo dopo prova del codice. Recovery console root: rimuovere `/etc/murus_igneus/mfa.json` e riavviare. Non sono implementati RBAC, LDAP/RADIUS o cifratura del disco; password base invariata.

SQLite root-only in `/etc/murus_igneus/logs`: audit dei POST (percorso, esito e sorgente, senza body), eventi kernel policy/DNAT raccolti ogni 5s, deduplicati per avvio e messaggio. Massimo circa 20.000 righe o 30 giorni, API ultimi 1000. Eventi limitati per frequenza/buffer e possibili perdite nei riavvii; non è un SIEM né audit antimanomissione. In live senza persistenza lo storico si perde.

## Aggiornamento firmato della sola applicazione

`murus-update verify DIRECTORY`, `murus-update install DIRECTORY`, `murus-update rollback`. La directory contiene `murus-igneus.deb`, `manifest.json` e firma binaria Ed25519 `manifest.sig` (64 byte). Manifest esatto: `{"schema":1,"package":"murus-igneus","version":"0.3.0~alpha.5","sha256":"HASH_DEB"}`.

L’amministratore installa fuori banda la chiave pubblica del firmatario in `/etc/murus_igneus/update.pub`. Senza chiave attendibile l’aggiornamento fallisce. Nessuna chiave privata di produzione è generata, inclusa o pubblicata dal progetto. Firmare su una macchina separata:

```sh
openssl pkeyutl -sign -inkey signer-private.pem -rawin -in manifest.json -out manifest.sig
```

Verifica firma, SHA256, nome/versione/architettura del DEB e versione crescente. Prima dell’installazione crea uno snapshot locale con dpkg-repack; errore installazione/riavvio tenta ripristino. Rollback esplicito verifica checksum dello snapshot locale root-only. Non sono aggiornamenti atomici A/B dell’intero OS, non aggiornano kernel/base Devuan, non fanno ripristino della configurazione e non sono una release firmata finché il maintainer non firma un bundle con la propria chiave. Installazione da console, non dal processo web.

## Verifica

Eseguire suite Python/JavaScript, GUI Chromium e i laboratori isolati `validate-native-networking.py` e `validate-enterprise-runtime.py`. Il secondo usa veri charon, nftables e pacchetti in namespace separati, verificando IKEv2, blocco plaintext, failover e ripristino WAN. La ISO richiede successivo avvio UEFI e verifica delle funzioni nuove nell’immagine; i report alpha.4 non attestano la alpha.5. Compatibilità FortiGate e hardware reale non ancora attestata.
