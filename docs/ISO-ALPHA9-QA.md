# Collaudo alpha.9 — parental control famiglia

Sorgente: `5dc406daae89e20adb7a207597730b9ad88c8e46`.
CI: https://github.com/blasterfish7/murus_igneus/actions/runs/40653511277

## Applicazione

- 216 test Python CI senza skip, inclusi SNMP reali e 21 nuovi casi di validazione, compatibilità dei vecchi backup, nomi dei dispositivi, fasce e DST, scadenza/precedenze dei bonus, DNS compiti/SafeSearch, stato IPv6 condiviso per LAN, aggiornamento/ripristino e provenienza delle liste.
- 14 controlli Chromium: compilazione reale della bozza, dispositivi nominati, Google/YouTube, preset compiti/notte, blocco IPv6 di LAN, aggiornamenti facoltativi, riepilogo/selezione per figlio, CSV, cancellazione e autenticazione TOTP. Regressioni Node, lint Python F/E9 e pacchetto DEB.
- Grafica originale verificata in Chromium a 1440 e 390 pixel: menu ricercabile per sezioni, temi chiaro/scuro, schede famiglia richiudibili e nessuno scorrimento orizzontale della pagina mobile iniziale.
- Installer console: quattro nuovi test di conferma, TTY, identità del disco e lock tra processi.
- Fixture TLS reale: status/auth rispondono durante il lock di transazione; le modifiche restano serializzate.
- 13 prove native e 9 IKEv2/strongSwan/failover WAN con pacchetti reali.
- 23 prove parental con veri dnsmasq/nftables/DHCP/TCP e proxy HTTP: VIP Google/YouTube, nessun inoltro AAAA non filtrato, compiti con domini scolastici e rifiuto degli altri record A/AAAA/TXT, ripristino a fine fascia, notte/bonus con filtri e pause conservati, aggiornamento attivo delle categorie e precedente protezione conservata dopo un download fallito. Restano le prove di resolver fermo, rollback, contatori reali e pulizia del report.
- La prova IPv6 usa indirizzi e vicini statici di laboratorio: il blocco di LAN impedisce un collegamento IPv6 instradato anche con un consenso successivo, e la rimozione dei soli blocchi permette il collegamento. Nessun router/AP domestico viene modificato.
- Quattro download HTTPS reali delle liste HaGeZi con validazione completa del formato.

## ISO originale

`murus-igneus-0.3.0-alpha.9-devuan-amd64.iso`, 475041792 byte.
SHA256: `320bafcb10698890b6931d3441bfa0fdc592665aa4e64e8cc852bd486222fbfe`.

DEB originale: 115640 byte, SHA256 `0567a75af44bd95b3a52b06764761bcb0070e586742e9cfc54d72b59a70babd6`.

58 controlli UEFI/live in QEMU TCG, 2 CPU, 2048 MiB, tre NIC Virtio: avvio/console, provenienza delle chiavi Devuan installate, HTTPS/Basic, backend e preview, IPsec/parental apply/rollback, fixture TLS installata, 13+9+23 prove di traffico da moduli installati e spegnimento regolare. L’accesso HTTPS attraverso la NIC di gestione verifica la pagina iniziale, l’inventario del disco e la richiesta di conferma. `murus-info` mostra gli URL effettivi e `murus-install --list` elenca il disco senza scriverlo. Il collaudo esegue poi `murus-install` su un disco virtuale vuoto dedicato di 16 GiB, immette la conferma esatta, spegne la live e riavvia dal solo disco senza CD/ISO. HTTPS torna raggiungibile e il backend riconosce il sistema installato.

La radice è creata con APT/mmdebstrap dai repository Devuan firmati, componenti main. L'archivio corrente non espone devuan-keyring: solo quel pacchetto pubblico di trust viene verificato con dpkg e ricostruito dal builder Devuan fissato per OCI SHA256; il resto del filesystem non viene rimasterizzato dal seed. bootstrap-provenance.json registra versione, immagine, digest del pacchetto e dei keyfile. La prova UEFI confronta versione e tutti i keyfile effettivamente installati. Vedere DEVUAN.md. Le verifiche di autenticazione APT rimangono obbligatorie.

Il publisher verifica la build originale, SHA256 ISO/DEB, rapporto di 58 controlli, manifesto di trust, tutti i 27 file applicativi e gli script installati contro i sorgenti e i digest di tutti gli allegati. Pubblica i binari collaudati senza ricompilarli e conserva le release precedenti.

## Limiti

Il controllo compiti è una lista DNS; cache, connessioni aperte, IP diretti e DoH/VPN sconosciuti restano limiti. SafeSearch si applica agli host/provider documentati, non è un test di efficacia sui contenuti o un'ispezione HTTPS. Il blocco IPv6 riguarda tutta la LAN che attraversa Murus, non la singola persona o il traffico diretto tra host. Schede su LAN differenti rimangono separate. Nessuna quota giornaliera o misura del tempo davanti allo schermo.

Non collaudati hardware fisico, BIOS/Secure Boot, interoperabilità FortiGate, scrittura switch, OpenAI live, aggiornamento applicativo completo con rollback o matrice completa di efficacia/prestazioni UTM. Lo scanner proxy parental è controllato. Restano i limiti IPv4/reporting di PARENTAL.md. Nessun codice o firmware Fortinet riutilizzato.
