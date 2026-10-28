# Collaudo alpha.10 — rete, password unica e anti-lockout

Sorgente: `a5249d17f0a50e3aa45195b50d7ba6be8c7e856a`.
CI: https://github.com/blasterfish7/murus_igneus/actions/runs/40662424590

## Correzione

La pagina Interfacce distingueva soltanto gli oggetti già dichiarati nella bozza, risultando vuota dopo l’installazione. Un inventario separato legge ora `ip -j -d address show`, senza consultare o modificare la bozza. Mostra tutte le NIC non loopback, comprese la gestione riservata e le porte scollegate, MAC, collegamento, stato amministrativo e indirizzi IPv4/IPv6. La scelta di una porta apre l’editor nella bozza, con indirizzo statico vuoto; nessun DHCP osservato viene convertito automaticamente in configurazione permanente. Le VLAN rilevate e WireGuard sono visibili ma non proposti come nuove porte fisiche. Le porte già nella bozza aprono la modifica invece di duplicarsi.

## Applicazione

- 231 test Python in CI, zero skip, inclusi tre nuovi casi di inventario: gestione/porte scollegate senza bozza, esclusione tunnel/VLAN dalle scelte fisiche, inventario vuoto e dati di indirizzo incompleti.
- 19 controlli reali in Chromium: inventario con bozza vuota, gestione visibile ma riservata, MAC e indirizzi, porta senza collegamento, configurazione della porta selezionata, nessuna duplicazione, inventario con sola gestione, errore esplicito e ultima lettura segnalata, aggiornamento in sola lettura e layout mobile. Restano i controlli di configurazione reale/compilatore, famiglia/report e TOTP.
- Password: sette nuovi casi per autorità root unica, scadenza/primo cambio, cambi console riconosciuti dal web, validazione, account bloccati, errore di aggiornamento, migrazione senza cambio console automatico e conservazione durante installazione.
- DHCP client e rotte: cinque nuovi casi per piani/porte riservate, regole UDP, gateway automatico, normalizzazione /0 e lease/gateway/subnet non attendibili.
- Lint F/E9, sintassi, regressioni JavaScript, pacchetto DEB e fixture HTTPS con lock di transazione.
- 13 prove native, 9 VPN IKEv2/failover WAN, 23 parental con pacchetti reali e quattro download HTTPS reali delle liste.

## WAN DHCP, password condivisa e anti-lockout

Sei prove reali con udhcpc/dnsmasq: acquisizione IPv4/default route con NAT, rinnovo senza modifica DNS di sistema, rollback a statico, pulizia reale su scadenza registrata controllata dal laboratorio, assenza server con ripristino, accesso TCP 8443 consentito dalla gestione anche con dati negati e rifiutato dalla WAN.

La ISO verifica il blocco API prima del cambio iniziale, cambia la password attraverso HTTPS esterno, accede alla console con quella password, esegue passwd e verifica la nuova password nel web con rifiuto della precedente. Il successivo riavvio del disco usa la stessa password modificata, verificando che l’installer non ripristini quella di fabbrica.

## ISO originale

`murus-igneus-0.3.0-alpha.10-devuan-amd64.iso`, 475052032 byte.
SHA256: `c60bbab52010d09e1dd283eba6a204e400b6606b99b1b9ec314731f943fcffaa`.

DEB originale: 121764 byte, SHA256 `1954d47f9e0f878c7641cf5def9274e234c88abe932bdc36f5a0ebbdb205e710`.

67 controlli in QEMU TCG UEFI, due CPU, 2048 MiB e tre NIC Virtio. La nuova verifica interroga l’API HTTPS realmente installata: tutte le tre schede sono presenti con MAC; la gestione è marcata come riservata e mostra l’indirizzo assegnato dal sistema. Seguono le prove di rete/VPN/parental dell’immagine originale, installazione su disco virtuale vuoto dedicato da 16 GiB, spegnimento e riavvio UEFI dal solo disco con ISO scollegata. HTTPS rimane raggiungibile dalla NIC di gestione nel sistema installato.

Devuan 6/main con APT/mmdebstrap e firme obbligatorie; soltanto il pacchetto pubblico devuan-keyring è verificato/esportato dal builder Devuan fissato per digest OCI. Provenienza e hash di tutti i keyfile sono registrati e confrontati al boot. Vedere DEVUAN.md e il manifesto allegato.

Il publisher controlla CI, ascendenza del sorgente, hash ISO/DEB, rapporto di 67 verifiche, provenienza, tutti i 28 file applicativi del pacchetto e gli script installati contro i sorgenti. Pubblica gli stessi binari collaudati senza ricompilare e verifica tutti i digest degli allegati.

## Limiti

L’inventario mostra ciò che il kernel vede: non rileva NIC non assegnate alla VM o senza driver. Una VM con la sola porta di gestione richiede ulteriori NIC per il transito dati. Nessuna scoperta automatica dei ruoli LAN/WAN e nessuna modifica della rete tramite rilevamento. L’inventario di indirizzi IPv6 non aggiunge supporto firewall IPv6. Restano i limiti di ALPHA9.md/PARENTAL.md, inclusi filtri basati su DNS, IP diretti, cache, VPN/DoH sconosciuti e rete mobile. Nessuna certificazione per hardware fisico, BIOS/Secure Boot, prestazioni/efficacia UTM complete o interoperabilità FortiGate. Nessun codice o firmware Fortinet.
