# Collaudo alpha.8 — PR #9 e #10

Sorgente combinato: `bf328cc0dfff2d4a3877004d14f16aa6d1ab8e98`.
CI: https://github.com/blasterfish7/murus_igneus/actions/runs/40504087723

## Verifiche

- 191 test Python CI senza skip, compresi SNMP reali, il test HTTPS della PR #9 e 12 casi di rollback verificato: rotta/indirizzo già assente, ripristino già corretto, gateway/dispositivo/metrica diversi, prefisso errato, readback fallito o non valido, link/alias, tag/padre VLAN, conntrack/sysctl e ruleset nft falliti.
- 10 controlli Chromium, regressioni UI Node, lint Python F/E9 e pacchetto DEB.
- Fixture TLS reale con il gestore e i moduli del prodotto: status e auth/status rispondono mentre il lock è occupato; una richiesta di modifica rimane serializzata.
- 13 prove native con pacchetti reali. La nuova prova inserisce una cancellazione di rotta già assente nell'undo: il kernel conferma l'assenza e il rollback ripristina DNAT funzionante. Rimane la prova di ruleset precedente davvero invalido per nft, con pending liberato, transito bloccato e regola di gestione conservata.
- 9 prove IKEv2/strongSwan e failover WAN, 17 parental/reporting e quattro download HTTPS reali delle liste HaGeZi.

## ISO originale

ISO `murus-igneus-0.3.0-alpha.8-devuan-amd64.iso`.
Dimensione 475123712 byte.
SHA256 `ffc6778201699ebf5a4677be7a7d986f0a1f66bbdce393ce64a8c58c4a5a0972`.

46 controlli UEFI/live in QEMU TCG, 2 CPU, 2048 MiB, tre NIC Virtio: avvio/console, Basic via HTTPS, backend effettivo e preview, IPsec/parental apply/rollback, fixture di gestione HTTPS con i moduli installati, 13+9+17 prove di rete da moduli installati, spegnimento regolare.

La fixture di gestione è un server TLS temporaneo su loopback con blocco della transazione controllato: non altera il servizio principale né la rete. Lo script di prova usa risposte di link controllate; le prove native invece interrogano nft/ip del kernel reale in namespace isolati.

Il publisher verifica build originale, SHA256 ISO/DEB, rapporto di 46 controlli, corrispondenza dei 27 file applicativi e degli script installati con i sorgenti, e digest degli allegati. Non ricompila e conserva le release precedenti.

## Limiti

Il readback di rete avviene dopo un comando fallito e deve confermare la postcondizione; non basta un testo di errore. Gli errori reali di conntrack/forwarding continuano a essere segnalati. Se anche il fallback nft fallisce, la protezione non viene dichiarata ripristinata. La gestione reattiva riguarda due endpoint di stato: altre letture e modifiche rimangono serializzate; apply resta sincrona.

Non collaudati installazione su disco/boot autonomo alpha.8, hardware, BIOS/Secure Boot, interoperabilità FortiGate, scrittura switch, OpenAI live, aggiornamento applicativo completo con rollback o matrice completa di efficacia/prestazioni UTM. I test proxy parental usano uno scanner controllato. Restano limiti IPv4/DNS/reporting di PARENTAL.md e quelli delle versioni precedenti. Nessun codice/firmware Fortinet riutilizzato.
