# Collaudo alpha.7 — correzioni autenticazione e rollback

Build: `64a4b5dad271bd0ea86e2c19822a5b6974c10105`.
CI: https://github.com/blasterfish7/murus_igneus/actions/runs/40207093633

## Verifiche

- 178 test Python CI senza skip, inclusi SNMP reali e otto nuovi casi di regressione: crescita continua del registro password, capacità/recupero spazio, 32 richieste simultanee, HTTP 401/429/scadenza e risposta API di rollback incompleto, errori nelle singole fasi del ripristino, errore nella generazione delle regole di sicurezza, errore finale del fallback e timer obsoleto.
- 10 controlli Chromium 153.0.8010.0, sintassi shell/JavaScript, regressioni Node e lint Python F/E9.
- 12 prove di rete con pacchetti reali. L'aggiunta rispetto alla alpha.6 causa un errore effettivo di sintassi nft nel ruleset precedente: verifica pending liberato, traffico inoltrato bloccato e regola di gestione HTTPS conservata. Restano prove VLAN/DHCP/DNS/DNAT/conntrack/rollback manuale e timer reale di 90 secondi.
- 9 prove IKEv2/strongSwan e failover statico di due WAN, 17 prove parental/reporting, quattro download HTTPS reali delle liste HaGeZi.

## ISO originale

`murus-igneus-0.3.0-alpha.7-devuan-amd64.iso`
Dimensione: 475041792 byte.
SHA256: `44c2af50e1a5df6dd4335a36fcee5a58133bfc5c0091bfb2cf556c0bb594115e`.

44 controlli superati in QEMU TCG UEFI/live, 2 CPU, 2048 MiB, tre NIC Virtio: avvio e console, autenticazione Basic reale attraverso HTTPS (10 password errate, 429 anche per credenziali corrette mentre bloccato, altro indirizzo operativo), backend reale/preview iniziale senza backup, applicazione e rollback IPsec/parental, le 12+9+17 prove di rete sui moduli installati nell'immagine, spegnimento regolare.

La ISO collaudata viene conservata in una release privata in bozza quando GitHub Actions rifiuta l'upload per quota. Il publisher verifica sorgente/build, hash ISO/DEB, rapporto originale di 44 controlli, corrispondenza dei 27 file applicativi e degli script installati con i sorgenti, e digest degli allegati. Nessuna ricompilazione durante la pubblicazione. La alpha.6 pubblicata rimane invariata.

## Limiti

Il recupero mantiene il firewall di sicurezza se nft riesce a installarlo; se anche il fallback fallisce, il risultato è esplicitamente incompleto e richiede intervento. PENDING viene liberato e l'API riporta ok:false. Il limite Basic non è una protezione completa da DoS/attacchi distribuiti; client dietro lo stesso NAT condividono la soglia. Le credenziali iniziali di laboratorio restano invariate, come richiesto nella PR di Claude. Il lock globale di apply resta durante l'attivazione dei servizi.

Nessuna nuova prova di installazione su disco/avvio autonomo, BIOS/Secure Boot, hardware fisico o interoperabilità FortiGate; nessuna matrice completa di efficacia/prestazioni UTM, scrittura switch, servizio OpenAI live o aggiornamento applicativo completo con rollback. I test proxy parental usano uno scanner controllato. Restano limiti del reporting DNS e IPv4 documentati in PARENTAL.md. Nessun codice/firmware Fortinet riutilizzato.

Dettagli operativi: [ALPHA7](ALPHA7.md), [parental/reporting](PARENTAL.md), [funzioni precedenti](ALPHA5.md).
