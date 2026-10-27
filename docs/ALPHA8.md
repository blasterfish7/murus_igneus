# Alpha.8 — gestione reattiva e rollback verificato

Integra le PR #9 e #10 sulla base alpha.7. Credenziali di laboratorio invariate: admin/igneus sulla GUI e root/igneus nella ISO; il DEB conserva la password root del sistema.

## Stato durante l'applicazione

Le letture autenticate `/api/status` e `/api/auth/status` rispondono senza attendere il lock della transazione, anche mentre vengono attivati i servizi. Lo stato pendente viene copiato prima di costruire la risposta. Restano autenticazione Basic/TOTP e CSRF; letture della configurazione e operazioni di modifica rimangono serializzate. La variazione non rende asincrona l'applicazione né garantisce tempi di risposta se il sistema operativo o i servizi sono bloccati.

## Ripristino idempotente e controllato

Un comando inverso della rete viene eseguito controllandone l'esito. Se fallisce, il rollback interroga nuovamente il kernel e può proseguire soltanto quando lo stato richiesto è già verificato: rotta/indirizzo/VLAN già assenti dopo una cancellazione, oppure rotta/indirizzo/stato link/alias/VLAN già corretti dopo un ripristino. Per le rotte si verificano gateway, dispositivo e metrica; per gli indirizzi interfaccia e prefisso; per le VLAN identificativo e interfaccia padre.

Le operazioni inverse vengono registrate dopo il successo dell'operazione originale; possono risultare già assolte dalla rimozione delle dipendenze, da altri cleanup o da interventi esterni. Non si assume che un messaggio di errore significhi automaticamente "risorsa già assente". Readback fallito, risposta non valida o stato diverso restano errori reali.

Errori di svuotamento conntrack e ripristino forwarding sono ancora segnalati e comportano il tentativo di mantenere il firewall di sicurezza; non vengono ignorati con check=False. Rimangono le garanzie della alpha.7: pending liberato, esito incompleto visibile nella GUI/API, fallback tentato su errore. Se anche nft non riesce a installarlo, non viene dichiarata una protezione ripristinata.

## Verifiche e limiti

Test unitari per stato già corretto, indirizzi/prefissi, rotte/gateway/metriche, VLAN/tag/padre, readback non valido e fallimenti reali di conntrack/sysctl. Prove reali con route già assente e DNAT nuovamente operativo, oltre al precedente errore nft con transito bloccato. Una fixture HTTPS con i moduli installati verifica che le due letture di stato rispondano mentre una scrittura resta in attesa del lock.

La versione alpha.8 conserva le release precedenti. Risultati effettivi della build e della ISO vengono registrati negli allegati e in ISO-ALPHA8-QA.md. Nessuna nuova certificazione hardware, installazione su disco, Secure Boot, interoperability FortiGate o efficacia completa UTM. Vedere ALPHA7.md, ALPHA5.md e PARENTAL.md per le funzioni precedenti e relativi limiti. Nessun codice o firmware Fortinet riutilizzato.
