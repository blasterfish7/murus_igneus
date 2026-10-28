# Murus Igneus 0.3.0-alpha.10 — schede di rete rilevate

Corregge la pagina Interfacce: nelle versioni precedenti mostrava solo gli oggetti già configurati, risultando vuota su un sistema appena installato. Ora l’inventario legge le schede presenti nel kernel Linux, indipendentemente dalla bozza.

- Dispositivo, MAC, collegamento, stato amministrativo e indirizzi attuali IPv4/IPv6, anche per porte scollegate.
- Porta di gestione visibile e marcata come riservata: non viene proposta per la configurazione dati.
- Pulsante Configura per una porta disponibile: apre la bozza con nome/dispositivo già selezionati. Gli indirizzi rilevati non vengono trasformati automaticamente in indirizzi statici.
- Porte già nella bozza indicate con il relativo nome; modifica senza duplicarle. VLAN e WireGuard rilevati rimangono visibili come interfacce virtuali.
- Rileva schede aggiorna l’inventario senza applicare configurazioni. I nomi Linux rilevati sono suggeriti anche nell’editor manuale, che continua ad accettare nuove VLAN.

Se è presente soltanto la scheda di gestione, viene mostrata esplicitamente: per una VM Proxmox aggiungere altre NIC e ripetere il rilevamento. L’inventario mostra ciò che Linux vede; driver mancanti o NIC non assegnate alla VM richiedono correzione nell’hypervisor/sistema.

Base Devuan 6/OpenRC, tutte le funzioni alpha.9 mantenute: nuova amministrazione, installer web/console, parental famiglia, VPN, UTM e assistente opzionale. Nessun codice o firmware Fortinet.

## WAN DHCP e rotta predefinita

Nel modulo di un’interfaccia dati scegliere Statico oppure DHCP client. Il client acquisisce IPv4, subnet e il primo gateway ricevuto, con metrica configurabile (100 predefinita); rinnova il lease e rimuove soltanto indirizzi/rotta di sua proprietà a scadenza, arresto o rollback. Sono supportati lease da 10 secondi a 7 giorni e una WAN DHCP alla volta. La doppia WAN e le rotte statiche su quella porta richiedono modalità statica. DNS DHCP mostrati nello stato ma non sostituiti ai DNS di sistema, nessuna rotta classless o IPv6 DHCP importata. Le subnet in conflitto con gestione, VPN o altre reti locali vengono rifiutate. Mancata risposta entro 15 secondi impedisce l’attivazione e avvia il ripristino della precedente configurazione.

Rotta predefinita apre il modulo con 0.0.0.0/0; anche 0.0.0.0 viene normalizzato a /0. Selezionare il nome della porta dati (con dispositivo Linux mostrato accanto) e il gateway WAN. La porta di gestione, normalmente eth0, resta dedicata alla gestione: non è una WAN dati. La WAN DHCP acquisisce il gateway automaticamente senza aggiungere una rotta statica manuale.

## Password unica e primo accesso

L’appliance usa la voce root di /etc/shadow come unica fonte per password web admin e console root. Il primo accesso obbliga a cambiare la password iniziale prima di configurare o installare: il blocco è imposto anche dalle API. Bastano 8–128 caratteri senza caratteri di controllo; non è richiesta complessità artificiale. Il modulo Amministrazione consente i cambi successivi. Dopo un cambio via web rientrare con la nuova password. Un cambio con passwd da console viene riconosciuto dal web; l’installazione su disco conserva la password scelta e non ripristina quella della ISO.

Per le precedenti installazioni con password web separata, il primo accesso dopo l’upgrade richiede una scelta esplicita della password comune; l’avvio del pacchetto da solo non cambia la password console. TOTP rimane richiesto quando già abilitato. Dopo il cambio non viene conservata una copia web in chiaro della password.

## Anti-lockout

La regola protetta Murus anti-lockout HTTPS consente TCP 8443 sull’interfaccia di gestione, indipendentemente dalle policy di transito. È visibile in Policy firewall e non modificabile dalla bozza. L’accesso amministrativo non viene aperto alla WAN. Restano la conferma entro 90 secondi e il ripristino automatico. La protezione riguarda la configurazione gestita da Murus, non scollegamenti fisici o modifiche esterne dell’indirizzo/interfaccia Linux.

## Accesso e installazione

Da un altro PC aprire https://IP-DI-GESTIONE:8443; utente GUI admin, console root: password iniziale comune igneus con cambio obbligatorio. Dopo il cambio usare la nuova password per entrambi. La console e murus-info mostrano gli indirizzi effettivi. Il backup FortiGate è facoltativo. Usare Installa su disco oppure murus-install da root; l’installazione richiede la conferma esatta della cancellazione del disco scelto. Dopo l’installazione spegnere, scollegare la ISO e riavviare dal disco.

Gli upgrade del pacchetto conservano la configurazione. I limiti funzionali di alpha.9 restano documentati in ALPHA9.md e PARENTAL.md. Il collaudo di questa immagine è registrato in ISO-ALPHA10-QA.md; nessuna certificazione per hardware fisico o Secure Boot.
