# Murus Igneus 0.3.0-alpha.10 — schede di rete rilevate

Corregge la pagina Interfacce: nelle versioni precedenti mostrava solo gli oggetti già configurati, risultando vuota su un sistema appena installato. Ora l’inventario legge le schede presenti nel kernel Linux, indipendentemente dalla bozza.

- Dispositivo, MAC, collegamento, stato amministrativo e indirizzi attuali IPv4/IPv6, anche per porte scollegate.
- Porta di gestione visibile e marcata come riservata: non viene proposta per la configurazione dati.
- Pulsante Configura per una porta disponibile: apre la bozza con nome/dispositivo già selezionati. Gli indirizzi rilevati non vengono trasformati automaticamente in indirizzi statici.
- Porte già nella bozza indicate con il relativo nome; modifica senza duplicarle. VLAN e WireGuard rilevati rimangono visibili come interfacce virtuali.
- Rileva schede aggiorna l’inventario senza applicare configurazioni. I nomi Linux rilevati sono suggeriti anche nell’editor manuale, che continua ad accettare nuove VLAN.

Se è presente soltanto la scheda di gestione, viene mostrata esplicitamente: per una VM Proxmox aggiungere altre NIC e ripetere il rilevamento. L’inventario mostra ciò che Linux vede; driver mancanti o NIC non assegnate alla VM richiedono correzione nell’hypervisor/sistema.

Base Devuan 6/OpenRC, tutte le funzioni alpha.9 mantenute: nuova amministrazione, installer web/console, parental famiglia, VPN, UTM e assistente opzionale. Nessun codice o firmware Fortinet.

## Accesso e installazione

Da un altro PC aprire https://IP-DI-GESTIONE:8443; account GUI admin/igneus, console live root/igneus. La console e murus-info mostrano gli indirizzi effettivi. Il backup FortiGate è facoltativo. Usare Installa su disco oppure murus-install da root; l’installazione richiede la conferma esatta della cancellazione del disco scelto. Dopo l’installazione spegnere, scollegare la ISO e riavviare dal disco.

Gli upgrade del pacchetto conservano la configurazione. I limiti funzionali di alpha.9 restano documentati in ALPHA9.md e PARENTAL.md. Il collaudo di questa immagine è registrato in ISO-ALPHA10-QA.md; nessuna certificazione per hardware fisico o Secure Boot.
