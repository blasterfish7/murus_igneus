# Murus Igneus 0.3.0-alpha.9 — gestione famiglia

Base Devuan 6 Excalibur/OpenRC. Implementazione indipendente con componenti open source; nessun firmware o codice Fortinet.

## Nuove funzioni

- Una scheda per figlio/profilo raccoglie dispositivi della stessa LAN, nomi associati agli IPv4 singoli e scelta dalle prenotazioni DHCP già configurate. Regole, pause e bonus condivisi. LAN differenti richiedono schede separate; nessuna identificazione automatica delle persone.
- Google SafeSearch per www.google.com, .it, .co.uk, .fr, .de, .es; YouTube Restricted Mode moderato/rigoroso per i cinque host indicati da Google. Richiedono DNS forzato; un blocco del servizio continua a prevalere. Nessuna ispezione HTTPS. Bing e DuckDuckGo non inclusi.
- Modalità notte con fasce configurabili, preset 21:00–07:00 tutti i giorni. Blocca anche connessioni esistenti, come le pause.
- Modalità compiti con fasce configurabili, preset 16:00–18:00 lunedì–venerdì: DNS limitato ai domini scolastici scelti. Conserva i filtri ordinari; le eccezioni ordinarie non ampliano la lista scolastica. Richiede tutti i domini necessari per login e risorse della scuola. Non blocca IP già risolti, connessioni aperte o VPN sconosciute; non è un controllo completo delle applicazioni.
- Bonus immediato 15–240 minuti, revocabile, con scadenza persistente. Supera solo fasce di accesso e notte: non supera pause manuali, resolver fermo, modalità compiti o filtri DNS. Non è una quota giornaliera e non misura lo schermo. Cambiare un profilo invalida i bonus relativi alla precedente configurazione.
- Aggiornamento automatico delle categorie in uso, facoltativo e disattivato nei vecchi backup. Controllo ogni ora, rinnovo dopo 24 ore; download HTTPS dagli stessi percorsi prestabiliti, validazione integrale, test dnsmasq prima della sostituzione, precedente copia privata e ripristino in caso di errore. Attiva i resolver senza riapplicare rete/VPN. Elenchi oltre 48 ore segnalati come obsoleti. Aggiornamenti manuali richiedono ancora Verifica e applica. Feed non firmati dal produttore.
- Blocco IPv6 opzionale su TUTTA la LAN del profilo, anche dispositivi non assegnati e accesso IPv6 al firewall. Serve a escludere il transito IPv6 attraverso Murus: non è parental IPv6 per dispositivo. Non copre router alternativi o traffico diretto tra host della stessa LAN.
- Riepilogo traffico per figlio/profilo e selettore dedicato, mantenendo dettaglio per IPv4 e raccolta locale facoltativa di 7 giorni. Nessun invio dei report al cloud.

## Installazione e uso

Avviare la ISO e aprire la gestione HTTPS sulla porta 8443 dell'interfaccia di management. GUI admin/igneus, console live root/igneus; la password del sistema installato da DEB non viene cambiata. L'installer web è disponibile nella gestione. Un backup FortiGate è facoltativo: si può configurare da zero.

Nella pagina Parental control creare una scheda per ogni figlio, assegnare IPv4 stabili, scegliere filtri e nuove funzioni, salvare la bozza e usare Verifica e applica con conferma entro 90 secondi. Nessun figlio/dispositivo viene aggiunto automaticamente. Il blocco IPv6 interessa l'intera LAN: leggere l'etichetta prima di selezionarlo. Bonus e pause operano sui profili già applicati.

Restano i limiti generali di un filtro al gateway: DNS cifrati/VPN sconosciuti, IP diretti, rete mobile e percorsi esterni possono aggirarlo. SafeSearch dipende dai provider e dagli host coperti, non garantisce l'assenza di contenuti inappropriati. Backup delle versioni precedenti compatibili con nuove opzioni disattivate. Vedere PARENTAL.md per dati e limiti del reporting.

## Verifica

I risultati di CI e della ISO originale saranno registrati in docs/ISO-ALPHA9-QA.md prima della pubblicazione. Le prove automatiche non certificano efficacia commerciale, hardware fisico o installazione su disco.
