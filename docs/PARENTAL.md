# Parental control IPv4

**Italiano** · [English](PARENTAL.en.md) · [Documentazione](INDEX.md)

Il parental control filtra i domini e limita gli orari dei dispositivi il cui traffico passa da Murus. Non legge il contenuto HTTPS e non è un controllo completo delle applicazioni. Usare Murus come gateway dei dispositivi; una VM separata che non riceve il loro traffico non basta.

## Configurazione

1. Configurare e confermare LAN, WAN, routing e policy Internet normali.
2. Per identificare un dispositivo, creare un pool DHCP e una Prenotazione DHCP con MAC stabile, IPv4 e nome. Rinnovare il lease sul dispositivo. La MAC privata del Wi-Fi deve restare stabile su quella rete. Per evitare l’aggiramento cambiando IP, usare una VLAN/SSID dedicata ai figli e proteggere l’intera subnet.
3. Aprire Parental control. Scaricare le liste delle categorie desiderate, poi creare un profilo sulla LAN corretta e indicare IPv4 o subnet. Massimo 8 profili, 64 indirizzi/subnet per profilo. Nessun dispositivo è inserito automaticamente.
4. Selezionare categorie e social da bloccare, aggiungere domini personalizzati ed eccezioni. Un dominio comprende i suoi sottodomini. Le eccezioni prevalgono sui blocchi dei domini, non su pause/orari. Con DNS forzato attivo, un’eccezione non può riabilitare i resolver cifrati noti inclusi nel filtro.
5. Impostare eventualmente le fasce consentite e il fuso Europe/Rome. Senza fasce l’accesso non ha limiti orari. Le fasce possono attraversare mezzanotte e rispettano il cambio dell’ora; controllare che l’orologio del firewall sia corretto. Il controllo rivaluta lo stato ogni 2 secondi.
6. Salvare nella bozza, usare Verifica e applica e confermare entro 90 secondi. Una lista selezionata ma non ancora scaricata impedisce l’applicazione; non viene dichiarata una protezione di categoria senza dati.
7. Nella sezione Stato attivo, Pausa ora blocca temporaneamente il profilo per 15 minuti–24 ore senza riavviare rete/VPN/UTM. Riprendi rimuove soltanto la pausa temporanea. Le pause hanno scadenza persistente e non vengono trasferite a un nuovo gruppo di dispositivi che riusa lo stesso ID.

Le fasce e le pause agiscono prima delle policy, del consenso DNAT/IPsec e del consenso per connessioni già stabilite. Il traffico diretto agli indirizzi protetti è bloccato anche in risposta, e viene bloccata la connessione al proxy HTTP locale. DHCP e DNS restano disponibili. Il proxy HTTP antivirus verifica anche i blocchi di dominio del profilo, per evitare di aggirare il parental attraverso il firewall stesso.

## DNS e liste

Ogni profilo usa un’istanza dnsmasq locale su una porta dedicata. Con DNS forzato attivo, le richieste TCP/UDP 53 dei dispositivi vengono reindirizzate al resolver del profilo; le porte DNS cifrate standard 853/784/8853 vengono bloccate. Se DNS forzato è spento, si filtra soltanto il DNS indirizzato al firewall: i DNS esterni possono aggirare il filtro. Il blocco QUIC UDP 443 è facoltativo e può interrompere alcune applicazioni; non impedisce tutto il DoH.

Categorie HaGeZi scaricabili da host e percorsi HTTPS prestabiliti:

- adult: `wildcard/nsfw-onlydomains.txt`;
- gambling: `wildcard/gambling.mini-onlydomains.txt`;
- malware/phishing: `wildcard/tif.mini-onlydomains.txt`;
- resolver e aggiramento noti: `wildcard/doh-vpn-proxy-bypass-onlydomains.txt`.

Fonte e licenza: https://github.com/hagezi/dns-blocklists — GPL-3.0. Il progetto distribuisce già la licenza GPL-3.0 in LICENSE. Le liste non sono incluse automaticamente nell’immagine: download volontario dall’interfaccia, massimo 16 MiB e 300.000 domini per lista, 600.000 domini complessivi per profilo. Il download controlla stato HTTP, formato, limiti e domini; una risposta HTML, vuota o con direttive viene rifiutata conservando la copia precedente. Sono registrati fonte, data e SHA256, non una firma crittografica del produttore. Gli aggiornamenti manuali richiedono Verifica e applica. Dalla alpha.9 è disponibile anche un aggiornamento automatico facoltativo con attivazione dei resolver, descritto sotto.

I domini dei social sono un elenco locale ristretto: Instagram, TikTok, Facebook/Messenger, YouTube, Snapchat, WhatsApp, Discord e Twitch. Le liste possono avere falsi positivi, omissioni e domini condivisi fra servizi. In particolare YouTube usa googlevideo.com: il blocco può coinvolgere servizi correlati.

## Limiti e dati

Cache DNS/applicative e connessioni già aperte possono prolungare l’accesso a un dominio appena bloccato finché il dispositivo non rinnova la risoluzione o la connessione; Pausa ora blocca invece il transito del profilo anche sulle connessioni esistenti. VPN/proxy esterni, DoH su HTTPS non riconosciuto, indirizzi IP diretti, DNS su porte non standard, cambi di IP fuori dal profilo, percorsi alternativi, rete mobile e traffico non instradato da Murus possono aggirare il controllo. Non sono implementati quote giornaliere di tempo, ispezione HTTPS, identificazione completa dell’app Instagram, protezione fuori casa o parental IPv6. Il firewall nativo resta IPv4.

Per impostazione predefinita non si registrano query DNS. Abilitando il reporting si conservano aggregati locali, come descritto sotto. Profili, indirizzi, prenotazioni e orari sono nel backup nativo; le liste e le pause sono nella directory privata /etc/murus_igneus. L’uso dell’assistente AI con la bozza può includere i profili: valgono provider, consenso e redazione già previsti dall’assistente. In avvio live senza installazione/persistenza, le modifiche si perdono al riavvio. Liste grandi e molti profili aumentano il consumo RAM: dimensionare e collaudare insieme a IPS e ClamAV.

## Verifica

Suite Python su validazione, IDNA, iniezioni, orari, mezzanotte, DST, feed e pause. GUI Chromium con compilatore reale. Laboratorio `tools/validate-parental-runtime.py` con veri dnsmasq, nftables, query DNS UDP/TCP, traffico TCP, proxy con scanner controllato, DHCP DORA, arresto resolver e rollback. Non è un test di efficacia commerciale su tutte le categorie o su tutte le applicazioni.


## Reporting locale (alpha.6)

Dalla pagina Parental control attivare **Abilita reporting locale**, salvare la bozza e applicarla. È disabilitato per impostazione predefinita e rimane facoltativo con i vecchi backup. Dopo circa 10 secondi premere Aggiorna report. Sono disponibili 24 ore o 7 giorni, selezione IPv4/subnet, upload/download, andamento orario, pacchetti bloccati dal parental e primi 100 domini DNS globali nel periodo, con il numero di richieste e risposte NXDOMAIN del filtro locale. L'esportazione CSV comprende il periodo completo e tutti i profili, indipendentemente dal filtro di visualizzazione. La cancellazione richiede conferma ed elimina lo storico di tutti i profili; se la raccolta è attiva riprende con nuovi dati.

I contatori nftables misurano IPv4 inoltrato in entrambe le direzioni dopo le policy e il passaggio IPS: includono anche traffico tra reti o VPN e non costituiscono una misura della sola WAN. Il proxy HTTP locale è escluso dai byte. I pacchetti bloccati riguardano pausa/orari/resolver fermo, porte DNS forzate e QUIC se bloccato; non tutti i blocchi delle altre policy/IPS. I DNS filtrati sono una misura separata e non vanno sommati ai pacchetti bloccati come tentativi univoci.

Le richieste DNS non attestano una visita: includono processi in background, prefetch, record A/AAAA e ripetizioni. I byte non sono attribuiti a un dominio. Non si calcola tempo trascorso sui siti/app; non si registrano URL, contenuti HTTPS o titoli di pagine. Cache del dispositivo, IP diretti, DoH/VPN e rete mobile possono lasciare lacune. Un selettore /32 distingue un dispositivo; una subnet è una voce aggregata e non separa i suoi host. Usare prenotazioni DHCP per identificare stabilmente ciascun dispositivo. Cambiare indirizzi/interfaccia del profilo crea identità di report distinte.

Aggregati locali in `/etc/murus_igneus/logs/parental.sqlite`, permessi 0600 e directory 0700. Nessun log DNS grezzo su disco: stdout dnsmasq viene aggregato in memoria. Accesso con l'autenticazione amministrativa e TOTP se attivo; cancellazione/esportazione richiedono CSRF. Nessun invio all'assistente AI o a servizi cloud. Conservazione massima 7 giorni, pulizia oraria e alle letture/scritture, massimo 50.000 righe/32 MiB: a volumi elevati lo storico può accorciarsi. La pulizia oraria può lasciare i dati scaduti fino al successivo passaggio. I domini sono limitati a 100 in visualizzazione/CSV, non una cronologia completa. Gli errori del collector o scarti del buffer DNS sono segnalati nella pagina.

Campioni ogni 10 secondi, aggregazione per fasce UTC di un'ora (la GUI mostra l'ora locale del browser). I filtri di periodo comprendono la fascia iniziale parziale. Riavvii/applicazioni possono perdere l'ultimo intervallo; i report non sono dati di fatturazione. I contatori di base vengono riacquisiti per non duplicare i totali al riavvio o dopo una cancellazione. Disabilitare la raccolta conserva gli aggregati precedenti fino alla scadenza o cancellazione. In modalità live senza persistenza lo storico si perde al riavvio. Il database contiene domini e indirizzi: proteggere anche backup e accesso console.


## Gestione famiglia (alpha.9)

Ogni profilo può rappresentare un figlio e contenere più dispositivi della stessa LAN. Aggiungere un nome per ogni IPv4 singolo già presente tra i client, oppure scegliere una prenotazione DHCP. Le etichette non creano o modificano prenotazioni. Una subnet rimane aggregata; LAN diverse richiedono profili separati. Nel report sono presenti riepilogo per figlio/profilo e selettore dedicato, oltre al dettaglio per indirizzo. Non c'è riconoscimento della persona che sta usando un dispositivo. Restano massimo 8 profili e 64 client per profilo.

SafeSearch Google usa CNAME verso forcesafesearch.google.com con record locale IPv4 216.239.38.120 per www.google.com, www.google.it, www.google.co.uk, www.google.fr, www.google.de e www.google.es. Altri motori o domini Google non sono inclusi. YouTube usa restrict.youtube.com (rigoroso, 216.239.38.120) o restrictmoderate.youtube.com (moderato, 216.239.38.119) per www.youtube.com, m.youtube.com, youtubei.googleapis.com, youtube.googleapis.com e www.youtube-nocookie.com. AAAA e altri tipi per gli alias restano locali, evitando inoltri DNS non filtrati. I VIP sono espliciti nel codice: se il provider li cambia richiedono un aggiornamento del software. Si richiede DNS forzato. I blocchi di dominio/servizio hanno precedenza; il proxy HTTP locale rifiuta questi host quando la restrizione è attiva, perché risolve indipendentemente dal DNS del profilo. Nessuna intercettazione HTTPS o analisi del contenuto dei video.

Riferimenti ufficiali: https://support.google.com/websearch/answer/186669 e https://knowledge.workspace.google.com/admin/youtube/control-youtube-content-available-to-users. CNAME e host-record dnsmasq: https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html. Restricted Mode è un filtro del provider, non una garanzia né un servizio YouTube Kids.

Modalità notte: fasce di blocco indipendenti dalle fasce consentite. Il preset propone 21:00–07:00 ogni giorno e resta modificabile. Modalità compiti: nelle fasce scelte il resolver consente solo study_domains e relativi sottodomini, senza ampliare i filtri ordinari. Il preset propone 16:00–18:00 lunedì–venerdì. Occorre elencare anche login e risorse della piattaforma scolastica. Le eccezioni ordinarie non aprono altri domini durante i compiti. Il proxy HTTP rispetta questa lista. DNS in cache, connessioni aperte e IP diretti rimangono un limite: non viene promesso un isolamento completo ai soli siti scolastici. I cambi di modalità sono rivalutati ogni 2 secondi e riavviano i resolver dopo test della configurazione; se il passaggio fallisce, il transito del profilo viene bloccato fino al ripristino. Non si calcola il tempo di studio.

Bonus temporaneo: durata 0–240 minuti (zero revoca), dalla sezione Stato attivo. Supera solo notte e fasce consentite. Pausa configurata, pausa immediata e resolver non pronto continuano a bloccare. I filtri e la modalità compiti rimangono attivi. Scadenze in parental-bonuses.json, permessi 0600: sopravvivono al riavvio, senza quote o accumulo di tempo. Si legano alla configurazione completa del profilo; modificandola i precedenti bonus non si applicano più. Non si esportano con il backup nativo, come le pause immediate.

Aggiornamento automatico: abilitarlo nella bozza e applicare. Solo categorie usate da profili attivi, controllo ogni ora e download quando una copia ha almeno 24 ore. Un errore viene mostrato separatamente dagli errori di filtraggio, con un nuovo tentativo dopo un'ora. Le liste più vecchie di 48 ore sono segnalate. Tutti i download vengono validati prima dell'attivazione; test dei resolver, copia .previous.json privata e ripristino delle liste/configurazioni precedenti in caso di errore. Se anche il ripristino del resolver fallisce, il controllo dei processi mantiene il profilo bloccato. Una configurazione sostituita o una conferma/manutenzione pendente impediscono l'attivazione dei risultati in background. Rete, DHCP, VPN e contatori non vengono riapplicati; durante il riavvio dei resolver possono fallire brevemente richieste DNS. Fonte HTTPS e SHA256 non equivalgono a firma del produttore. Aggiornamenti manuali continuano a richiedere riapplicazione. Stato dell'ultimo successo in parental-auto-update.json, permessi 0600.

Blocco IPv6 opzionale: agisce sull'intera LAN, anche se un solo profilo lo seleziona. Blocca inoltro e traffico IPv6 locale in entrambi i sensi prima dei consensi ordinari. Influenza quindi anche dispositivi non assegnati, NDP e accesso IPv6 al firewall. Non abilita routing o parental IPv6 e non modifica switch/AP, router alternativi o scambi diretti sullo stesso segmento. Usare una LAN/VLAN dedicata. Quando è disattivato, la GUI dichiara esplicitamente che il parental non copre IPv6.

### Social solo in determinate fasce

Nei profili famiglia, **Servizi bloccati solo nelle fasce social** aggiunge un filtro DNS in giorni e orari scelti, senza sospendere tutto Internet. Il preset seleziona WhatsApp e Instagram dal lunedì al venerdì, 15:00–19:00 nel fuso del profilo (normalmente Europe/Rome). Si può cambiare l'elenco dei servizi o le fasce. Le categorie permanenti (ad esempio **Contenuti per adulti**) restano attive anche fuori fascia. Seleziona **Contenuti per adulti** e aggiorna la lista prima di applicare la bozza.

Il blocco richiede DNS forzato e riguarda le nuove risoluzioni DNS. Cache, connessioni già aperte, traffico cellulare, IP diretti e tunnel possono aggirarlo. Un servizio inserito anche nella lista permanente resta bloccato tutto il giorno; le eccezioni DNS esplicite si applicano anche durante la fascia social.
