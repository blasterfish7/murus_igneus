# Parental control IPv4 — alpha.6

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

Fonte e licenza: https://github.com/hagezi/dns-blocklists — GPL-3.0. Il progetto distribuisce già la licenza GPL-3.0 in LICENSE. Le liste non sono incluse automaticamente nell’immagine: download volontario dall’interfaccia, massimo 16 MiB e 300.000 domini per lista, 600.000 domini complessivi per profilo. Il download controlla stato HTTP, formato, limiti e domini; una risposta HTML, vuota o con direttive viene rifiutata conservando la copia precedente. Sono registrati fonte, data e SHA256, non una firma crittografica del produttore. Non sono aggiornamenti automatici: dopo il download riapplicare la bozza per attivare i dati nuovi.

I domini dei social sono un elenco locale ristretto: Instagram, TikTok, Facebook/Messenger, YouTube, Snapchat, Discord e Twitch. Le liste possono avere falsi positivi, omissioni e domini condivisi fra servizi. In particolare YouTube usa googlevideo.com: il blocco può coinvolgere servizi correlati.

## Limiti e dati

Cache DNS/applicative e connessioni già aperte possono prolungare l’accesso a un dominio appena bloccato finché il dispositivo non rinnova la risoluzione o la connessione; Pausa ora blocca invece il transito del profilo anche sulle connessioni esistenti. VPN/proxy esterni, DoH su HTTPS non riconosciuto, indirizzi IP diretti, DNS su porte non standard, cambi di IP fuori dal profilo, percorsi alternativi, rete mobile e traffico non instradato da Murus possono aggirare il controllo. Non sono implementati quote giornaliere di tempo, ispezione HTTPS, identificazione completa dell’app Instagram, protezione fuori casa o parental IPv6. Il firewall nativo resta IPv4.

Nessuna cronologia delle query DNS è registrata da questo modulo. Profili, indirizzi, prenotazioni e orari sono nel backup nativo; le liste e le pause sono nella directory privata /etc/murus_igneus. L’uso dell’assistente AI con la bozza può includere i profili: valgono provider, consenso e redazione già previsti dall’assistente. In avvio live senza installazione/persistenza, le modifiche si perdono al riavvio. Liste grandi e molti profili aumentano il consumo RAM: dimensionare e collaudare insieme a IPS e ClamAV.

## Verifica

Suite Python su validazione, IDNA, iniezioni, orari, mezzanotte, DST, feed e pause. GUI Chromium con compilatore reale. Laboratorio `tools/validate-parental-runtime.py` con veri dnsmasq, nftables, query DNS UDP/TCP, traffico TCP, proxy con scanner controllato, DHCP DORA, arresto resolver e rollback. Non è un test di efficacia commerciale su tutte le categorie o su tutte le applicazioni.
