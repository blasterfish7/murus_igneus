# Collaudo alpha.6 — parental control e reporting

Sorgente della build: `fe201577f6e3b4d8f39f2391935076c826dedcca`.
CI: https://github.com/blasterfish7/murus_igneus/actions/runs/40136817311

## Prove

- 167 test Python CI, senza skip, inclusi SNMP reali, precedenti regressioni e 12 nuovi casi reporting: delta, baseline/reset/cancellazione, query DNS e NXDOMAIN locali, scarti visibili, separazione identità/subnet, limiti di conservazione, permessi e CSV.
- 10 controlli Chromium 153.0.8010.0, incluso reporting con aggregati di fixture realmente conservati nel database: selezione dispositivo/periodo, CSV scaricato e cancellazione confermata. Backend reale, applicazione delle reti disabilitata nella fixture GUI.
- 11 prove native con pacchetti reali, inclusi DHCP/DNS/VLAN/DNAT, conferma e rollback manuale e timer effettivo di 90 secondi.
- 9 prove reali IKEv2/strongSwan e failover di due WAN statiche.
- 17 prove parental con dnsmasq/nftables e traffico reale: DNS UDP/TCP trasparente, domini/categorie/social ed eccezioni, dispositivo non assegnato, DoT, transito IPv4 con NAT, volumi upload/download e blocchi effettivi, query DNS e domini filtrati, cancellazione dello storico senza perdita del transito, proxy HTTP, pausa delle sessioni aperte, ripresa, fasce Europe/Rome, prenotazione DHCP DORA, resolver fermo, rollback e categoria mancante.
- Quattro feed HaGeZi scaricati realmente da HTTPS e validati per formato e limiti, non una certificazione della qualità delle categorie.

## Immagine originale

ISO: `murus-igneus-0.3.0-alpha.6-devuan-amd64.iso`.
SHA256: `eb48a856c22ec9eab7127e9e57ea0739bf25e8e6f7d0337a585e1bc9ac63663f`.
Dimensione: 475041792 byte.

42 controlli UEFI/live superati: avvio, backend HTTPS reale, configurazione iniziale senza backup, preview VLAN, applicazione/rollback IPsec e parental nel servizio effettivo dell'appliance, 11 prove native, 9 enterprise, 17 parental eseguite dai moduli installati nella ISO, spegnimento regolare. QEMU TCG, 2 CPU, 2048 MiB RAM, tre NIC Virtio. Non è una prova d'installazione su disco o hardware fisico.

L'immagine originale è preservata negli allegati di una bozza perché GitHub Actions segnala la quota artefatti esaurita anche dopo la cancellazione di 7,28 GB di copie temporanee. Gli upload sono facoltativi, i test obbligatori. Il publisher verifica SHA256, manifest, rapporto originale di 42 controlli e corrispondenza dei 27 file applicativi del DEB con i sorgenti testati; non ricompila.

## Limiti

Il reporting raccoglie byte IPv4 inoltrati (anche reti locali/VPN, proxy locale escluso), pacchetti dei blocchi parental e aggregati DNS locali. Non attribuisce byte ai domini, visite o tempo alle app. Subnet aggregate; DoH/VPN, cache, rete mobile e traffico fuori dal gateway possono lasciare lacune. Campionamento 10 secondi, fasce orarie UTC, perdita possibile dell'ultimo intervallo; non dati di fatturazione. Reporting disattivato di default, conservazione fino a 7 giorni/50.000 righe/database 32 MiB. Vedere [PARENTAL](PARENTAL.md).

Non ricollaudati: installazione su disco alpha.6 e avvio autonomo, BIOS/Secure Boot, hardware fisico, apparati FortiGate, scrittura switch, modelli AI reali/OpenAI live, aggiornamento applicativo completo con rollback e matrice completa VPN/IPS/AV. Il laboratorio proxy parental usa uno scanner controllato; non è una certificazione ClamAV. Nessuna ispezione HTTPS, HA o riconoscimento completo delle applicazioni. Restano i limiti documentati delle funzioni alpha.5. Nessun codice o firmware Fortinet riutilizzato.
