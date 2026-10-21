# Collaudo alpha.5

Build e test del commit `55ec4ea84c58f0c036cd50ac9a7266a7c96fdd38`:
https://github.com/blasterfish7/murus_igneus/actions/runs/39651874250

## Verifiche completate

- 138 test Python in CI, tutti superati senza skip, compresi i test SNMP reali.
- Controlli statici Python, sintassi shell e JavaScript, regressioni UI Node.
- 8 controlli Chromium 153.0.8010.0: configurazione VLAN/DHCP/DNS/DNAT, provider OpenAI senza lettura della chiave, storico amministrativo, enrollment TOTP/sessione sicura/nuova autenticazione/rifiuto replay. Backend reale; applicazione di rete disabilitata nella fixture GUI.
- 11 prove native con pacchetti reali: VLAN, DHCP DORA, DNS, DNAT e restrizioni, conntrack, ripristino manuale, timer reale di 90 secondi e persistenza della configurazione.
- 9 prove enterprise con charon/swanctl e nftables reali: configurazione IKEv2, handshake, transito cifrato LAN-to-LAN, rifiuto plaintext con sorgente remota, nessun fallback plaintext dopo stop; scelta WAN primaria dopo tre successi, passaggio alla riserva, default unreachable senza linee sane, ritorno alla primaria e rimozione delle risorse gestite.
- Tutti i 24 file dell’applicazione nel DEB CI confrontati byte per byte con i sorgenti; comando murus-update installato eseguibile.

## ISO originale

ISO `murus-igneus-0.3.0-alpha.5-devuan-amd64.iso`, SHA-256 `7bbceee7a1bdde8e47b909c46c22e2effa1c9c5f1836dcf6f33239c8c659fc81`.

24 verifiche superate: avvio UEFI, backend HTTPS reale, applicazione IPsec al backend effettivo dell’appliance con avvio del daemon Murus e suo arresto tramite rollback, le 11 prove native e le 9 prove IKEv2/WAN eseguite dai moduli installati nella ISO in namespace isolati, quindi spegnimento regolare. QEMU TCG, 2 CPU, 2048 MiB RAM e tre NIC Virtio; nessun disco di installazione, BIOS o Secure Boot. Il servizio di distribuzione ipsec è disabilitato nella ISO per evitare conflitti con il daemon gestito da Murus.

Firme ufficiali ClamAV scaricate correttamente durante questa build. Manifest dei pacchetti allegato alla release.

## Limiti delle prove

Non collaudati: installazione su disco della alpha.5 e successivo avvio senza ISO, BIOS/Secure Boot, hardware fisico, apparati FortiGate, switch in scrittura, qualità di risposte di modelli reali, servizio OpenAI live, installazione e rollback applicativi firmati completi, prestazioni/efficacia UTM e una matrice completa VPN/IPS/antivirus. La verifica Ed25519 su un DEB reale e il rifiuto di pacchetto/manifest manomessi sono coperti dalla suite Python; non equivalgono a un collaudo di aggiornamento dell’appliance.

I test IPsec provano due strongSwan; non attestano tutti i profili FortiGate. Il failover verifica nuove connessioni, non continuità di sessioni esistenti. Le firme ClamAV e le versioni effettivamente incluse sono registrate negli allegati di build. Solo componenti della sezione main, senza codice/firmware Fortinet. La disponibilità di motori IPS/AV non è una certificazione di efficacia equivalente a un NGFW commerciale.
