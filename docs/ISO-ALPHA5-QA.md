# Collaudo alpha.5

Build e test del commit `722fc4d5aa638d651705f39a7f11b935ca6c261b`:
https://github.com/blasterfish7/murus_igneus/actions/runs/39649427949

## Verifiche completate

- 138 test Python in CI, tutti superati senza skip, compresi i test SNMP reali.
- Controlli statici Python, sintassi shell e JavaScript, regressioni UI Node.
- 8 controlli Chromium 153.0.8010.0: configurazione VLAN/DHCP/DNS/DNAT, provider OpenAI senza lettura della chiave, storico amministrativo, enrollment TOTP/sessione sicura/nuova autenticazione/rifiuto replay. Backend reale; applicazione di rete disabilitata nella fixture GUI.
- 11 prove native con pacchetti reali: VLAN, DHCP DORA, DNS, DNAT e restrizioni, conntrack, ripristino manuale, timer reale di 90 secondi e persistenza della configurazione.
- 9 prove enterprise con charon/swanctl e nftables reali: configurazione IKEv2, handshake, transito cifrato LAN-to-LAN, rifiuto plaintext con sorgente remota, nessun fallback plaintext dopo stop; scelta WAN primaria dopo tre successi, passaggio alla riserva, default unreachable senza linee sane, ritorno alla primaria e rimozione delle risorse gestite.
- Tutti i 24 file dell’applicazione nel DEB CI confrontati byte per byte con i sorgenti; comando murus-update installato eseguibile.

## ISO originale

ISO `murus-igneus-0.3.0-alpha.5-devuan-amd64.iso`, SHA-256 `d67e09e1917b8c489ed9537de62f94df4f49be331760ce9dce33400c302cdbb9`.

23 verifiche superate: avvio UEFI, backend HTTPS reale, le 11 prove native e le 9 prove IKEv2/WAN eseguite dai moduli installati nella ISO in namespace isolati, quindi spegnimento regolare. QEMU TCG, 2 CPU, 2048 MiB RAM e tre NIC Virtio; nessun disco di installazione, BIOS o Secure Boot.

Firme ufficiali ClamAV scaricate correttamente durante questa build. Manifest dei pacchetti allegato alla release.

## Limiti delle prove

Non collaudati: installazione su disco della alpha.5 e successivo avvio senza ISO, BIOS/Secure Boot, hardware fisico, apparati FortiGate, switch in scrittura, qualità di risposte di modelli reali, servizio OpenAI live, installazione e rollback applicativi firmati completi, prestazioni/efficacia UTM e una matrice completa VPN/IPS/antivirus. La verifica Ed25519 su un DEB reale e il rifiuto di pacchetto/manifest manomessi sono coperti dalla suite Python; non equivalgono a un collaudo di aggiornamento dell’appliance.

I test IPsec provano due strongSwan; non attestano tutti i profili FortiGate. Il failover verifica nuove connessioni, non continuità di sessioni esistenti. Le firme ClamAV e le versioni effettivamente incluse sono registrate negli allegati di build. Solo componenti della sezione main, senza codice/firmware Fortinet. La disponibilità di motori IPS/AV non è una certificazione di efficacia equivalente a un NGFW commerciale.
