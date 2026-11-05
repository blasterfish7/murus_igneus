# Devuan 6 Excalibur / OpenRC

**Italiano** · [English](DEVUAN.md) · [Documentazione](INDEX.md)

Murus Igneus dispone di un pacchetto DEB per una VM Devuan 6 Excalibur amd64 dedicata e di una ISO live con installazione da web o console. Per l'uso della release consulta la [guida alpha.12](ALPHA12.md).

## Sorgenti e provenienza

Usa `excalibur`, `excalibur-updates` ed `excalibur-security` da `deb.devuan.org/merged`, solo componente `main`, come in [sources.list](../packaging/devuan/sources.list). Usa il pacchetto ufficiale `devuan-keyring` e la verifica APT. Non usare `trusted=yes`, installazioni non autenticate o repository Debian/Ubuntu mescolati.

Il builder costruisce una nuova root da pacchetti autenticati e rifiuta pacchetti non-free, contrib, firmware e microcode. Non rimasterizza la ISO live Devuan. Il pacchetto pubblico devuan-keyring è verificato e ricostruito dal builder quando manca nell'archivio, senza copiare altri pacchetti dalla seed. Il digest OCI della seed è fissato in CI. Versione, digest del pacchetto, immagine seed e hash delle chiavi sono in `bootstrap-provenance.json` e vengono verificati anche dopo l'avvio UEFI.

## Pacchetto DEB

Su una macchina con Python 3 e `dpkg-deb`:

```sh
sh packaging/devuan/build-deb.sh
```

Il file `dist/murus-igneus_*_all.deb` non richiede root né modifica il firewall della macchina di build. Installa il DEB su una VM dedicata con Devuan 6 e OpenRC; quando il servizio parte applica un firewall IPv4 a blocco predefinito e gestisce l'inoltro.

Dopo `sudo apt update`, installa il file specifico con `sudo apt install ./dist/NOME_PACCHETTO.deb`. Usa `ip -br address` per identificare la porta di gestione e imposta `MURUS_MANAGEMENT_INTERFACE` in `/etc/default/murus-igneus`. L'IPv4 esistente viene conservato; in sua assenza viene aggiunto `MURUS_MANAGEMENT_FALLBACK` (default `192.168.56.1/24`). Il pacchetto non riscrive le rotte di default e non avvia da solo il firewall. Con la console disponibile:

```sh
sudo rc-update add murus-igneus default
sudo rc-service murus-igneus start
sudo /usr/sbin/murus-info
```

Accedi a `https://IP-GESTIONE:8443`. Per le credenziali e l'obbligo di cambio al primo accesso consulta la [guida alpha.12](ALPHA12.md); l'installazione del solo pacchetto non cambia automaticamente la password root. Stato e certificati sono in `/etc/murus_igneus`; il log del servizio è `/var/log/murus-igneus.log`.

## ISO

Esegui solo in un ambiente Devuan isolato e privilegiato:

```sh
bash tools/build-devuan-iso.sh
```

Gli output in `dist/` includono ISO amd64, `SHA256SUMS`, elenco pacchetti e provenienza. GitHub Actions costruisce la ISO sui push. La build prova a scaricare le definizioni ClamAV ufficiali, con limite cinque minuti, e registra l'esito in `signature-status.txt`. `MURUS_FETCH_SIGNATURES=0` salta esplicitamente il download. Secure Boot non è previsto.

La ISO live è headless. Su Proxmox collega la porta di gestione al bridge raggiungibile dal PC. La console mostra l'URL IPv4 sulla porta HTTPS 8443; `murus-info` mostra gli indirizzi effettivi. La porta di gestione è normalmente `eth0`, con DHCP e fallback. Usa altre porte per WAN e LAN.

Da **Installa su disco** o `murus-install` seleziona un disco non montato di almeno 8 GiB e conferma con `CANCELLA /dev/DEVICE`, usando il nome esatto. `murus-install --list` elenca i dischi senza modificarli. Gli installer condividono un lock; l'installazione cancella il disco scelto, prepara GPT/EFI/ext4 e copia configurazione e stato. Spegni, scollega la ISO e avvia dal disco. Le modifiche della sola live non persistono.

## VPN, UTM e collaudo

WireGuard conserva la chiave privata sul firewall; configura chiavi pubbliche dei peer, CIDR remoti e policy. È disponibile anche IKEv2/PSK nativo, senza conversione automatica VPN da FortiGate. Suricata ispeziona il traffico IPv4 inoltrato con NFQUEUE senza bypass; le regole community conservano le azioni originarie. Il proxy HTTP ClamAV usa la porta 3128, ACL per client/destinazioni, richieste GET/HEAD fino a 20 MiB e serve il contenuto solo dopo scansione riuscita. Non supporta CONNECT o ispezione HTTPS. Aggiorna regole e firme da UTM e riapplica la configurazione.

`MURUS_LAB=YES python3 tools/validate-devuan-runtime.py` è riservato a una VM usa e getta con tre NIC e senza connessioni alla produzione. Modifica la configurazione del firewall per provare traffico reale, VPN, IPS e rollback; tenta anche aggiornamenti ClamAV e prove proxy/EICAR. Con `MURUS_SKIP_SIGNATURE_UPDATE=YES` la verifica antivirus è esclusa. I risultati non certificano hardware fisico o tutte le combinazioni di NIC. Vedi [stato e verifiche](../SOURCE_STATUS.md).
