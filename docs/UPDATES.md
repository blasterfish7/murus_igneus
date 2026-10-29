# Aggiornamenti applicativi firmati

La pagina **Sistema → Aggiornamenti** gestisce l’applicazione Murus Igneus su Devuan 6 Excalibur installato su disco. Non aggiorna Devuan, kernel, bootloader o firmware. In modalità live l’installazione degli aggiornamenti è disabilitata.

## Release e canali

Il controllo è esplicito, sul catalogo GitHub del progetto. Il canale stabile esclude le prerelease; quello sperimentale include alpha/beta. Le note vengono mostrate come testo. Il catalogo non è un’autorizzazione a installare e non attiva download/installazioni automatiche.

Un repository privato può rispondere 404/403: la pagina lo segnala e permette il caricamento offline. Non salva token GitHub sul firewall. Le release alpha.10 esistenti non diventano bundle firmati per il solo fatto di avere SHA256SUMS.

## Firma e bootstrap della fiducia

L’amministratore installa dalla console una chiave pubblica Ed25519 attendibile in `/etc/murus_igneus/update.pub`, proprietario root e senza permessi di scrittura per gruppo/altri. La firma va controllata attraverso un canale indipendente. Non accettare una nuova chiave pubblica soltanto perché inclusa nel download da verificare.

La chiave privata resta sulla macchina del firmatario e non va caricata sul firewall né nel repository. Nessuna chiave privata di produzione viene creata o inclusa dalla procedura CI. Un manutentore che dispone già della propria chiave può preparare il bundle:

```sh
python3 tools/sign-update-bundle.py murus-igneus_VERSION_all.deb --key /percorso/privato/firma.pem --output bundle-VERSION
```

Il risultato contiene solo `manifest.json`, `manifest.sig` (firma binaria di 64 byte) e `murus-igneus.deb`. Il manifest firmato riporta schema, nome del pacchetto, versione DEB e SHA256. Il verificatore controlla anche nome/versione/architettura interni al DEB. Non sono accettati checksum senza firma, chiavi scrivibili da altri o pacchetti di versione uguale/precedente.

La prima versione che introduce la pagina richiede un bootstrap manuale tramite ISO/DEB attendibile. Non è possibile aggiornare da una pagina che non esiste nelle versioni precedenti. La chiave scelta deve essere disponibile anche per firmare le release successive; finché non viene predisposta la firma delle release non esiste un aggiornamento online installabile.

## Installazione dal web

1. Caricare i tre file (DEB massimo 4 MiB; manifest massimo 4096 byte).
2. Verificare versione, firma, digest e metadati.
3. Riscrivere la conferma `AGGIORNA VERSIONE`.
4. Attendere backup, installazione e ritorno del servizio HTTPS. Il traffico viene interrotto durante il riavvio.

La verifica dura 30 minuti ed è sostituita da un successivo caricamento. Si installa la configurazione confermata, non la bozza del browser. Modifiche pendenti, altri lavori di manutenzione e operazioni switch/parental impediscono l’avvio. Durante aggiornamento/recupero sono bloccate le altre scritture API e il rinnovo automatico delle liste parental.

Il worker è un processo indipendente, con lock ereditato, e sopravvive al riavvio del server web. Il registro in `/var/lib/murus-igneus/updates/status.json` viene scritto atomicamente con fsync. Prima di modificare il pacchetto il servizio viene fermato e vengono salvati:

- Il pacchetto precedente tramite dpkg-repack, con digest locale.
- `/etc/murus_igneus`, compresi configurazione confermata, credenziali applicative e chiavi.
- `/etc/default/murus-igneus` e `/etc/sysctl.d/90-murus-igneus.conf`.

Gli snapshot sono locali, riservati a root, e possono contenere segreti. Non vengono inviati a GitHub. Servono almeno 256 MiB liberi; la configurazione da salvare è limitata a 128 MiB/4096 elementi. Collegamenti simbolici e file speciali nella configurazione sono rifiutati. I conffile locali vengono conservati senza domande interattive di dpkg. Non vengono installate automaticamente dipendenze di sistema nuove: un errore di dipendenze deve far fallire l’upgrade.

La nuova versione deve riavviare HTTPS e confermare localmente che l’avvio della configurazione salvata è riuscito; si controlla anche la versione DEB installata. Un errore gestito dal worker attiva il ripristino di pacchetto e configurazione. Se il ripristino fallisce, il registro lo dichiara e blocca ulteriori modifiche.

## Ripristino e interruzioni

Il ripristino volontario recupera anche la configurazione del backup: le modifiche confermate dopo quel backup vanno perse. Richiede la conferma `RIPRISTINA VERSIONE`.

Se il processo viene interrotto, il registro viene rilevato come **Recupero necessario**. La pagina permette `RECUPERA SERVIZIO`: prima della prima scrittura DEB riavvia il servizio; dopo una scrittura del pacchetto ripristina lo snapshot preciso di quell’operazione. Se il web non riparte, usare la console:

```sh
murus-update status
murus-update recover
```

Restano disponibili `murus-update verify DIRECTORY`, `murus-update install DIRECTORY` e `murus-update rollback`. Anche l’installazione da console lavora su una copia privata verificata, per impedire che il bundle originale cambi tra verifica e installazione.

Il registro e gli snapshot non costituiscono un sistema operativo A/B. Non è garantito il ripristino automatico dopo un’interruzione elettrica, un filesystem corrotto o un guasto del disco; può essere necessario avviare dalla ISO e intervenire dalla console. Il normale aggiornamento preserva la password console: `/etc/shadow` non fa parte del backup applicativo e non viene sovrascritto dal ripristino della configurazione.

## Collaudo

I test locali usano OpenSSL Ed25519 e DEB reali per firma/caricamento, HTTP per autenticazione/CSRF e comandi di sistema controllati per iniettare errori di installazione/riavvio. Il passaggio del lock a un processo indipendente è verificato realmente. I controlli Chromium usano risposte controllate e non installano pacchetti sul sistema ospite.

`tools/validate-updates-runtime.py` è riservato alla VM Devuan usa e getta installata dal collaudo ISO. Esegue caricamento HTTPS e installazione di DEB reali, ripristino web, fallimento reale di postinst e recupero da console. La prova è integrata dopo l’avvio autonomo dal disco, con ISO scollegata. Non eseguirla su un firewall in uso: cambia realmente i pacchetti, riavvia il servizio e usa una chiave di test temporanea.

Le firme ClamAV e le regole Suricata restano nella pagina UTM; APT Devuan resta un’operazione separata.
