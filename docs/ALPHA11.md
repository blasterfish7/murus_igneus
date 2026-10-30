# Murus Igneus 0.3.0-alpha.11

Nuova dashboard dinamica con CPU, memoria, uptime, traffico e schede delle porte; pagina Sistema → Aggiornamenti con verifica Ed25519, backup applicazione/configurazione, installazione indipendente dal server web, rollback e recupero delle operazioni interrotte.

## Installazione nuova

Avviare la ISO amd64 in UEFI. Collegarsi da un altro PC a `https://IP-GESTIONE:8443`. La porta di gestione normalmente è eth0 ed è dedicata: usare un'altra scheda per la WAN. Utente web iniziale `admin`, console `root`, password iniziale `igneus`. Il primo accesso richiede una nuova password di almeno 8 caratteri, condivisa tra console e web. L'importazione di un backup FortiGate è facoltativa. L'installer su disco cancella il disco selezionato dopo conferma esplicita.

## Passaggio dalla alpha.10 installata

La alpha.10 non dispone della nuova pagina Aggiornamenti. Eseguire prima un backup esterno della configurazione e, se in VM, uno snapshot. Trasferire il DEB della release sul firewall e verificarne SHA256 confrontandolo con il manifest della release GitHub attendibile. Dalla console root, nella directory del pacchetto:

```sh
rc-service murus-igneus stop
dpkg --force-confold --force-confdef -i ./murus-igneus_0.3.0-alpha.11_all.deb
rc-service murus-igneus start
```

Il nome scaricato usa `-alpha.11`; la versione Debian interna è `0.3.0~alpha.11`. Password e configurazione locali vengono conservate. Il traffico e il web possono interrompersi durante il riavvio. Questo bootstrap manuale non utilizza il rollback automatico del nuovo aggiornamento web. In alternativa si può installare da ISO su un nuovo disco/VM e ripristinare una configurazione compatibile verificandola prima di applicarla.

## Aggiornamenti successivi

Questa release non include una chiave privata di produzione né una nuova radice di fiducia automatica. ISO e DEB sono distribuiti con checksum e provenienza; non costituiscono da soli un bundle Ed25519 firmato. Prima di installare futuri aggiornamenti dal web, predisporre una chiave pubblica attendibile e i tre file del bundle firmato come descritto in [UPDATES.md](UPDATES.md). Un repository privato può rendere indisponibile il catalogo senza autenticazione; resta il caricamento offline.

Il meccanismo aggiorna solo l'applicazione su Devuan 6 installato, non il sistema operativo/kernel. Gli aggiornamenti applicativi sono disabilitati nella live. Il rollback ripristina anche la configurazione salvata. Non è un sistema A/B e il recupero da interruzioni elettriche non è garantito.

## Collaudo e limiti

La pubblicazione è subordinata alla suite Python, Chromium, prove di traffico reali e 73 controlli della ISO originale: avvio UEFI, installazione, avvio autonomo dal disco e sei prove reali di firma, upgrade DEB/OpenRC, rollback e recupero. Il manifest candidate-validation.json associa asset, digest, commit e run CI. Il report ISO pubblicato documenta il risultato effettivo.

Resta una prerelease sperimentale: niente certificazione su hardware fisico, BIOS o Secure Boot. Nessuna ispezione antivirus del contenuto HTTPS e nessun HA. Nessun codice o firmware Fortinet riutilizzato.
