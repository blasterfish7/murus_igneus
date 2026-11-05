# Murus Igneus 0.3.0-alpha.12

**Italiano** · [English](ALPHA12.en.md) · [Documentazione](INDEX.md)

Nuove funzioni: accesso SSH amministrativo facoltativo e fasce social indipendenti dai filtri permanenti.

- **Nuova installazione:** avviare la ISO Devuan amd64 in UEFI. Accedere a `https://IP-DI-GESTIONE:8443` e seguire la procedura di installazione. La guida [alpha.11](https://github.com/blasterfish7/murus_igneus/blob/v0.3.0-alpha.11/docs/ALPHA11.md) descrive il primo accesso e l'installazione; l'installazione su disco cancella il disco selezionato dopo conferma esplicita.
- **Upgrade da alpha.11:** salvare la configurazione e fare uno snapshot se si usa una VM. Scaricare il DEB, verificare il suo SHA256 confrontandolo con `SHA256SUMS` della release attendibile e copiarlo sul firewall. Dalla console root:
  ```sh
  rc-service murus-igneus stop
  dpkg --force-confold --force-confdef -i ./murus-igneus_0.3.0-alpha.12_all.deb
  rc-service murus-igneus start
  ```
  La versione Debian interna è `0.3.0~alpha.12`. Il riavvio interrompe brevemente web e inoltro del traffico. La procedura manuale non attiva il rollback del sistema di aggiornamento firmato.
- **SSH:** OpenSSH è incluso nella nuova ISO. Su una precedente installazione senza OpenSSH, installare `openssh-server` dalla console, fermare l'eventuale servizio di sistema (`service ssh stop`) e disabilitarlo (`update-rc.d ssh disable`). In **Amministrazione → Accesso SSH** abilitare il servizio Murus, indicare le sorgenti IPv4 autorizzate e incollare le chiavi pubbliche Ed25519. Verificare e applicare la bozza, provare la connessione e confermare entro 90 secondi. SSH è spento di default e non si attiva nella live.
- **Famiglia:** nel profilo scegliere i servizi da bloccare solo a orario. Il preset imposta WhatsApp e Instagram lun–ven 15:00–19:00, secondo il fuso del profilo. La categoria adulti deve essere selezionata e la lista scaricata; poi resta attiva anche fuori fascia. Il blocco riguarda il DNS e non interrompe necessariamente sessioni aperte o indirizzi già in cache.

Il DEB e i checksum non costituiscono un bundle di aggiornamento firmato. Per la firma e il caricamento dalla pagina web, vedere la guida UPDATES.md allegata alla release. La prerelease non aggiorna Devuan o il kernel.
