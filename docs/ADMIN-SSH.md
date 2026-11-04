# Accesso SSH di amministrazione

OpenSSH è incluso nella ISO di sviluppo e disabilitato di default. SSH si abilita su Murus installato su disco. Nella pagina **Amministrazione → Accesso SSH**, indica uno o più indirizzi o reti IPv4 autorizzati (preferisci il singolo PC con /32) e le chiavi pubbliche Ed25519. Se non hai già una chiave, sul PC di amministrazione esegui:

```sh
ssh-keygen -t ed25519
```

Incolla solo la chiave pubblica (.pub). Salva nella bozza, verifica, applica e prova `ssh root@IP_DI_GESTIONE` prima di confermare la modifica entro 90 secondi. L'accesso root richiede la chiave privata corrispondente; password, autenticazione interattiva e forwarding SSH sono disabilitati. La porta TCP 22 è accessibile solo via interfaccia di gestione IPv4 e dalle sorgenti esplicite. La chiave host viene generata sull'installazione al primo avvio del servizio SSH.

Su un sistema aggiornato da una ISO precedente senza OpenSSH, serve installare `openssh-server` da console. Murus gestisce un proprio processo sshd; se l'installazione del pacchetto ha avviato il servizio di sistema, fermalo con `service ssh stop` e disabilitalo con `update-rc.d ssh disable` prima di applicare. La porta 22 dell'appliance rimane chiusa per impostazione predefinita. Mantieni la console locale disponibile per diagnosi e recupero.
