# Alpha.7 — correzioni di autenticazione e rollback

Integra la PR #8 di Claude e completa i casi limite riprodotti nella revisione. Non modifica le credenziali iniziali di laboratorio: GUI admin/igneus, console ISO root/igneus; l'installazione del solo DEB conserva la password root del sistema.

## Autenticazione Basic

Massimo 10 credenziali errate per indirizzo in una finestra mobile di 60 secondi. Dopo la soglia le credenziali inviate ricevono HTTP 429 e Retry-After: 60; anche una password corretta deve attendere la scadenza. Una richiesta senza Authorization riceve la normale sfida 401 e non consuma tentativi. Credenziali malformate inviate vengono conteggiate. Un accesso corretto ammesso prima del blocco azzera i fallimenti dell'indirizzo. TOTP resta separato.

Controllo e registrazione sono atomici per impedire l'ammissione di tentativi simultanei oltre soglia. Memoria limitata a 1.024 indirizzi e 10 timestamp recenti per indirizzo; gli scaduti vengono rimossi durante le richieste. A tabella piena, nuovi indirizzi con credenziali ricevono 429 fino al recupero di spazio: il limite non viene aggirato saltando il conteggio. Client dietro lo stesso NAT condividono la soglia. Non è una protezione completa contro attacchi distribuiti o saturazione delle connessioni.

## Recupero delle modifiche

Il rollback prova prima a installare le regole di sicurezza; se fallisce non modifica interfacce e servizi. Altrimenti prova separatamente arresto dei servizi, operazioni inverse della rete e ripristino dei servizi precedenti. Le regole precedenti vengono riaperte solo dopo un recupero senza errori. Pulizia conntrack e ripristino forwarding vengono controllati; un errore comporta un ulteriore tentativo di installare il firewall di sicurezza.

Lo stato pendente viene liberato anche con eccezioni, compresi errori iniziali o del fallback. L'esito incompleto viene mostrato nello stato, nella risposta API con ok:false/error e nella GUI. Se anche nft non riesce a installare il fallback, il messaggio lo riporta: non viene dichiarata una protezione ripristinata. In caso di recupero incompleto controllare lo stato e risolvere la causa prima di ripristinare il servizio. Un timer vecchio non annulla una nuova transazione.

## Build e verifiche

La versione cambia in 0.3.0-alpha.7 per mantenere intatta la alpha.6 pubblicata. La copia di sicurezza dei build collaudati in una release privata in bozza funziona per i push di tutti i rami del repository, incluso quello di Claude, quando la quota artefatti Actions impedisce l'upload. Gli artefatti ISO temporanei hanno conservazione di 2 giorni; release pubblicate invariate.

La pipeline esegue suite Python/Chromium, prove reali di rete e VPN e 17 prove parental/reporting. Nuove prove: transito bloccato dopo un precedente ruleset realmente non valido per nft e limite credenziali attraverso HTTPS sull'appliance. Collaudo ISO atteso: 44 controlli UEFI/live; l'esito effettivo viene registrato separatamente dopo la build. Nessuna nuova certificazione hardware, installazione su disco o efficacia UTM.

Rimangono VPN, UTM, AI opzionale, parental control e reporting della alpha.6. Vedere ALPHA5.md e PARENTAL.md per configurazione e limiti.
