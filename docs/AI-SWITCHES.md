# Assistente AI e switch locali — alpha.2

## Assistente locale

Aprire **Assistente AI** nella GUI (`https://IP-gestione:8443`). Il backend
supporta Ollama con i modelli locali Qwen3 0.6b, 1.7b, 4b e 8b. I pesi Qwen3
ufficiali sono Apache-2.0; Ollama è MIT. Il runtime e i pesi **non sono inclusi**
nel pacchetto/ISO, non vengono scaricati automaticamente e non sono richiesti
per usare firewall, VPN, UTM o switch.

Sul server AI installare Ollama da una distribuzione ufficiale verificata e
scaricare, per esempio, `ollama pull qwen3:4b`. Per una prova più leggera è
disponibile `qwen3:0.6b`; qualità e precisione sono inferiori. Pianificare RAM,
CPU e spazio per il modello, oltre alle risorse riservate a IPS e antivirus.
Un server della LAN separato evita la competizione con il traffico del firewall.

Eseguire il runtime con `OLLAMA_NO_CLOUD=1`. Se deve essere raggiunto dalla LAN,
associare `OLLAMA_HOST` all'IP privato del server e alla porta 11434 e consentire
l'accesso soltanto dall'IP del firewall. L'API HTTP locale non fornisce da sola
autenticazione o cifratura: usare una rete di gestione fidata. Nessun modello
cloud è selezionabile nella GUI.

Nella pagina AI:

1. Impostare `http://IP-privato:11434` (o `http://127.0.0.1:11434` per un
   runtime installato sul firewall), scegliere il modello e salvare.
2. Premere **Verifica modello**, poi abilitare l'assistente e salvare.
3. Fare una domanda. Vengono inviati domanda, bozza nativa, esiti della sua
   validazione e telemetria degli switch; i log delle policy sono facoltativi.
   Non vengono letti o inviati i file delle password o la chiave privata VPN.
4. Per richiedere una bozza completa selezionare **Consenti una proposta di configurazione**.
   Una configurazione proposta deve superare il validatore Murus. Il pulsante
   di caricamento modifica soltanto la bozza. Controllarla in **Verifica e
   applica**, applicarla e confermarla entro il tempo previsto.

L'AI non esegue shell, non applica policy, non gestisce direttamente gli switch
e non sostituisce IPS/antivirus. Risposte e proposte possono essere errate.
Non esiste una chat persistente: ogni domanda ha il proprio contesto; nessuna
cronologia viene scritta su disco da Murus. L'eventuale registrazione sul server
Ollama dipende dalla sua configurazione. Nomi di dispositivi, descrizioni e log
sono trattati come dati non attendibili. Un solo lavoro AI per volta; timeout
di generazione 120 secondi. Se manca il runtime compare un errore esplicito.

## Switch tramite standard aperti

Aprire **Switch locali** e aggiungere l'IPv4 privato dello switch, la porta UDP
(161 predefinita) e le credenziali già configurate sul dispositivo:

- SNMPv3 `authPriv`, autenticazione SHA (SHA-1 Net-SNMP) e cifratura AES;
- oppure SNMPv2c con community (trasmessa senza cifratura).

Le credenziali sono salvate in `/etc/murus_igneus/switches.json`, permessi 0600,
e non ritornano nelle API, nell'AI o negli argomenti dei processi. Per questa
prima versione usare password senza spazi: caratteri ammessi
`A–Z a–z 0–9 _ . @ ! % + = : ? , -`, massimo 64 caratteri, minimo 8 per SNMPv3.
Durante una modifica lasciare le password vuote per conservarle. Massimo 32
dispositivi, aggiunta manuale; non è presente scansione automatica della LAN.

**Leggi stato** acquisisce nome/descrizione, porte IF-MIB, stato amministrativo
e operativo, velocità nominale e contatori cumulativi a 32 bit. I contatori
possono riavvolgersi; non rappresentano throughput istantaneo. I vicini LLDP
compaiono se lo switch espone la relativa MIB. Gli indici LLDP locali possono
differire dagli indici IF-MIB. Le letture sono manuali, con data visibile;
letture fallite invalidano il precedente risultato. Viste SNMP limitate possono
nascondere alcune tabelle. Non è un controller FortiLink.

Per comandare una porta:

1. Leggere gli indici IF-MIB e inserire quelli di gestione, uplink e aggregazioni
   nell'elenco **porte protette**. Tali porte non possono essere modificate.
2. Abilitare esplicitamente la scrittura per quel dispositivo; sullo switch
   serve un utente/community autorizzato a scrivere `ifAdminStatus`.
3. Premere Abilita/Disabilita su una porta Ethernet: l'anteprima rilegge lo
   switch e genera un token monouso valido 120 secondi.
4. Digitare la frase mostrata e confermare. Vengono ricontrollati identità
   dichiarata dello switch, stato precedente e configurazione di gestione;
   viene inviato un solo SET su `ifAdminStatus` e verificato lo stato finale.

**Non c'è rollback automatico dei comandi switch.** Una porta errata può tagliare
il collegamento: proteggere gli uplink e usare prima un apparato di laboratorio.
In caso di timeout dopo il SET l'esito può essere incerto: verificare prima di
riprovare. Il salvataggio permanente della modifica dipende dal costruttore.
Non vengono eseguiti comandi di salvataggio proprietari.

Questa versione non configura VLAN, trunk, LAG, PoE, STP, firmware o provisioning
e non adotta apparati FortiLink. Un FortiSwitch può essere monitorato solo se
raggiungibile e autorizzato tramite SNMP; il suo controller può sovrascrivere
eventuali modifiche. La compatibilità con apparati fisici resta da verificare.

Le impostazioni AI e switch sono separate dalla bozza firewall e non incluse
nella sua esportazione JSON. L'installer le copia insieme alla directory di
stato; durante una sessione live non installata si perdono al riavvio. Modificando
un pacchetto già installato le impostazioni esistenti vengono conservate.

## Provenienza

Codice Murus originale; nessun codice, firmware o risorsa grafica Fortinet.
Client SNMP: Net-SNMP dal componente Devuan `main`. Riferimenti ufficiali:

- <https://github.com/ollama/ollama/blob/main/LICENSE>
- <https://github.com/ollama/ollama/blob/main/docs/api.md>
- <https://huggingface.co/Qwen/Qwen3-4B>
- <https://www.net-snmp.org/docs/man/snmpcmd.html>
- <https://www.net-snmp.org/docs/man/snmp.conf.html>
