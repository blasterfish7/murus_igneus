# Rete nativa

**Italiano** · [English](NATIVE-NETWORKING.md) · [Documentazione](INDEX.md)

La configurazione nativa gestisce VLAN, DHCP/DNS, port forwarding e viste delle connessioni. L'importazione dei backup FortiGate rimane conservativa: queste funzioni non implicano la conversione automatica delle sezioni proprietarie.

## VLAN

Dichiara la porta fisica nelle interfacce dati, con o senza IPv4. Aggiungi un dispositivo univoco, ad esempio `eth2.20`, con `parent=eth2`, `vlan_id=20` e IPv4/prefisso. Non sono ammessi come genitori gestione, loopback, VPN o altre VLAN; non duplicare coppie porta/tag. Massimo 64 VLAN e 15 caratteri sicuri per nome. Murus controlla alias, tag e genitore prima di gestire un dispositivo: non adotta VLAN estranee dal solo nome. Cambi di tag e rollback rimuovono o ripristinano rotte e indirizzi nell'ordine necessario. La porta fisica non viene rimossa.

## DHCP, DNS e WAN DHCP

Un pool DHCP IPv4 per interfaccia dati statica, lease da 1 a 168 ore. Intervallo nella subnet, esclusi rete, broadcast e firewall. L'IPv4 dell'interfaccia viene annunciato come gateway. Imposta fino a quattro DNS espliciti o lascia vuoto se usi DNS locale su quella porta. Non attivare DHCP dove esiste già un server. Le release recenti supportano prenotazioni per MAC; relay e DHCPv6 non sono implementati.

Il DNS locale offre cache, forwarding e nomi delle lease nel dominio locale. I nomi locali irrisolti non vengono inoltrati. Seleziona le porte dati e fino a otto resolver IPv4 espliciti. Nessun fallback automatico a `/etc/resolv.conf` o import di `/etc/hosts`. L'accesso è limitato alle subnet selezionate e al relativo IPv4 locale; nessun permesso implicito su WAN o gestione. Il filtro per categorie è una [funzione parental separata](PARENTAL.md).

Murus avvia `dnsmasq-base` con configurazione in `/run/murus-igneus` dentro la transazione di applicazione/ripristino. Il file `/var/lib/murus-igneus/dnsmasq.leases` viene copiato dall'installer; vecchie lease possono sopravvivere ai pool che le hanno create.

Una porta WAN dati può ricevere IPv4 e gateway via DHCP. Non usare la porta di gestione per il traffico WAN. I DNS ricevuti sono mostrati, senza riscrivere il DNS di sistema. Rotte statiche e doppia WAN richiedono porte statiche; la rotta di default è `0.0.0.0/0` (alias `0.0.0.0`).

## Port forwarding

Ogni pubblicazione abilitata è un permesso esplicito prima delle policy ordinarie. Imposta ID, sorgente CIDR, interfaccia d'ingresso, IPv4 pubblico, porta TCP/UDP, porta interna, host e porta di destinazione. L'IPv4 pubblico deve coincidere con l'indirizzo statico di ingresso; la destinazione deve essere un host utilizzabile su una subnet interna distinta. Duplicati e conflitti con WireGuard vengono rifiutati. Una voce disabilitata non installa regole.

Il permesso verifica conntrack DNAT, tuple originali e tradotte, sorgente e interfacce. Non consente accesso diretto al server interno. Suricata, se attivo, continua a ispezionare il traffico. Non sono disponibili hairpin NAT, alias pubblici, intervalli di porte, NAT 1:1, IPv6 o conversione automatica VIP FortiGate.

## Connessioni e verifica

`/api/traffic` è autenticata, in sola lettura e limitata a 500 righe / 256 KiB. Mostra tuple originali e di risposta, stato e contatori se disponibili. Gli eventi del kernel sono soggetti a limiti; non costituiscono un archivio completo dei flussi. I [report parental](PARENTAL.md) usano contatori separati.

Il laboratorio CI `tools/validate-native-networking.py` usa namespace isolati e pacchetti reali VLAN, DHCP, DNS e DNAT, inclusi negazione delle sorgenti e rollback. La suite Chromium verifica i moduli della GUI contro il compilatore reale, con dati di stato simulati. Per i test delle ISO effettive vedi [stato e verifiche](../SOURCE_STATUS.md).
