# Murus Igneus su Proxmox VE

Questa configurazione è pensata per una VM di prova accanto a un firewall esistente. Usa bridge separati per WAN e LAN di test. Non collegare una LAN con DHCP Murus a un segmento dove c'è già un server DHCP attivo.

| Impostazione VM | Profilo iniziale |
| --- | --- |
| Macchina / BIOS | q35 / OVMF, disco EFI e Secure Boot disattivato |
| Disco | SCSI su **VirtIO SCSI single**, I/O thread attivo; 16 GiB per il laboratorio |
| CPU e RAM | 2 vCPU e 2 GiB fissi per iniziare. Con IDS/IPS o antivirus dimensiona in base al carico osservato. |
| Rete | Tre NIC VirtIO: gestione su un bridge raggiungibile dal PC, WAN e LAN su segmenti distinti. Identifica le interfacce dal MAC nell'inventario Murus. |
| Guest Agent | **Options → QEMU Guest Agent**, trasporto VirtIO, freeze/thaw durante i backup disattivato |

Il collaudo della ISO di sviluppo usa QEMU con UEFI, disco VirtIO SCSI su un I/O thread e tre NIC VirtIO. Verifica installazione, avvio autonomo, risposta del Guest Agent, inventario IP e spegnimento richiesto dall'host. Non misura le prestazioni di Proxmox/KVM o della rete fisica.

## Guest Agent

La nuova ISO include il pacchetto Devuan `qemu-guest-agent` e il servizio OpenRC `murus-guest-agent`. Senza il canale VirtIO `org.qemu.guest_agent.0` il servizio non avvia un processo. Non ascolta su TCP e non richiede regole firewall. Il canale consente ping, inventario e spegnimento. L'esecuzione di comandi, l'accesso ai file e il freeze/thaw non sono abilitati.

Dopo aver abilitato il canale, spegni e riavvia la VM dall'host. Verifica sul nodo Proxmox con `qm agent VMID ping` e dalla console Murus con `rc-service murus-guest-agent status`. Gli IP rilevati compaiono nello stato della VM.

Se aggiorni con il DEB invece di reinstallare, installa `qemu-guest-agent` da Devuan. Se esiste un servizio SysV `qemu-guest-agent`, fermalo e disabilitalo prima di attivare quello Murus: un solo processo deve usare il canale. Con il canale presente, registra il servizio con `rc-update add murus-guest-agent default` e avvialo con `rc-service murus-guest-agent start`.

## Misurare prima di cambiare multiqueue

Esegui i test su due macchine di laboratorio ai lati di Murus, con routing e una policy TCP per la porta 5201. Sul server di test avvia `iperf3 -s`; dal client esegui `iperf3 -c IP_SERVER -t 30`, poi la stessa prova con `-R` e con `-P 4`. Registra throughput, ritrasmissioni e CPU del nodo e della VM. Ripeti con e senza IDS/IPS in laboratorio, a parità di NIC, regole e percorsi. Se il limite è l'elaborazione di una singola coda, confronta due code con la stessa prova; non cambiare più impostazioni insieme. I risultati dipendono dalla macchina e dalle regole: non ci sono ancora numeri misurati su Proxmox.
