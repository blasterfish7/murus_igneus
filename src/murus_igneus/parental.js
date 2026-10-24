/* Parental profiles, weekly windows and transparent network limits. SPDX-License-Identifier: MIT */
(() => {
  const page = document.createElement('section'); page.id='parental-page';page.className='page';page.hidden=true;
  page.innerHTML=`<p class="eyebrow">FAMIGLIA</p><h2>Parental control</h2>
    <p>Profili per dispositivi o subnet, filtri dei domini e fasce di accesso settimanali. Murus deve essere il gateway della rete protetta.</p>
    <aside>Usa IP stabili tramite Prenotazioni DHCP, oppure una VLAN dedicata ai figli con l’intera subnet nel profilo. Le categorie filtrano domini, non il contenuto delle pagine HTTPS. VPN, DNS cifrati non riconosciuti, rete mobile, IP fuori dal profilo e traffico che non passa da Murus possono aggirare i filtri. App e dispositivi possono conservare indirizzi già risolti: il blocco di Instagram non è un riconoscimento completo dell’applicazione.</aside>
    <h3>Liste delle categorie</h3><p>Liste HaGeZi GPL-3.0, scaricate solo quando premi Aggiorna. Dopo un aggiornamento verifica e riapplica la bozza. Le categorie selezionate devono essere scaricate prima dell’applicazione; il reporting DNS è facoltativo e conserva solo aggregati locali.</p><div id="parental-feeds"></div><p id="parental-feed-state" role="status"></p>
    <form id="parental-form"><label><input id="parental-enabled" type="checkbox"> Abilita parental control</label>
    <label>Fuso orario<input id="parental-timezone" required value="Europe/Rome"></label>
    <label>Resolver DNS IPv4 per i profili (virgola)<input id="parental-upstreams" required value="1.1.1.1, 9.9.9.9"></label>
    <label><input id="parental-reporting" type="checkbox"> Abilita reporting locale: volumi, richieste DNS e blocchi (7 giorni)</label>
    <div id="parental-profiles"></div><button id="parental-add" type="button" class="secondary">Aggiungi profilo</button><button>Salva parental control nella bozza</button></form>
    <h3>Stato attivo e pausa immediata</h3><p>Le modifiche sopra richiedono Verifica e applica. La pausa qui sotto agisce sui profili già attivi, dura al massimo 24 ore e sopravvive al riavvio fino alla scadenza. Riprendi rimuove la pausa temporanea: restano validi orari e pause configurati nel profilo.</p>
    <label>Durata pausa<select id="parental-pause-minutes"><option value="15">15 minuti</option><option value="30" selected>30 minuti</option><option value="60">1 ora</option><option value="120">2 ore</option><option value="1440">24 ore</option></select></label>
    <button id="parental-refresh" class="secondary">Aggiorna stato</button><p id="parental-runtime-state" role="status"></p><div id="parental-runtime"></div>
    <h3>Report traffico dei profili</h3><p>La raccolta parte dopo aver abilitato il reporting e applicato la bozza. Nessun invio al cloud. I domini sono richieste DNS, non una cronologia delle pagine visitate; i byte non sono attribuibili ai siti o alle app.</p>
    <label>Periodo<select id="parental-report-days"><option value="1">Ultime 24 ore</option><option value="7" selected>Ultimi 7 giorni</option></select></label>
    <label>Dispositivo o subnet<select id="parental-report-client"><option value="">Tutti i profili</option></select></label>
    <button id="parental-report-refresh" class="secondary">Aggiorna report</button><button id="parental-report-export" class="secondary">Esporta CSV</button><button id="parental-report-clear" class="secondary">Cancella tutti i report</button>
    <p id="parental-report-state" role="status"></p><p id="parental-report-note"></p><div id="parental-report-totals"></div>
    <h4>Andamento orario · IPv4 inoltrato</h4><div id="parental-report-hourly"></div>
    <h4>Domini DNS più richiesti · massimo 100 nel periodo</h4><div id="parental-report-domains"></div>`;
  document.querySelector('main').append(page);
  let profiles=[],taskId=null,reportData=null;
  const values=input=>input.value.split(/[\n,]+/).map(v=>v.trim()).filter(Boolean);
  function field(card,label,value,type='text') {const wrap=document.createElement('label');wrap.textContent=label;const input=document.createElement(type==='textarea'?'textarea':'input');if(type!=='textarea')input.type=type;input.value=value??'';wrap.append(input);card.append(wrap);return input;}
  function checkbox(card,label,checked,change){const input=field(card,label,'','checkbox');input.checked=checked;input.onchange=()=>change(input.checked);return input;}
  function render() {
    el('parental-profiles').replaceChildren();
    for(const row of profiles){
      const card=document.createElement('article');card.className='switch-card';card.append(text('h3',`Profilo ${row.id}`));
      const name=field(card,'Nome profilo',row.name);name.required=true;name.maxLength=80;name.oninput=()=>{row.name=name.value;};
      checkbox(card,'Profilo abilitato',row.enabled,v=>{row.enabled=v;});
      const label=document.createElement('label');label.textContent='LAN protetta';const port=document.createElement('select');
      for(const entry of config.interfaces.filter(r=>r.address))port.append(new Option(entry.name,entry.name));
      port.value=row.interface;port.required=true;port.onchange=()=>{row.interface=port.value;};label.append(port);card.append(label);
      const clients=field(card,'IPv4 o subnet dei dispositivi (una per riga)',row.clients.join('\n'),'textarea');clients.required=true;clients.oninput=()=>{row.clients=values(clients);};
      checkbox(card,'Forza DNS attraverso il filtro; blocca DNS cifrati sulle porte standard',row.enforce_dns,v=>{row.enforce_dns=v;});
      checkbox(card,'Blocca QUIC (UDP 443); alcune applicazioni possono smettere di funzionare',row.block_quic,v=>{row.block_quic=v;});
      checkbox(card,'Pausa configurata finché non viene modificata e riapplicata la bozza',row.paused,v=>{row.paused=v;});
      card.append(text('h4','Categorie'));
      for(const [id,title] of [['adult','Contenuti per adulti'],['gambling','Gioco d’azzardo'],['malware','Malware e phishing'],['bypass','Resolver cifrati e strumenti di aggiramento noti']])checkbox(card,title,row.categories.includes(id),v=>{row.categories=v?[...row.categories,id]:row.categories.filter(x=>x!==id);});
      card.append(text('h4','Servizi da bloccare'));
      for(const id of ['instagram','tiktok','facebook','youtube','snapchat','discord','twitch'])checkbox(card,id,row.services.includes(id),v=>{row.services=v?[...row.services,id]:row.services.filter(x=>x!==id);});
      const blocked=field(card,'Domini aggiuntivi bloccati (inclusi i sottodomini)',row.blocked_domains.join('\n'),'textarea');blocked.oninput=()=>{row.blocked_domains=values(blocked);};
      const allowed=field(card,'Eccezioni consentite (prevalgono sui blocchi dei domini)',row.allowed_domains.join('\n'),'textarea');allowed.oninput=()=>{row.allowed_domains=values(allowed);};
      card.append(text('h4','Fasce in cui Internet è consentito'));
      card.append(text('p','Senza fasce: nessun limite orario. Inizio incluso, fine esclusa. Una fascia 22:00–07:00 continua nel giorno successivo. Controlli ogni 2 secondi; verifica l’ora del firewall. Le eccezioni dei domini non superano pause e orari.'));
      for(const window of row.windows){
        const box=document.createElement('div');box.className='feature-grid';
        for(const [index,title] of ['Lun','Mar','Mer','Gio','Ven','Sab','Dom'].entries())checkbox(box,title,window.days.includes(index),v=>{window.days=v?[...window.days,index]:window.days.filter(d=>d!==index);});
        const start=field(box,'Dalle',window.start,'time');start.required=true;start.oninput=()=>{window.start=start.value;};
        const end=field(box,'Alle',window.end,'time');end.required=true;end.oninput=()=>{window.end=end.value;};
        box.append(button('Rimuovi fascia',()=>{row.windows=row.windows.filter(w=>w!==window);render();}));card.append(box);
      }
      card.append(button('Aggiungi fascia',()=>{if(row.windows.length>=28)return error('Massimo 28 fasce');row.windows.push({days:[0,1,2,3,4],start:'16:00',end:'20:00'});render();}),button('Rimuovi profilo',()=>{profiles=profiles.filter(p=>p!==row);render();}));
      el('parental-profiles').append(card);
    }
  }
  async function refresh(){
    const data=await api('parental');el('parental-feeds').replaceChildren();
    for(const feed of data.lists){const card=document.createElement('article');card.append(text('strong',feed.name),text('p',feed.ready?`${feed.count} domini · ${new Date(feed.updated*1000).toLocaleString()}`:'Lista non scaricata'));
      const update=button('Aggiorna '+feed.name,async()=>{try{const job=await api('parental/update',{category:feed.id});taskId=job.id;el('parental-feed-state').textContent='Download e validazione della lista in corso…';}catch(exc){error(exc);}});update.disabled=data.task?.state==='running';card.append(update);el('parental-feeds').append(card);}
    el('parental-runtime-state').textContent=data.error?`Errore del controllo: ${data.error}`:data.running?'Parental control attivo':'Parental control disabilitato';el('parental-runtime').replaceChildren();
    for(const row of data.profiles){const card=document.createElement('article');card.append(text('h4',row.name),text('p',row.blocked?`Accesso bloccato: ${row.reason}`:'Accesso consentito negli orari configurati, con filtri DNS attivi'));
      if(row.pause_until)card.append(text('p','Pausa fino a '+new Date(row.pause_until*1000).toLocaleString()));
      const pause=minutes=>async()=>{try{await api('parental/pause',{id:row.id,minutes});await refresh();}catch(exc){error(exc);}};
      card.append(button('Pausa ora',()=>pause(Number(el('parental-pause-minutes').value))()),button('Riprendi',pause(0)));el('parental-runtime').append(card);}
    if(data.task?.state==='running')taskId=data.task.id;
    else if(taskId&&data.task?.id===taskId){el('parental-feed-state').textContent=data.task.state==='failed'?data.task.error:data.task.result.message;taskId=null;}
  }
  el('nav').append(button('Parental control',async()=>{try{const settings=config.parental||{enabled:false,timezone:'Europe/Rome',upstream_servers:['1.1.1.1','9.9.9.9'],profiles:[]};profiles=structuredClone(settings.profiles);el('parental-enabled').checked=settings.enabled;el('parental-reporting').checked=!!settings.reporting;el('parental-timezone').value=settings.timezone;el('parental-upstreams').value=settings.upstream_servers.join(', ');render();show('parental-page');await refresh();await refreshReport();}catch(exc){error(exc);}}));
  el('parental-add').onclick=()=>{if(profiles.length>=8)return error('Massimo 8 profili');profiles.push({id:Array.from({length:8},(_,i)=>i+1).find(id=>!profiles.some(p=>p.id===id)),name:'Nuovo profilo',enabled:true,interface:config.interfaces.find(r=>r.address)?.name||'',clients:[],categories:[],services:[],blocked_domains:[],allowed_domains:[],windows:[],paused:false,enforce_dns:true,block_quic:false});render();};
  el('parental-form').onsubmit=event=>{event.preventDefault();if(pending)return error('Conferma o annulla prima la modifica pendente');config.parental={enabled:el('parental-enabled').checked,reporting:el('parental-reporting').checked,timezone:el('parental-timezone').value.trim(),upstream_servers:values(el('parental-upstreams')),profiles:structuredClone(profiles)};invalidate();show('review-page');};
  const bytes=value=>{const units=['B','KiB','MiB','GiB','TiB'];let i=0;while(value>=1024&&i<units.length-1){value/=1024;i++;}return `${value.toFixed(i?1:0)} ${units[i]}`;};
  function reportTable(target,headers,rows){
    const box=el(target);box.replaceChildren();if(!rows.length){box.append(text('p','Nessun dato raccolto nel periodo selezionato.'));return;}
    const table=document.createElement('table'),head=document.createElement('thead'),tr=document.createElement('tr');
    for(const title of headers)tr.append(text('th',title));head.append(tr);table.append(head);const body=document.createElement('tbody');
    for(const values of rows){const row=document.createElement('tr');for(const value of values){const td=document.createElement('td');if(value instanceof Node)td.append(value);else td.textContent=String(value);row.append(td);}body.append(row);}table.append(body);box.append(table);
  }
  function renderReport(){
    if(!reportData)return;const d=reportData,key=el('parental-report-client').value,selected=rows=>rows.filter(r=>!key||r.entity===key);
    el('parental-report-note').textContent=d.note;
    el('parental-report-state').textContent=(d.collecting?'Raccolta attiva':'Raccolta disabilitata; eventuali dati precedenti restano fino alla scadenza')+
      (d.last_sample?' · Ultimo campione: '+new Date(d.last_sample*1000).toLocaleString():' · Nessun campione disponibile')+
      (d.error?' · Errore/incompletezza: '+d.error:'')+(d.discarded_dns?' · Eventi DNS scartati: '+d.discarded_dns:'')+(d.domains_truncated?' · Mostrati solo i primi 100 domini globali':'');
    reportTable('parental-report-totals',['Profilo','IPv4 / subnet','Upload','Download','Pacchetti bloccati','Richieste DNS','DNS filtrati'],selected(d.devices).map(r=>[r.name,r.client,bytes(r.upload_bytes),bytes(r.download_bytes),r.blocked_packets,r.dns_queries,r.dns_filtered]));
    const hours=new Map();for(const r of selected(d.hourly)){const h=hours.get(r.time)||{time:r.time,up:0,down:0};h.up+=r.upload_bytes;h.down+=r.download_bytes;hours.set(r.time,h);}
    const entries=[...hours.values()].sort((a,b)=>b.time-a.time),max=Math.max(1,...entries.map(r=>r.up+r.down));
    reportTable('parental-report-hourly',['Ora locale (inizio fascia)','Upload','Download','Volume relativo'],entries.map(r=>{const meter=document.createElement('meter');meter.min=0;meter.max=max;meter.value=r.up+r.down;meter.title=bytes(r.up+r.down);meter.setAttribute('aria-label','Volume '+meter.title);return[new Date(r.time*1000).toLocaleString(),bytes(r.up),bytes(r.down),meter];}));
    reportTable('parental-report-domains',['Profilo','IPv4 / subnet','Dominio richiesto','Richieste','Filtrate dal resolver'],selected(d.domains).map(r=>[r.name,r.client,r.domain,r.queries,r.filtered]));
  }
  async function refreshReport(){
    const days=Number(el('parental-report-days').value);const d=await api('parental/report/'+days);reportData=d;
    const select=el('parental-report-client'),previous=select.value;select.replaceChildren(new Option('Tutti i profili',''));
    for(const r of d.devices)select.append(new Option(`${r.name} · ${r.client}`,r.entity));select.value=d.devices.some(r=>r.entity===previous)?previous:'';renderReport();
  }
  el('parental-report-client').onchange=renderReport;
  el('parental-report-days').onchange=()=>refreshReport().catch(error);
  el('parental-report-refresh').onclick=()=>refreshReport().catch(error);
  el('parental-report-export').onclick=async()=>{try{const data=await api('parental/report/export',{days:Number(el('parental-report-days').value)});const url=URL.createObjectURL(new Blob(['\ufeff',data.csv],{type:'text/csv;charset=utf-8'}));const a=document.createElement('a');a.href=url;a.download='murus-parental-report.csv';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(exc){error(exc);}};
  el('parental-report-clear').onclick=async()=>{if(!confirm('Cancellare tutti i report parental di tutti i profili? La raccolta attiva continuerà con nuovi dati.'))return;try{await api('parental/report/clear',{confirm:true});await refreshReport();}catch(exc){error(exc);}};
  el('parental-refresh').onclick=()=>refresh().catch(error);
  setInterval(()=>{if(!el('parental-page').hidden)refresh().catch(error);},3000);
})();
