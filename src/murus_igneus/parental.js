/* Parental profiles, weekly windows and transparent network limits. SPDX-License-Identifier: MIT */
(() => {
  const page = document.createElement('section'); page.id='parental-page';page.className='page';page.hidden=true;
  page.innerHTML=`<p class="eyebrow">FAMIGLIA</p><h2>Parental control</h2>
    <p>Profili per dispositivi o subnet, filtri dei domini e fasce di accesso settimanali. Murus deve essere il gateway della rete protetta.</p>
    <aside>Usa IP stabili tramite Prenotazioni DHCP, oppure una VLAN dedicata ai figli con l’intera subnet nel profilo. Le categorie filtrano domini, non il contenuto delle pagine HTTPS. VPN, DNS cifrati non riconosciuti, rete mobile, IP fuori dal profilo e traffico che non passa da Murus possono aggirare i filtri. App e dispositivi possono conservare indirizzi già risolti: il blocco di Instagram non è un riconoscimento completo dell’applicazione.</aside>
    <h3>Liste delle categorie</h3><p>Liste HaGeZi GPL-3.0, scaricate solo quando premi Aggiorna. Dopo un aggiornamento verifica e riapplica la bozza. Le categorie selezionate devono essere scaricate prima dell’applicazione; non viene registrata la cronologia DNS.</p><div id="parental-feeds"></div><p id="parental-feed-state" role="status"></p>
    <form id="parental-form"><label><input id="parental-enabled" type="checkbox"> Abilita parental control</label>
    <label>Fuso orario<input id="parental-timezone" required value="Europe/Rome"></label>
    <label>Resolver DNS IPv4 per i profili (virgola)<input id="parental-upstreams" required value="1.1.1.1, 9.9.9.9"></label>
    <div id="parental-profiles"></div><button id="parental-add" type="button" class="secondary">Aggiungi profilo</button><button>Salva parental control nella bozza</button></form>
    <h3>Stato attivo e pausa immediata</h3><p>Le modifiche sopra richiedono Verifica e applica. La pausa qui sotto agisce sui profili già attivi, dura al massimo 24 ore e sopravvive al riavvio fino alla scadenza. Riprendi rimuove la pausa temporanea: restano validi orari e pause configurati nel profilo.</p>
    <label>Durata pausa<select id="parental-pause-minutes"><option value="15">15 minuti</option><option value="30" selected>30 minuti</option><option value="60">1 ora</option><option value="120">2 ore</option><option value="1440">24 ore</option></select></label>
    <button id="parental-refresh" class="secondary">Aggiorna stato</button><p id="parental-runtime-state" role="status"></p><div id="parental-runtime"></div>`;
  document.querySelector('main').append(page);
  let profiles=[],taskId=null;
  const values=input=>input.value.split(/[\n,]+/).map(v=>v.trim()).filter(Boolean);
  function field(card,label,value,type='text') {const wrap=document.createElement('label');wrap.textContent=label;const input=document.createElement(type==='textarea'?'textarea':'input');if(type!=='textarea')input.type=type;input.value=value??'';wrap.append(input);card.append(wrap);return input;}
  function checkbox(card,label,checked,change){const input=field(card,label,'','checkbox');input.checked=checked;input.onchange=()=>change(input.che…1178 tokens truncated…me').replaceChildren();
    for(const row of data.profiles){const card=document.createElement('article');card.append(text('h4',row.name),text('p',row.blocked?`Accesso bloccato: ${row.reason}`:'Accesso consentito negli orari configurati, con filtri DNS attivi'));
      if(row.pause_until)card.append(text('p','Pausa fino a '+new Date(row.pause_until*1000).toLocaleString()));
      const pause=minutes=>async()=>{try{await api('parental/pause',{id:row.id,minutes});await refresh();}catch(exc){error(exc);}};
      card.append(button('Pausa ora',()=>pause(Number(el('parental-pause-minutes').value))()),button('Riprendi',pause(0)));el('parental-runtime').append(card);}
    if(data.task?.state==='running')taskId=data.task.id;
    else if(taskId&&data.task?.id===taskId){el('parental-feed-state').textContent=data.task.state==='failed'?data.task.error:data.task.result.message;taskId=null;}
  }
  el('nav').append(button('Parental control',async()=>{try{const settings=config.parental||{enabled:false,timezone:'Europe/Rome',upstream_servers:['1.1.1.1','9.9.9.9'],profiles:[]};profiles=structuredClone(settings.profiles);el('parental-enabled').checked=settings.enabled;el('parental-timezone').value=settings.timezone;el('parental-upstreams').value=settings.upstream_servers.join(', ');render();show('parental-page');await refresh();}catch(exc){error(exc);}}));
  el('parental-add').onclick=()=>{if(profiles.length>=8)return error('Massimo 8 profili');profiles.push({id:Array.from({length:8},(_,i)=>i+1).find(id=>!profiles.some(p=>p.id===id)),name:'Nuovo profilo',enabled:true,interface:config.interfaces.find(r=>r.address)?.name||'',clients:[],categories:[],services:[],blocked_domains:[],allowed_domains:[],windows:[],paused:false,enforce_dns:true,block_quic:false});render();};
  el('parental-form').onsubmit=event=>{event.preventDefault();if(pending)return error('Conferma o annulla prima la modifica pendente');config.parental={enabled:el('parental-enabled').checked,timezone:el('parental-timezone').value.trim(),upstream_servers:values(el('parental-upstreams')),profiles:structuredClone(profiles)};invalidate();show('review-page');};
  el('parental-refresh').onclick=()=>refresh().catch(error);
  setInterval(()=>{if(!el('parental-page').hidden)refresh().catch(error);},3000);
})();
