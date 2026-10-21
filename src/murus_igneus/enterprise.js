/* Original IKEv2, failover and administration UI. SPDX-License-Identifier: MIT */
(() => {
  const section = document.createElement('section'); section.id = 'enterprise-page'; section.className = 'page'; section.hidden = true;
  section.innerHTML = `<h2>VPN IPsec e doppia WAN</h2>
    <p>IPsec IKEv2 con PSK, AES256/SHA256/DH14 e selettori IPv4. Ogni tunnel autorizza tutto il traffico tra i due selettori; IPS resta applicato. Niente IKEv1, accesso mobile o migrazione automatica VPN.</p>
    <form id="ipsec-form"><h3>Tunnel IPsec</h3><div id="ipsec-list"></div><button id="ipsec-add" type="button" class="secondary">Aggiungi tunnel</button><button>Salva IPsec nella bozza</button></form>
    <h3>Doppia WAN</h3><p>Due WAN statiche in ordine di preferenza. Tre controlli ICMP consecutivi per cambiare stato; basta un obiettivo raggiungibile per linea. Le sessioni esistenti possono interrompersi al cambio. Non è SD-WAN e IPsec non cambia automaticamente indirizzo pubblico.</p>
    <form id="wan-form"><label><input id="wan-enabled" type="checkbox"> Abilita failover</label><div id="wan-links"></div><button>Salva WAN nella bozza</button></form>
    <p>Le policy devono autorizzare ciascuna WAN. Rimuovi le rotte default statiche prima di abilitare il failover. Tabelle 18081/18082 e priorità omonime devono essere libere.</p>
    <button id="enterprise-health" class="secondary">Stato attivo</button><pre id="enterprise-state"></pre>`;
  document.querySelector('main').append(section);
  const admin = document.createElement('section'); admin.id = 'admin-page'; admin.className = 'page'; admin.hidden = true;
  admin.innerHTML = `<h2>Amministrazione e storico</h2><h3>Autenticazione a due fattori</h3><p>Password amministratore e TOTP a 6 cifre, sessione di 15 minuti. Conserva il segreto in modo sicuro. Recupero da console root: rimuovi /etc/murus_igneus/mfa.json e riavvia il servizio.</p>
    <button id="mfa-status">Stato MFA</button><button id="mfa-enroll">Configura TOTP</button><p id="mfa-state"></p><pre id="mfa-secret"></pre>
    <form id="mfa-confirm"><label>Codice dell’app Authenticator<input id="mfa-code" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" required></label><button>Conferma attivazione</button><button id="mfa-disable" type="button" class="secondary">Disabilita con un nuovo codice</button></form>
    <h3>Eventi persistenti</h3><p>Ultimi 1000 eventi; conservazione massima 30 giorni o 20.000 eventi. Include operazioni amministrative e log kernel policy/DNAT raccolti ogni 5 secondi. I limiti di frequenza e il buffer kernel possono omettere eventi. In modalità live lo storico si perde al riavvio.</p>
    <button id="events-refresh">Aggiorna storico</button><pre id="events-history"></pre>
    <h3>Aggiornamenti firmati</h3><p>La verifica dei pacchetti usa una chiave pubblica Ed25519 installata dall’amministratore. La chiave privata di firma non deve essere presente sul firewall. Usa murus-update da console per verificare, installare o ripristinare un pacchetto firmato.</p>`;
  document.querySelector('main').append(admin);
  let tunnels = [];
  function field(parent, label, value, type = 'text') { const l = document.createElement('label'); l.textContent = label; const input = document.createElement('input'); input.type = type; input.value = value ?? ''; l.append(input); parent.append(l); return input; }
  function renderTunnels() {
    el('ipsec-list').replaceChildren();
    for (const row of tunnels) {
      const card = document.createElement('article'); const controls = {};
      for (const [key, label, type] of [['id','ID (1–16)','number'],['public_device','Dispositivo WAN (es. eth1)','text'],['remote_ip','IP del peer remoto','text'],['local_id','Identità IKE locale','text'],['remote_id','Identità IKE remota','text'],['local_network','Rete LAN locale CIDR','text'],['remote_network','Rete remota CIDR','text'],['psk','PSK condivisa (20–128 caratteri)','password']]) {
        controls[key] = field(card, label, row[key], type); controls[key].required = true;
        controls[key].oninput = () => { row[key] = key === 'id' ? Number(controls[key].value) : controls[key].value; };
      }
      const enabled = field(card, 'Abilitato', '', 'checkbox'); enabled.checked = row.enabled; enabled.onchange = () => { row.enabled = enabled.checked; };
      card.append(button('Rimuovi', () => { tunnels = tunnels.filter(r => r !== row); renderTunnels(); })); el('ipsec-list').append(card);
    }
  }
  function edit() {
    tunnels = structuredClone(config.ipsec || []); renderTunnels(); el('wan-enabled').checked = !!config.wan?.enabled; el('wan-links').replaceChildren();
    for (let i=0;i<2;i++) { const row = config.wan?.links?.[i] || {}; const card = document.createElement('article'); card.append(text('h4', i ? 'WAN di riserva' : 'WAN preferita'));
      for (const [key, label, value] of [['device','Dispositivo',row.device],['gateway','Gateway IPv4',row.gateway],['targets','Obiettivi ICMP separati da virgola',(row.targets || []).join(', ')]]) { const input = field(card,label,value); input.id = `wan-${i}-${key}`; }
      el('wan-links').append(card);
    }
    show('enterprise-page');
  }
  el('nav').append(button('VPN IPsec e doppia WAN', edit),button('Amministrazione',()=>show('admin-page')));
  el('ipsec-add').onclick = () => { if(tunnels.length >=16)return error('Massimo 16 tunnel'); tunnels.push({id:Array.from({length:16},(_,i)=>i+1).find(id=>!tunnels.some(r=>r.id===id)), enabled:false}); renderTunnels(); };
  el('ipsec-form').onsubmit = event => {event.preventDefault();if(pending)return error('Conferma o annulla la modifica pendente');config.ipsec=structuredClone(tunnels);invalidate();show('review-page');};
  el('wan-form').onsubmit = event => {event.preventDefault();if(pending)return error('Conferma o annulla la modifica pendente'); const enabled=el('wan-enabled').checked;
    config.wan={enabled,links:[0,1].map(i=>({device:el(`wan-${i}-device`).value.trim(),gateway:el(`wan-${i}-gateway`).value.trim(),targets:el(`wan-${i}-targets`).value.split(',').map(v=>v.trim()).filter(Boolean)})).filter(r=>r.device||r.gateway||r.targets.length)};invalidate();show('review-page');};
  el('enterprise-health').onclick=async()=>{try{el('enterprise-state').textContent=JSON.stringify(await api('enterprise'),null,2);}catch(exc){error(exc);}};
  el('mfa-status').onclick=async()=>{try{const r=await api('auth/status');el('mfa-state').textContent=r.enabled?'TOTP attivo':'TOTP disabilitato';}catch(exc){error(exc);}};
  el('mfa-enroll').onclick=async()=>{try{const r=await api('auth/enroll',{});el('mfa-secret').textContent=`Segreto: ${r.secret}\n${r.uri}\nInserisci il codice entro 5 minuti per attivare.`;}catch(exc){error(exc);}};
  el('mfa-confirm').onsubmit=async event=>{event.preventDefault();try{await api('auth/confirm',{code:el('mfa-code').value});el('mfa-secret').textContent='';el('mfa-code').value='';el('mfa-state').textContent='TOTP attivato';}catch(exc){error(exc);}};
  el('mfa-disable').onclick=async()=>{try{await api('auth/disable',{code:el('mfa-code').value});el('mfa-code').value='';el('mfa-state').textContent='TOTP disabilitato';}catch(exc){error(exc);}};
  el('events-refresh').onclick=async()=>{try{const r=await api('events');el('events-history').textContent=(r.error?'Errore raccolta: '+r.error+'\n':'')+r.events.map(e=>`${new Date(e.time*1000).toLocaleString()} ${e.kind} ${JSON.stringify(e.detail)}`).join('\n');}catch(exc){error(exc);}};
})();
