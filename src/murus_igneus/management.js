/* Original local AI and SNMP management UI. SPDX-License-Identifier: MIT */
(() => {
  const container = document.querySelector('main');
  const page = (id, markup) => {
    const section = document.createElement('section');
    section.id = id; section.className = 'page'; section.hidden = true;
    section.innerHTML = markup; container.append(section);
  };
  page('assistant-page', `
    <p class="eyebrow">ASSISTENTE AI</p><h2>AI per la tua rete</h2>
    <p>Analizza la bozza e la telemetria degli switch. Le proposte passano nell’editor e richiedono verifica e conferma.</p>
    <aside>Ollama usa un modello Qwen3 installato nella LAN, non incluso nella ISO. OpenAI è un servizio esterno opzionale: riceverà domanda, bozza e telemetria selezionata. Le credenziali strutturate vengono rimosse, ma IP, nomi e testo libero possono essere riservati. Verifica i dati prima di inviarli.</aside>
    <form id="ai-settings"><label><input id="ai-enabled" type="checkbox"> Abilita assistente</label>
      <label>Provider<select id="ai-provider"><option value="ollama">Ollama locale</option><option value="openai">OpenAI API</option></select></label>
      <div id="ai-local"><label>Server Ollama (IPv4 privato)<input id="ai-endpoint" required placeholder="http://192.168.10.10:11434"></label>
      <label>Modello locale<select id="ai-model"></select></label></div>
      <div id="ai-cloud" hidden><label>Modello OpenAI<input id="ai-cloud-model" maxlength="100" placeholder="ID del modello disponibile nel tuo progetto"></label>
      <label>Chiave API (vuoto: conserva quella salvata)<input id="ai-api-key" type="password" autocomplete="new-password"></label><p id="ai-key-state"></p>
      <label><input id="ai-delete-key" type="checkbox"> Elimina la chiave salvata</label>
      <label><input id="ai-cloud-consent" type="checkbox"> Autorizzo l’invio dei dati selezionati a OpenAI e l’uso della quota API</label>
      <label>Massimo token di risposta<input id="ai-max-tokens" type="number" min="256" max="8192" value="2048"></label></div>
      <div class="actions"><button>Salva impostazioni AI</button><button type="button" id="ai-check" class="secondary">Verifica modello</button></div>
    </form><p id="ai-connection" role="status"></p>
    <form id="ai-question-form"><label>Domanda<textarea id="ai-question" maxlength="4000" rows="4" required placeholder="Spiegami quali reti possono accedere a Internet e segnala le regole troppo ampie."></textarea></label>
      <label><input id="ai-allow-proposal" type="checkbox"> Consenti una proposta di configurazione da verificare</label><label><input id="ai-logs" type="checkbox"> Includi gli ultimi log delle policy</label>
      <button id="ai-send">Chiedi all’assistente</button></form>
    <p id="ai-state" role="status"></p><pre id="ai-answer" class="ai-answer"></pre>
    <details id="ai-proposal-panel" hidden><summary>Configurazione proposta da controllare</summary><pre id="ai-proposal"></pre>
      <button id="ai-use-proposal">Carica proposta nella bozza</button></details>
  `);
  page('switches-page', `
    <p class="eyebrow">RETE LOCALE</p><h2>Switch</h2>
    <p>Inventario manuale tramite SNMPv2c o SNMPv3 authPriv (SHA/AES). Lettura IF-MIB e vicini LLDP, se esposti dallo switch.</p>
    <aside>Proteggi gli indici delle porte di gestione, uplink e aggregazione prima di abilitare la scrittura.
    Le modifiche up/down non hanno rollback automatico. VLAN, PoE e configurazioni proprietarie non sono ancora gestiti.</aside>
    <div class="actions"><button id="sw-new">Aggiungi switch</button><button id="sw-refresh" class="secondary">Aggiorna inventario</button></div>
    <p id="sw-state" role="status"></p><div id="sw-inventory"></div>
    <form id="sw-form" hidden><h3 id="sw-form-title">Switch</h3><input id="sw-id" type="hidden">
      <label>Nome<input id="sw-name" required maxlength="80"></label>
      <label>IPv4 di gestione<input id="sw-host" required placeholder="192.168.10.2"></label>
      <label>Porta UDP SNMP<input id="sw-udp-port" type="number" min="1" max="65535" value="161" required></label><label>Versione<select id="sw-version"><option value="3">SNMPv3 authPriv SHA/AES</option><option value="2c">SNMPv2c (non cifrato)</option></select></label>
      <div id="sw-v2"><label>Community<input id="sw-community" type="password" autocomplete="new-password"></label></div>
      <div id="sw-v3"><label>Utente<input id="sw-username" autocomplete="off"></label>
        <label>Password autenticazione SHA<input id="sw-auth-pass" type="password" autocomplete="new-password"></label>
        <label>Password cifratura AES<input id="sw-priv-pass" type="password" autocomplete="new-password"></label></div>
      <p>Durante la modifica lascia vuote le credenziali per mantenere quelle salvate.</p>
      <label>Indici IF-MIB delle porte protette (separati da virgola)<input id="sw-protected" placeholder="1, 24"></label>
      <label><input id="sw-write" type="checkbox"> Abilita comandi up/down (richiede autorizzazione SNMP in scrittura sullo switch)</label>
      <div class="actions"><button>Salva switch</button><button type="button" id="sw-cancel" class="secondary">Annulla</button></div>
    </form><section id="sw-detail" hidden><h3 id="sw-title"></h3><p id="sw-info"></p>
      <p>Contatori cumulativi a 32 bit, soggetti a riavvolgimento; non indicano la velocità istantanea.</p>
      <div class="table-wrap"><table><thead><tr><th>Indice</th><th>Porta</th><th>Descrizione</th><th>Admin / Link</th><th>Velocità</th><th>RX / TX byte</th><th>Azioni</th></tr></thead><tbody id="sw-ports"></tbody></table></div>
      <h3>Vicini LLDP</h3><p>Indice LLDP: timeMark.portaLocale.indiceRemoto. Il numero locale LLDP può differire dall’indice IF-MIB.</p><pre id="sw-lldp"></pre>
    </section>
  `);
  page('updates-page', `
    <p class="eyebrow">MANUTENZIONE DEL SISTEMA</p><h2>Aggiornamenti</h2>
    <p>Aggiorna l’applicazione Murus Igneus con un bundle firmato. Il servizio e il traffico vengono interrotti durante il riavvio.</p>
    <div class="runtime-grid"><article class="runtime-card"><span>Versione installata</span><strong id="update-version">—</strong><small>Pacchetto applicativo DEB</small></article><article class="runtime-card"><span>Firma degli aggiornamenti</span><strong id="update-trust">—</strong><small>Chiave Ed25519 configurata dalla console</small></article><article class="runtime-card"><span>Ripristino disponibile</span><strong id="update-previous">—</strong><small>Pacchetto e configurazione salvata</small></article></div>
    <p id="update-availability" role="status"></p>
    <section class="panel"><h3>Release disponibili</h3><label>Canale<select id="update-channel"><option value="stable">Stabile</option><option value="experimental">Sperimentale · include alpha e beta</option></select></label><button id="update-check" class="secondary">Controlla release su GitHub</button><p id="update-catalog-state" role="status"></p><div id="update-releases"></div><p>Il catalogo non autorizza l’installazione: il bundle deve sempre superare la verifica della firma. I repository privati possono richiedere il caricamento offline.</p></section>
    <section class="panel"><h3>Carica un aggiornamento firmato</h3><p>Seleziona i tre file del bundle. Il solo DEB o il checksum della ISO non costituiscono un aggiornamento firmato.</p><form id="update-upload"><label>Manifest JSON<input id="update-manifest" type="file" accept=".json" required></label><label>Firma Ed25519<input id="update-signature" type="file" accept=".sig" required></label><label>Pacchetto applicativo (massimo 4 MiB)<input id="update-package" type="file" accept=".deb" required></label><button id="update-verify">Verifica bundle</button></form><p id="update-preview" role="status"></p><div id="update-install-panel" hidden><label>Per installare, riscrivi <strong id="update-install-phrase"></strong><input id="update-install-text" autocomplete="off"></label><button id="update-install" disabled>Backup e installazione</button></div></section>
    <section class="panel"><h3>Operazione e recupero</h3><p id="update-job-state" role="status">Nessuna operazione</p><details><summary>Dettagli tecnici dell’operazione</summary><pre id="update-job-detail" hidden></pre></details><p>Il backup comprende il pacchetto e la configurazione applicativa. Il recupero del registro interrotto va completato prima di nuove modifiche.</p><label id="update-restore-label">Per ripristinare, riscrivi <strong id="update-restore-phrase"></strong><input id="update-restore-text" autocomplete="off"></label><button id="update-restore" disabled>Ripristina versione precedente</button></section>
    <aside>Questo aggiornamento non comprende Devuan, kernel o firmware. Le firme antivirus e IPS si aggiornano dalla pagina UTM. Un guasto del disco o del sistema operativo richiede il recupero da console/ISO.</aside>
  `);
  let updatePreview=null, updateMonitoring=false, updateRead=null, updateInventory=null;
  function resetUpdatePreview(){updatePreview=null;el('update-install-panel').hidden=true;el('update-install').disabled=true;el('update-preview').textContent='';}
  for(const id of ['update-manifest','update-signature','update-package'])el(id).onchange=resetUpdatePreview;
  async function refreshUpdates(){
    if(updateRead)return updateRead;
    updateRead=(async()=>{try{
      const data=await api('updates');updateInventory=data;
      el('update-version').textContent=data.installed_version||'Non installato';
      el('update-trust').textContent=data.trust_configured?'Chiave presente':'Da configurare';
      el('update-previous').textContent=data.rollback_version||'Nessuno';
      el('update-availability').textContent=data.live?'Sessione live: installa prima Murus su disco.':!data.supported?'Aggiornamenti disponibili solo su Devuan 6 Excalibur installato.':!data.trust_configured?'Configura dalla console la chiave pubblica di firma attendibile in /etc/murus_igneus/update.pub. Non caricare la chiave privata sul firewall.':data.scope;
      const job=data.job, recovery=job?.state==='recovery_required', locked=data.busy||recovery;
      el('update-verify').disabled=!data.supported||!data.trust_configured||locked;
      const stateNames={queued:'In attesa',running:'In corso',recovering:'Ripristino in corso',recovery_required:'Recupero necessario',succeeded:'Completato',failed:'Non riuscito'};
      el('update-job-state').textContent=job?((stateNames[job.state]||'Stato da verificare')+' · '+job.phase+(job.error?' · '+job.error:'')):'Nessuna operazione di aggiornamento';
      el('update-job-detail').hidden=!job;el('update-job-detail').textContent=job?JSON.stringify(job,null,2):'';
      el('update-restore-phrase').textContent=recovery?'RECUPERA SERVIZIO':data.rollback_version?'RIPRISTINA '+data.rollback_version:'';
      el('update-restore-label').hidden=!recovery&&!data.rollback_available;
      el('update-restore').textContent=recovery?'Recupera operazione interrotta':'Ripristina versione precedente';
      el('update-restore').disabled=!data.supported||data.busy||(!recovery&&!data.rollback_available)||el('update-restore-text').value!==el('update-restore-phrase').textContent;
    }catch(exc){el('update-job-state').textContent='Servizio non raggiungibile · attendo il ritorno della pagina web. '+exc.message;el('update-verify').disabled=el('update-install').disabled=el('update-restore').disabled=true;}finally{updateRead=null;}})();return updateRead;
  }
  el('nav').append(button('Aggiornamenti',async()=>{show('updates-page');updateMonitoring=true;await refreshUpdates();}));
  el('update-check').onclick=async()=>{el('update-check').disabled=true;el('update-catalog-state').textContent='Controllo release…';el('update-releases').replaceChildren();try{const data=await api('updates/check',{channel:el('update-channel').value});el('update-catalog-state').textContent=data.releases.length?'Release pubblicate per il canale selezionato.':'Nessuna release pubblicata per questo canale.';for(const release of data.releases){const article=text('article','','panel'),link=text('a','Apri release su GitHub');link.href=release.url;link.target='_blank';link.rel='noopener noreferrer';article.append(text('h4',release.tag+(release.newer?' · più recente':'')),text('p',release.notes||'Nessuna nota disponibile'),link);el('update-releases').append(article);}}catch(exc){el('update-catalog-state').textContent=exc.message;}finally{el('update-check').disabled=false;}};
  async function encodedFile(id,limit){const file=el(id).files[0];if(!file||file.size===0||file.size>limit)throw Error('File mancante o oltre il limite: '+id);const bytes=new Uint8Array(await file.arrayBuffer());let value='';for(let i=0;i<bytes.length;i+=32768)value+=String.fromCharCode(...bytes.subarray(i,i+32768));return btoa(value);}
  el('update-upload').onsubmit=async event=>{event.preventDefault();resetUpdatePreview();el('update-verify').disabled=true;try{const files={'manifest.json':await encodedFile('update-manifest',4096),'manifest.sig':await encodedFile('update-signature',64),'murus-igneus.deb':await encodedFile('update-package',4*1024*1024)};const result=await api('updates/stage',{files});updatePreview=result;el('update-preview').textContent='Firma, digest e metadati verificati · versione '+result.version+' · SHA256 '+result.sha256;el('update-install-phrase').textContent=result.confirmation;el('update-install-text').value='';el('update-install-panel').hidden=false;}catch(exc){el('update-preview').textContent=exc.message;}finally{await refreshUpdates();}};
  el('update-install-text').oninput=()=>{el('update-install').disabled=!updatePreview||el('update-install-text').value!==updatePreview.confirmation;};
  el('update-install').onclick=async()=>{if(!updatePreview)return;if(dirty&&!confirm('La bozza non salvata non verrà installata né inclusa nel backup. Continuare con la configurazione confermata?'))return;el('update-install').disabled=true;try{await api('updates/install',{id:updatePreview.id,confirmation:el('update-install-text').value});resetUpdatePreview();el('update-job-state').textContent='Aggiornamento avviato. La pagina può perdere temporaneamente la connessione.';await refreshUpdates();}catch(exc){el('update-preview').textContent=exc.message;}};
  el('update-restore-text').oninput=()=>{el('update-restore').disabled=!updateInventory||updateInventory.busy||el('update-restore-text').value!==el('update-restore-phrase').textContent;};
  el('update-restore').onclick=async()=>{if(!confirm('Il servizio verrà riavviato. Il ripristino del pacchetto recupera anche la configurazione del suo backup. Continuare?'))return;el('update-restore').disabled=true;try{const recovering=updateInventory?.job?.state==='recovery_required';await api(recovering?'updates/recover':'updates/rollback',{confirmation:el('update-restore-text').value});el('update-restore-text').value='';await refreshUpdates();}catch(exc){el('update-job-state').textContent=exc.message;}};
  const dialog = document.createElement('dialog');
  dialog.id = 'sw-confirm-dialog';
  dialog.innerHTML = `<form id="sw-confirm-form"><h3>Conferma modifica porta</h3><p id="sw-warning"></p><p>Scrivi esattamente: <strong id="sw-phrase"></strong></p><label>Conferma<input id="sw-confirm-text" autocomplete="off"></label><div class="actions"><button id="sw-execute" disabled>Esegui sullo switch</button><button type="button" id="sw-dismiss" class="secondary">Annulla</button></div></form>`;
  document.body.append(dialog);

  let aiJob = null, aiKind = '', aiProposal = null, aiDraft = null, swJob = null, swKind = '', selected = null, devices = [], portPlan = null;
  function aiSettings(data) {
    el('ai-enabled').checked = data.settings.enabled; el('ai-provider').value = data.settings.provider || 'ollama';
    el('ai-endpoint').value = data.settings.provider === 'openai' ? 'http://127.0.0.1:11434' : data.settings.endpoint;
    el('ai-cloud-model').value = data.settings.provider === 'openai' ? data.settings.model : '';
    el('ai-cloud-consent').checked = !!data.settings.cloud_consent; el('ai-max-tokens').value = data.settings.max_output_tokens || 2048;
    el('ai-key-state').textContent = data.settings.key_configured ? 'Chiave presente sul firewall' : 'Nessuna chiave configurata';
    el('ai-api-key').value = ''; el('ai-delete-key').checked = false; providerFields();
    el('ai-model').replaceChildren(...data.models.map(m => new Option(m, m)));
    el('ai-model').value = data.settings.provider === 'openai' ? 'qwen3:4b' : data.settings.model;
  }
  function providerFields() {
    const cloud = el('ai-provider').value === 'openai';
    el('ai-cloud').hidden = !cloud; el('ai-local').hidden = cloud; el('ai-endpoint').required = !cloud; el('ai-cloud-model').required = cloud;
  }
  el('ai-provider').onchange = providerFields;
  async function openAI() {
    const data = await api('assistant'); aiSettings(data); show('assistant-page');
    if (data.task?.state === 'running') {
      if (aiJob !== data.task.id) {
        // Another tab (or a reload) has no verifiable copy of the submitted draft.
        aiDraft = null; aiProposal = null; el('ai-proposal-panel').hidden = true;
        aiKind = 'ask';
      }
      aiJob = data.task.id; el('ai-state').textContent = 'Elaborazione in corso…';
    }
  }
  el('nav').append(button('Assistente AI', () => openAI().catch(error)), button('Switch locali', () => { show('switches-page'); refreshSwitches().catch(error); }));
  el('ai-settings').onsubmit = async e => {
    e.preventDefault(); try {
      const cloud = el('ai-provider').value === 'openai';
      const settings = { enabled: el('ai-enabled').checked, provider: el('ai-provider').value, endpoint: el('ai-endpoint').value.trim(),
        model: cloud ? el('ai-cloud-model').value.trim() : el('ai-model').value, cloud_consent: el('ai-cloud-consent').checked,
        max_output_tokens: Number(el('ai-max-tokens').value), delete_key: el('ai-delete-key').checked };
      if (el('ai-api-key').value) settings.api_key = el('ai-api-key').value;
      await api('assistant/settings', settings); el('ai-api-key').value = ''; el('ai-delete-key').checked = false;
      el('ai-connection').textContent = 'Impostazioni salvate. Verifica la disponibilità del modello.';
    } catch (exc) { error(exc); }
  };
  el('ai-check').onclick = async () => {
    try { const task = await api('assistant/check', {}); aiJob = task.id; aiKind = 'check'; el('ai-connection').textContent = 'Verifica in corso…'; } catch (exc) { error(exc); }
  };
  el('ai-question-form').onsubmit = async e => {
    e.preventDefault();
    if (aiJob || el('ai-send').disabled) return;
    el('ai-send').disabled = true;
    const submittedDraft = JSON.stringify(config);
    try {
      const task = await api('assistant/ask', { question: el('ai-question').value, configuration: config, include_logs: el('ai-logs').checked, allow_proposal: el('ai-allow-proposal').checked });
      aiDraft = submittedDraft; aiProposal = null; el('ai-proposal-panel').hidden = true;
      aiJob = task.id; aiKind = 'ask'; el('ai-state').textContent = 'Il modello sta elaborando…'; el('ai-answer').textContent = ''; el('ai-send').disabled = true;
    } catch (exc) { el('ai-send').disabled = false; error(exc); }
  };
  el('ai-use-proposal').onclick = () => {
    if (!aiProposal) return;
    if (pending) return error('Conferma o annulla prima la modifica pendente.');
    if (JSON.stringify(config) !== aiDraft) return error('La bozza è cambiata dopo la domanda: ripeti l’analisi AI.');
    if (!confirm('Sostituire la bozza con questa proposta AI? Devi ancora verificarla e applicarla.')) return;
    config = structuredClone(aiProposal); invalidate(); el('ai-proposal-panel').hidden = true; show('review-page');
  };
  function versionFields() { el('sw-v2').hidden = el('sw-version').value !== '2c'; el('sw-v3').hidden = el('sw-version').value !== '3'; }
  el('sw-version').onchange = versionFields;
  function editSwitch(row = {}) {
    el('sw-form').reset(); el('sw-form').hidden = false; el('sw-form-title').textContent = row.id ? 'Modifica switch' : 'Aggiungi switch';
    el('sw-id').value = row.id || ''; el('sw-name').value = row.name || ''; el('sw-host').value = row.host || '';
    el('sw-udp-port').value = row.port || 161; el('sw-version').value = row.version || '3'; el('sw-username').value = row.username || '';
    el('sw-protected').value = (row.protected_ports || []).join(', '); el('sw-write').checked = !!row.write_enabled; versionFields();
  }
  el('sw-new').onclick = () => editSwitch(); el('sw-cancel').onclick = () => { el('sw-form').reset(); el('sw-form').hidden = true; };
  el('sw-refresh').onclick = () => refreshSwitches().catch(error);
  el('sw-form').onsubmit = async e => {
    e.preventDefault(); try {
      const row = { name: el('sw-name').value.trim(), host: el('sw-host').value.trim(), version: el('sw-version').value, port: Number(el('sw-udp-port').value),
        protected_ports: el('sw-protected').value.split(',').map(v => v.trim()).filter(Boolean).map(Number), write_enabled: el('sw-write').checked };
      if (el('sw-id').value) row.id = el('sw-id').value;
      if (row.version === '2c') row.community = el('sw-community').value;
      else { row.username = el('sw-username').value; row.auth_pass = el('sw-auth-pass').value; row.priv_pass = el('sw-priv-pass').value; }
      await api('switches/save', row); el('sw-form').reset(); el('sw-form').hidden = true; await refreshSwitches();
    } catch (exc) { error(exc); }
  };
  async function startSwitch(path, payload, kind) {
    const task = await api(path, payload); swJob = task.id; swKind = kind; el('sw-state').textContent = 'Operazione SNMP in corso…';
  }
  async function refreshSwitches() {
    const data = await api('switches'); devices = data.devices;
    el('sw-inventory').replaceChildren();
    if (!data.snmp_available) el('sw-state').textContent = 'Net-SNMP assente: installare il pacchetto snmp.';
    for (const row of devices) {
      const card = document.createElement('article'); card.className = 'switch-card';
      card.append(text('h3', row.name), text('p', `${row.host} · SNMP${row.version} · ${row.write_enabled ? 'scrittura abilitata' : 'sola lettura'}`));
      card.append(button('Leggi stato', () => { selected = row.id; startSwitch('switches/poll', { id: row.id }, 'poll').catch(error); }),
        button('Mostra porte', () => { selected = row.id; renderSwitch(row); }), button('Modifica', () => editSwitch(row)),
        button('Rimuovi', async () => { if (!confirm(`Rimuovere ${row.name} dall’inventario?`)) return; try { await api('switches/delete', { id: row.id }); if (selected === row.id) { selected = null; el('sw-detail').hidden = true; } await refreshSwitches(); } catch (exc) { error(exc); } }));
      el('sw-inventory').append(card);
    }
    if (!devices.length) el('sw-inventory').append(text('p', 'Nessuno switch registrato.'));
    if (selected) { const row = devices.find(d => d.id === selected); if (row) renderSwitch(row); }
  }
  function renderSwitch(row) {
    el('sw-detail').hidden = false; el('sw-title').textContent = row.name; const t = row.telemetry;
    el('sw-ports').replaceChildren(); el('sw-lldp').textContent = '';
    if (!t || t.error) { el('sw-info').textContent = t?.error || 'Premi Leggi stato per interrogare lo switch.'; return; }
    el('sw-info').textContent = `${t.name} · ${t.description} · letto ${new Date(t.polled * 1000).toLocaleString()} ${(t.warnings || []).join('; ')}`;
    const stateName = v => ({ 1: 'up', 2: 'down', 3: 'testing' }[v] || String(v ?? 'n/d'));
    for (const p of t.ports) {
      const tr = document.createElement('tr');
      for (const value of [p.index, p.name, p.alias, `${stateName(p.admin)} / ${stateName(p.oper)}`, p.speed_bps == null ? 'n/d' : `${p.speed_bps / 1e6} Mbps`, `${p.in_octets32 ?? 'n/d'} / ${p.out_octets32 ?? 'n/d'}`]) tr.append(text('td', value));
      const td = document.createElement('td');
      if (p.protected) td.textContent = 'Protetta';
      else if (row.write_enabled && p.type === 6 && [1, 2].includes(p.admin)) td.append(button(p.admin === 1 ? 'Disabilita…' : 'Abilita…', () => startSwitch('switches/port/preview', { id: row.id, port: p.index, admin: p.admin === 1 ? 2 : 1 }, 'preview').catch(error)));
      else td.textContent = 'Sola lettura';
      tr.append(td); el('sw-ports').append(tr);
    }
    el('sw-lldp').textContent = t.lldp.length ? t.lldp.map(n => `${n.index}: ${n.remote_name}`).join('\n') : 'Nessun vicino LLDP esposto.';
  }
  el('sw-dismiss').onclick = () => { dialog.close(); portPlan = null; };
  el('sw-confirm-text').oninput = () => { el('sw-execute').disabled = !portPlan || el('sw-confirm-text').value !== portPlan.confirmation; };
  el('sw-confirm-form').onsubmit = async e => {
    e.preventDefault(); if (!portPlan) return;
    try { await startSwitch('switches/port/apply', { token: portPlan.token, confirmation: el('sw-confirm-text').value }, 'apply'); dialog.close(); portPlan = null; } catch (exc) { error(exc); }
  };
  async function progress() {
    if(updateMonitoring&&!document.hidden&&!el('updates-page').hidden)await refreshUpdates();
    if (aiJob) {
      const data = await api('assistant'), task = data.task;
      if (task?.id !== aiJob) {
        aiJob = null; aiProposal = null; aiDraft = null; el('ai-proposal-panel').hidden = true;
        el('ai-send').disabled = false;
        el('ai-state').textContent = 'Risultato non più disponibile o sostituito da un’altra sessione. Ripeti la domanda.';
      } else if (task.state !== 'running') {
        aiJob = null; el('ai-send').disabled = false;
        if (task.state === 'failed') { el('ai-state').textContent = task.error; el('ai-connection').textContent = task.error; }
        else if (aiKind === 'check') el('ai-connection').textContent = task.result.message;
        else {
          el('ai-state').textContent = 'Risposta AI: controlla le indicazioni prima di usarle. Nessuna modifica applicata.';
          const f = task.result.facts;
          const facts = f ? `Dati della bozza verificati dal motore: ${f.policy_count} policy; ${f.dnat_grants || 0} autorizzazioni DNAT; ${f.vlan_count || 0} VLAN; transito senza autorizzazione bloccato; WireGuard ${f.vpn_enabled ? 'abilitata' : 'disabilitata'}; ${f.ipsec_grants || 0} tunnel IPsec abilitati; failover WAN ${f.wan_failover ? 'abilitato' : 'disabilitato'}; IPS ${f.ips_enabled ? 'abilitato' : 'disabilitato'}; antivirus HTTP ${f.http_antivirus_enabled ? 'abilitato' : 'disabilitato'}; antivirus HTTPS non disponibile.\n\nRisposta AI (può contenere errori):\n` : '';
          el('ai-answer').textContent = facts + (task.result.answer || task.result.message || '');
          aiProposal = aiDraft === null ? null : task.result.proposal;
          if (task.result.proposal && aiDraft === null) el('ai-answer').textContent += '\n\nProposta di un’altra sessione: ripeti la domanda da questa bozza per caricarla.';
          if (task.result.proposal_errors) el('ai-answer').textContent += '\n\nProposta rifiutata:\n' + task.result.proposal_errors.join('\n');
          el('ai-proposal-panel').hidden = !aiProposal;
          if (aiProposal) el('ai-proposal').textContent = JSON.stringify(aiProposal, null, 2);
        }
      }
    }
    if (swJob) {
      const data = await api('switches'), task = data.task;
      if (task?.id === swJob && task.state !== 'running') {
        swJob = null;
        el('sw-state').textContent = task.state === 'failed' ? task.error : task.result.message || 'Lettura completata.';
        if (task.state === 'succeeded' && swKind === 'preview') {
          portPlan = task.result; el('sw-warning').textContent = portPlan.warning; el('sw-phrase').textContent = portPlan.confirmation;
          el('sw-confirm-text').value = ''; el('sw-execute').disabled = true; dialog.showModal();
        }
        await refreshSwitches();
      }
    }
  }
  setInterval(() => progress().catch(error), 2000);
})();

