/* Original local AI and SNMP management UI. SPDX-License-Identifier: MIT */
(() => {
  const container = document.querySelector('main');
  const page = (id, markup) => {
    const section = document.createElement('section');
    section.id = id; section.className = 'page'; section.hidden = true;
    section.innerHTML = markup; container.append(section);
  };
  page('assistant-page', `
    <p class="eyebrow">ASSISTENTE LOCALE</p><h2>AI per la tua rete</h2>
    <p>Analizza la bozza e la telemetria degli switch. Le proposte passano nell’editor e richiedono verifica e conferma.</p>
    <aside>Serve Ollama con un modello Qwen3 già installato, sul firewall o su un server della LAN.
    Il modello non è incluso nella ISO. Configura il server in modalità solo locale.
    La bozza, la domanda e la telemetria saranno inviate all’indirizzo qui indicato.</aside>
    <form id="ai-settings"><label><input id="ai-enabled" type="checkbox"> Abilita assistente</label>
      <label>Server Ollama (IPv4 privato)<input id="ai-endpoint" required placeholder="http://192.168.10.10:11434"></label>
      <label>Modello locale<select id="ai-model"></select></label>
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
  const dialog = document.createElement('dialog');
  dialog.id = 'sw-confirm-dialog';
  dialog.innerHTML = `<form id="sw-confirm-form"><h3>Conferma modifica porta</h3><p id="sw-warning"></p><p>Scrivi esattamente: <strong id="sw-phrase"></strong></p><label>Conferma<input id="sw-confirm-text" autocomplete="off"></label><div class="actions"><button id="sw-execute" disabled>Esegui sullo switch</button><button type="button" id="sw-dismiss" class="secondary">Annulla</button></div></form>`;
  document.body.append(dialog);

  let aiJob = null, aiKind = '', aiProposal = null, aiDraft = null, swJob = null, swKind = '', selected = null, devices = [], portPlan = null;
  function aiSettings(data) {
    el('ai-enabled').checked = data.settings.enabled; el('ai-endpoint').value = data.settings.endpoint;
    el('ai-model').replaceChildren(...data.models.map(m => new Option(m, m)));
    el('ai-model').value = data.settings.model;
  }
  async function openAI() {
    const data = await api('assistant'); aiSettings(data); show('assistant-page');
    if (data.task?.state === 'running') {
      aiJob = data.task.id; aiKind = 'ask'; el('ai-state').textContent = 'Elaborazione in corso…';
    }
  }
  el('nav').append(button('Assistente AI', () => openAI().catch(error)), button('Switch locali', () => { show('switches-page'); refreshSwitches().catch(error); }));
  el('ai-settings').onsubmit = async e => {
    e.preventDefault(); try {
      await api('assistant/settings', { enabled: el('ai-enabled').checked, endpoint: el('ai-endpoint').value.trim(), model: el('ai-model').value });
      el('ai-connection').textContent = 'Impostazioni salvate. Verifica la disponibilità del modello.';
    } catch (exc) { error(exc); }
  };
  el('ai-check').onclick = async () => {
    try { const task = await api('assistant/check', {}); aiJob = task.id; aiKind = 'check'; el('ai-connection').textContent = 'Verifica in corso…'; } catch (exc) { error(exc); }
  };
  el('ai-question-form').onsubmit = async e => {
    e.preventDefault(); try {
      aiDraft = JSON.stringify(config); aiProposal = null; el('ai-proposal-panel').hidden = true;
      const task = await api('assistant/ask', { question: el('ai-question').value, configuration: config, include_logs: el('ai-logs').checked, allow_proposal: el('ai-allow-proposal').checked });
      aiJob = task.id; aiKind = 'ask'; el('ai-state').textContent = 'Il modello locale sta elaborando…'; el('ai-answer').textContent = ''; el('ai-send').disabled = true;
    } catch (exc) { error(exc); }
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
    if (aiJob) {
      const data = await api('assistant'), task = data.task;
      if (task?.id === aiJob && task.state !== 'running') {
        aiJob = null; el('ai-send').disabled = false;
        if (task.state === 'failed') { el('ai-state').textContent = task.error; el('ai-connection').textContent = task.error; }
        else if (aiKind === 'check') el('ai-connection').textContent = task.result.message;
        else {
          el('ai-state').textContent = 'Risposta AI: controlla le indicazioni prima di usarle. Nessuna modifica applicata.';
          const f = task.result.facts;
          const facts = f ? `Dati della bozza verificati dal motore: ${f.policy_count} policy; transito senza corrispondenza bloccato; VPN ${f.vpn_enabled ? 'abilitata' : 'disabilitata'}; IPS ${f.ips_enabled ? 'abilitato' : 'disabilitato'}; antivirus HTTP ${f.http_antivirus_enabled ? 'abilitato' : 'disabilitato'}; antivirus HTTPS non disponibile.\n\nRisposta AI (può contenere errori):\n` : '';
          el('ai-answer').textContent = facts + (task.result.answer || task.result.message || '');
          aiProposal = task.result.proposal;
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
