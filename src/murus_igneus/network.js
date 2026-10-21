/* Native DNS and read-only traffic view. SPDX-License-Identifier: MIT */
(() => {
  function page(id, markup) {
    const section = document.createElement('section');
    section.id = id; section.className = 'page'; section.hidden = true;
    section.innerHTML = markup; document.querySelector('main').append(section);
  }
  page('dns-page', `<p class="eyebrow">SERVIZI DI RETE</p><h2>DNS locale</h2>
    <p>Cache e inoltro DNS IPv4 sulle interfacce selezionate. I client devono appartenere alla subnet locale. I nomi dei lease DHCP sono risolvibili sul servizio locale.</p>
    <form id="dns-form"><label><input type="checkbox" id="dns-enabled"> Abilita DNS</label>
    <label>Interfacce dati (Ctrl/Cmd + clic)<select id="dns-interfaces" multiple size="5"></select></label>
    <label>Resolver IPv4 a monte (separati da virgola)<input id="dns-upstreams" placeholder="1.1.1.1, 9.9.9.9"></label>
    <label>Dominio locale<input id="dns-domain" required value="lan"></label>
    <button>Salva nella bozza</button></form>
    <h3>DHCP/DNS attivo</h3><button id="leases-refresh" class="secondary">Aggiorna stato e lease</button><p id="dns-state"></p><pre id="dns-leases"></pre>`);
  page('traffic-page', `<p class="eyebrow">DIAGNOSTICA</p><h2>Connessioni e log</h2>
    <p>Campione delle sessioni IPv4 attive e degli eventi policy/DNAT nel buffer kernel. Le policy registrano eventi solo quando il log è abilitato; il limite di frequenza può ometterne alcuni. Non è uno storico completo.</p>
    <div class="actions"><button id="traffic-refresh">Aggiorna</button><label><input id="traffic-auto" type="checkbox"> Aggiorna ogni 5 secondi</label></div>
    <label>Filtra IP, porta, protocollo o ID<input id="traffic-filter" type="search"></label><p id="traffic-state" role="status"></p>
    <h3>Sessioni attive</h3><div class="table-wrap"><table><thead><tr><th>Protocollo / stato</th><th>Sorgente originale</th><th>Destinazione originale</th><th>Sorgente risposta</th><th>Destinazione risposta</th><th>Byte andata / ritorno</th></tr></thead><tbody id="traffic-connections"></tbody></table></div>
    <h3>Eventi policy e DNAT</h3><pre id="traffic-events"></pre>`);
  let latest = null, busy = false;
  el('nav').append(button('DNS e lease', () => {
    if (!config) return;
    const dns = config.dns || blank().dns;
    el('dns-enabled').checked = dns.enabled; el('dns-domain').value = dns.domain;
    el('dns-upstreams').value = dns.upstream_servers.join(', ');
    el('dns-interfaces').replaceChildren();
    for (const row of config.interfaces) { const option = new Option(row.name, row.name); option.selected = dns.interfaces.includes(row.name); el('dns-interfaces').append(option); }
    show('dns-page');
  }), button('Connessioni e log', () => { show('traffic-page'); refresh().catch(error); }));
  el('dns-form').onsubmit = event => {
    event.preventDefault(); if (pending) return error('Conferma o annulla prima la modifica pendente.');
    config.dns = { enabled: el('dns-enabled').checked, interfaces: [...el('dns-interfaces').selectedOptions].map(o => o.value),
      upstream_servers: el('dns-upstreams').value.split(',').map(s => s.trim()).filter(Boolean), domain: el('dns-domain').value.trim() };
    invalidate(); show('review-page');
  };
  el('leases-refresh').onclick = async () => {
    try { const data = await api('network-services'); el('dns-state').textContent = data.running ? 'Processo DHCP/DNS attivo' : 'Processo DHCP/DNS disabilitato o non in esecuzione';
      el('dns-leases').textContent = data.leases.length ? data.leases.map(r => `${r.address} · ${r.mac} · ${r.hostname} · scadenza ${r.expires === '0' ? 'infinita' : new Date(Number(r.expires) * 1000).toLocaleString()}`).join('\n') : 'Nessun lease registrato. I lease possono includere assegnazioni precedenti.';
    } catch (exc) { error(exc); }
  };
  function render() {
    if (!latest) return;
    const needle = el('traffic-filter').value.toLowerCase(), match = row => JSON.stringify(row).toLowerCase().includes(needle);
    el('traffic-connections').replaceChildren();
    for (const row of latest.connections.filter(match)) {
      const tr = document.createElement('tr');
      for (const value of [`${row.protocol} / ${row.state}`, `${row.source}:${row.sport}`, `${row.destination}:${row.dport}`, `${row.reply_source}:${row.reply_sport}`, `${row.reply_destination}:${row.reply_dport}`, `${row.bytes || 'n/d'} / ${row.reply_bytes || 'n/d'}`]) tr.append(text('td', value));
      el('traffic-connections').append(tr);
    }
    el('traffic-events').textContent = latest.events.filter(match).map(row => row.raw).join('\n') || 'Nessun evento corrispondente.';
  }
  async function refresh() {
    if (busy) return; busy = true;
    try { latest = await api('traffic'); el('traffic-state').textContent = `${new Date(latest.time * 1000).toLocaleTimeString()} · ${latest.connections.length} sessioni nel campione${latest.truncated ? ' · campione limitato' : ''}. ${latest.errors.join('; ')}`; render(); }
    finally { busy = false; }
  }
  el('traffic-refresh').onclick = () => refresh().catch(error); el('traffic-filter').oninput = render;
  setInterval(() => { if (!el('traffic-page').hidden && el('traffic-auto').checked) refresh().catch(error); }, 5000);
})();
