/* DNS draft ownership and bounded traffic refresh behavior. SPDX-License-Identifier: MIT */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const elements = new Map(), nav = new Map(), intervals = [];
function element(id) {
  if (!elements.has(id)) elements.set(id, { value: '', checked: false, hidden: false, children: [],
    append(...nodes) { this.children.push(...nodes); }, replaceChildren(...nodes) { this.children = nodes; }, selectedOptions: [] });
  return elements.get(id);
}
let calls = [], invalidated = 0, lastPage = '', errors = [], defer = null;
const context = vm.createContext({
  document: { createElement: () => element('created' + elements.size), querySelector: () => element('main') },
  el: element, button: (name, fn) => { nav.set(name, fn); return {}; }, text: (tag, value) => ({ tag, textContent: value }),
  Option: function(label, value) { this.label = label; this.value = value; },
  config: { interfaces: [{ name: 'LAN', device: 'eth2' }], dns: { enabled: true, interfaces: ['LAN'], upstream_servers: ['1.1.1.1'], domain: 'lan' } },
  pending: null, blank: () => ({}), invalidate: () => { invalidated++; }, show: page => { lastPage = page; }, error: e => errors.push(e),
  setInterval: fn => { intervals.push(fn); },
  api: async (path, data) => {
    calls.push({ path, data });
    if (path === 'traffic') {
      if (defer) await defer;
      return { time: 1, truncated: false, errors: [], connections: [{ protocol: 'tcp', state: 'ESTABLISHED', source: '<img src=x onerror=alert(1)>', sport: '42', destination: '192.0.2.2', dport: '8080', reply_source: '198.51.100.10', reply_sport: '80', reply_destination: '192.0.2.10', reply_dport: '42', bytes: '', reply_bytes: '' }], events: [{ raw: 'OW dnat 1 source=192.0.2.10' }] };
    }
    if (path === 'network-services') return { running: false, leases: [] };
    throw Error('Unexpected API call ' + path);
  }
});
vm.runInContext(fs.readFileSync('src/murus_igneus/network.js', 'utf8'), context);
(async () => {
  nav.get('DNS e lease')();
  assert.equal(lastPage, 'dns-page'); assert.equal(element('dns-upstreams').value, '1.1.1.1');
  context.pending = { id: 'pending' };
  element('dns-domain').value = 'changed.lan';
  element('dns-form').onsubmit({ preventDefault() {} });
  assert.equal(context.config.dns.domain, 'lan'); assert.equal(invalidated, 0);
  context.pending = null; element('dns-interfaces').selectedOptions = [{ value: 'LAN' }];
  element('dns-upstreams').value = ' 1.1.1.1, 9.9.9.9, ';
  element('dns-form').onsubmit({ preventDefault() {} });
  assert.equal(context.config.dns.domain, 'changed.lan'); assert.equal(context.config.dns.upstream_servers.length, 2);
  assert.equal(lastPage, 'review-page'); assert.equal(invalidated, 1);
  assert.equal(calls.length, 0, 'Editing DNS must only change the draft');

  nav.get('Connessioni e log')(); await new Promise(resolve => setImmediate(resolve));
  assert.equal(calls.length, 1); assert.equal(element('traffic-connections').children.length, 1);
  assert.equal(element('traffic-connections').children[0].children[1].textContent, '<img src=x onerror=alert(1)>:42');
  element('traffic-filter').value = 'does-not-match'; element('traffic-filter').oninput();
  assert.equal(element('traffic-connections').children.length, 0);
  element('traffic-filter').value = '198.51.100.10'; element('traffic-filter').oninput();
  assert.equal(element('traffic-connections').children.length, 1, 'Filter should match translated destination too');
  element('traffic-auto').checked = true; element('traffic-page').hidden = true;
  intervals[0](); assert.equal(calls.length, 1, 'Hidden traffic page should not refresh');
  element('traffic-page').hidden = false;
  let release; defer = new Promise(resolve => { release = resolve; });
  const first = element('traffic-refresh').onclick(); await Promise.resolve();
  await element('traffic-refresh').onclick();
  assert.equal(calls.length, 2, 'Overlapping refresh should not create duplicate requests');
  release(); await first;
  await element('leases-refresh').onclick();
  assert.match(element('dns-state').textContent, /non in esecuzione/);
  assert.equal(errors.length, 1, 'Only the pending-configuration edit should report an error');
  console.log('DNS draft, safe traffic rendering, filters and refresh regressions passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
