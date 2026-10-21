/* Real Chromium UI acceptance. System mutations disabled by loopback fixture. SPDX-License-Identifier: MIT */
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { chromium } = require(process.env.MURUS_PLAYWRIGHT || 'playwright-core');
const root = path.resolve(__dirname, '..'), checks = [];
const fixture = spawn(process.env.MURUS_PYTHON || 'python3', [path.join(__dirname, 'networking-browser-server.py')]);
let browser;
(async () => {
  const port = await new Promise((resolve, reject) => {
    let output = '';
    fixture.stdout.on('data', chunk => { output += chunk; const m = output.match(/PORT:(\d+)/); if (m) resolve(Number(m[1])); });
    fixture.stderr.on('data', data => process.stderr.write(data));
    fixture.once('exit', code => reject(Error('Fixture exited ' + code)));
  });
  browser = await chromium.launch({ headless: true, executablePath: process.env.MURUS_CHROMIUM,
    args: ['--no-sandbox', '--no-zygote', '--single-process', '--disable-dev-shm-usage', '--disable-gpu'] });
  const context = await browser.newContext({ httpCredentials: { username: 'admin', password: 'test-browser' } });
  const page = await context.newPage(), errors = [], applyRequests = [];
  page.on('pageerror', error => errors.push(String(error)));
  page.on('request', request => { if (request.url().endsWith('/api/apply')) applyRequests.push(request.url()); });
  await page.goto('http://127.0.0.1:' + port);
  await page.waitForFunction(() => !!config);
  const nav = name => page.locator('#nav').getByRole('button', { name, exact: true }).click();
  async function add(values) {
    await page.locator('#add').click();
    for (const [key, value] of Object.entries(values)) {
      const field = page.locator('#field-' + key);
      if (await field.evaluate(el => el.tagName === 'SELECT')) await field.selectOption(String(value));
      else await field.fill(String(value));
    }
    await page.locator('#edit-dialog').getByRole('button', { name: 'Salva nella bozza', exact: true }).click();
  }
  await nav('Interfacce');
  await add({ name: 'WAN', device: 'eth1', address: '192.0.2.2/24' });
  await add({ name: 'TRUNK', device: 'eth2', address: '' });
  await add({ name: 'LAN', device: 'eth2.20', address: '198.51.100.1/24', parent: 'eth2', vlan_id: 20 });
  assert.equal(await page.evaluate(() => config.interfaces[0].vlan_id), null);
  assert.equal(await page.evaluate(() => config.interfaces[2].vlan_id), 20);
  checks.push('Physical and VLAN interfaces authored in GUI with numeric tag and nullable physical tag');
  await nav('DNS e lease');
  await page.locator('#dns-enabled').check(); await page.locator('#dns-interfaces').selectOption('LAN');
  await page.locator('#dns-upstreams').fill('1.1.1.1, 9.9.9.9'); await page.locator('#dns-domain').fill('test.lan');
  await page.locator('#dns-form').getByRole('button', { name: 'Salva nella bozza' }).click();
  await nav('DHCP'); await add({ interface: 'LAN', start: '198.51.100.100', end: '198.51.100.150', lease_hours: 12, dns_servers: '' });
  assert.equal(await page.evaluate(() => config.dhcp[0].lease_hours), 12);
  assert.deepEqual(await page.evaluate(() => config.dhcp[0].dns_servers), []);
  checks.push('DNS and DHCP GUI produce complete native objects without immediate application');
  await nav('Port forwarding');
  await add({ id: '1', name: 'Web', interface: 'WAN', public_ip: '192.0.2.2', protocol: 'tcp', external_port: 8080, target_interface: 'LAN', target_ip: '198.51.100.10', target_port: 80, source: '192.0.2.0/24' });
  await nav('Verifica e applica'); await page.locator('#validate').click();
  await page.waitForFunction(() => validated === true);
  assert.match(await page.locator('#rules').textContent(), /dnat ip to 198\.51\.100\.10:80/);
  assert.match(await page.locator('#network').textContent(), /"kind": "vlan"/);
  assert.equal(await page.locator('#apply').isEnabled(), true);
  assert.equal(applyRequests.length, 0);
  checks.push('Full GUI-authored VLAN DHCP DNS DNAT draft passes real backend compiler and enables previewed application only');
  await nav('DNS e lease'); await page.locator('#leases-refresh').click();
  await page.waitForFunction(() => document.getElementById('dns-state').textContent.includes('non in esecuzione'));
  await nav('Connessioni e log'); await page.waitForFunction(() => document.getElementById('traffic-events').textContent.includes('OW dnat 1'));
  await page.locator('#traffic-filter').fill('does-not-match');
  assert.equal(await page.locator('#traffic-events').textContent(), 'Nessun evento corrispondente.');
  checks.push('DNS health, traffic page and event filtering render controlled fixture responses');
  assert.deepEqual(errors, []); checks.push('No page JavaScript exceptions');
  const target = path.join(root, 'dist/browser-networking-qa.json'); fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, JSON.stringify({ success: true, chromium: browser.version(), checks,
    scope: 'Real Chromium and real HTTP backend compiler; runtime status responses controlled, apply disabled. Packet acceptance is tested separately.' }, null, 2) + '\n');
  console.log(JSON.stringify({ success: true, chromium: browser.version(), checks }));
})().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => {
  if (browser) await browser.close(); fixture.kill('SIGTERM');
});
