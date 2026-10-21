/* Regression tests for asynchronous draft ownership; no external dependencies. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
function harness() {
  const elements = new Map();
  const el = id => {
    if (!elements.has(id)) elements.set(id, { value: '', checked: false, disabled: false, hidden: false,
      append() {}, replaceChildren() {}, showModal() {}, close() {} });
    return elements.get(id);
  };
  let task = null, fail = false, calls = 0, progress;
  const nav = new Map();
  const draft = { schema: 1, marker: 'original' };
  const context = vm.createContext({
    document: { querySelector: () => el('main'), createElement: () => ({ append() {}, hidden: true }), body: { append() {} } },
    el, Option: function() {}, button: (label, fn) => { nav.set(label, fn); return {}; }, text: () => ({}),
    config: draft, pending: null, structuredClone, confirm: () => true,
    invalidate() {}, show() {}, error() {},
    setInterval: fn => { progress = fn; },
    api: async (path, data) => {
      if (path === 'assistant/ask') { calls++; if (fail) throw Error('Busy'); return { id: 'job1' }; }
      if (path === 'assistant') return { task, settings: { enabled: true, endpoint: 'http://127.0.0.1:11434', model: 'qwen3:4b' }, models: ['qwen3:4b'] };
      throw Error('Unexpected request ' + path);
    }
  });
  vm.runInContext(fs.readFileSync('src/murus_igneus/management.js', 'utf8'), context);
  return { el, context, openAI: () => nav.get('Assistente AI')(), progress: () => progress(), setTask: t => { task = t; }, fail: () => { fail = true; }, calls: () => calls };
}
const submit = h => h.el('ai-question-form').onsubmit({ preventDefault() {} });
(async () => {
  const h = harness();
  await submit(h);
  h.context.config = { schema: 1, marker: 'edited after question' };
  h.fail();
  await submit(h); // Must not replace the draft attached to job1.
  h.setTask({ id: 'job1', state: 'succeeded', result: { answer: 'Done', proposal: { schema: 1, marker: 'old proposal' } } });
  await h.progress();
  h.el('ai-use-proposal').onclick();
  assert.equal(h.context.config.marker, 'edited after question', 'An old proposal replaced a newer draft');
  assert.equal(h.calls(), 1, 'A second request was sent while a job was already owned');

  const positive = harness();
  await submit(positive);
  positive.setTask({ id: 'job1', state: 'succeeded', result: { answer: 'Done', proposal: { schema: 1, marker: 'accepted proposal' } } });
  await positive.progress();
  positive.el('ai-use-proposal').onclick();
  assert.equal(positive.context.config.marker, 'accepted proposal', 'Matching draft proposal cannot be loaded');

  const doubleClick = harness();
  await Promise.all([submit(doubleClick), submit(doubleClick)]);
  assert.equal(doubleClick.calls(), 1, 'Concurrent submissions created duplicate jobs');

  const recovered = harness();
  await submit(recovered);
  recovered.setTask({ id: 'job1', state: 'succeeded', result: { answer: 'Done', proposal: null } });
  await recovered.progress();
  recovered.setTask({ id: 'remote-job', state: 'running' });
  await recovered.openAI(); // No original draft exists in this tab for this task.
  recovered.setTask({ id: 'remote-job', state: 'succeeded', result: { answer: 'Remote', proposal: { schema: 1, marker: 'unrelated remote draft' } } });
  await recovered.progress();
  recovered.el('ai-use-proposal').onclick();
  assert.equal(recovered.context.config.marker, 'original', 'A recovered task reused another task draft identity');

  const mismatch = harness();
  await submit(mismatch);
  mismatch.setTask({ id: 'other-session', state: 'running' });
  await mismatch.progress();
  assert.equal(mismatch.el('ai-send').disabled, false, 'Lost job leaves the form locked');
  assert.match(mismatch.el('ai-state').textContent, /sessione|risultato/i);
  console.log('AI UI draft ownership and superseded task regressions passed');
})().catch(e => { console.error(e); process.exitCode = 1; });
