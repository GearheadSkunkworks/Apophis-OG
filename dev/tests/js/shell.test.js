'use strict';
// node --test dev/tests/js/shell.test.js
// Loads dev/ui/campaigns.js in a vm with a tiny fake DOM, tests the pure logic under OGC._test and
// drives the shell (steps, dialog, toast, api, indicators flow, compile) against a fake fetch.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SRC = fs.readFileSync(path.join(__dirname, '..', '..', 'ui', 'campaigns.js'), 'utf8');

// ---- fake DOM -----------------------------------------------------------------------------
class Node_ {
  constructor(tag) {
    this.nodeType = tag === '#text' ? 3 : 1; this.tagName = tag.toUpperCase(); this.children = [];
    this.parentNode = null; this.attributes = {}; this.listeners = {}; this.dataset = {};
    this._text = ''; this.className = ''; this.hidden = false; this.disabled = false; this.value = '';
    this.open = false; this.checked = false;
    const self = this;
    this.classList = {
      toggle(c, on) { const s = new Set(self.className.split(/\s+/).filter(Boolean)); (on === undefined ? !s.has(c) : on) ? s.add(c) : s.delete(c); self.className = [...s].join(' '); },
      contains(c) { return self.className.split(/\s+/).includes(c); }
    };
  }
  get firstChild() { return this.children[0] || null; }
  appendChild(c) { if (c.parentNode) c.parentNode.removeChild(c); c.parentNode = this; this.children.push(c); return c; }
  removeChild(c) { const i = this.children.indexOf(c); if (i >= 0) this.children.splice(i, 1); c.parentNode = null; return c; }
  insertBefore(c, ref) { if (c.parentNode) c.parentNode.removeChild(c); c.parentNode = this; const i = ref ? this.children.indexOf(ref) : -1; if (i < 0) this.children.push(c); else this.children.splice(i, 0, c); return c; }
  setAttribute(k, v) { this.attributes[k] = String(v); if (k === 'id') this.id = String(v); }
  getAttribute(k) { return this.attributes[k] === undefined ? null : this.attributes[k]; }
  addEventListener(t, fn) { (this.listeners[t] = this.listeners[t] || []).push(fn); }
  removeEventListener() {}
  fire(t, ev) { (this.listeners[t] || []).forEach(f => f(Object.assign({target: this, key: '', preventDefault() {}, stopPropagation() {}}, ev))); }
  click() { if (!this.disabled) this.fire('click'); }
  focus() { FakeDoc.activeElement = this; }
  contains(n) { for (let x = n; x; x = x.parentNode) if (x === this) return true; return false; }
  querySelector() { return null; }
  querySelectorAll() { return []; }
  set textContent(v) { this.children = []; this._text = String(v); }
  get textContent() { return this._text + this.children.map(c => c.nodeType === 3 ? c._text : c.textContent).join(''); }
  find(pred, out = []) { if (pred(this)) out.push(this); this.children.forEach(c => c.nodeType === 1 && c.find(pred, out)); return out; }
}
class TextNode extends Node_ { constructor(t) { super('#text'); this._text = t; } }
const FakeDoc = {activeElement: null};
function makeEnv(fetchImpl, o) {
  o = o || {};
  const body = new Node_('body');
  const doc = Object.assign(FakeDoc, {
    readyState: 'complete', body,
    createElement: t => new Node_(t), createTextNode: t => new TextNode(t),
    getElementById(id) { return body.find(n => n.id === id)[0] || null; },
    addEventListener(t, fn) { (doc._l = doc._l || {})[t] = fn; }, removeEventListener() {}
  });
  const root = new Node_('div'); if (!o.noUI) { root.setAttribute('id', 'ogc-root'); body.appendChild(root); }
  const fold = new Node_('details'); fold.setAttribute('id', 'ogc-fold'); body.appendChild(fold);
  const win = {console};
  const ctx = vm.createContext({window: win, document: doc, fetch: fetchImpl || (() => Promise.reject(new Error('no fetch'))),
    FileReader: class {}, setTimeout: o.realTimers ? setTimeout : (fn) => 0, clearTimeout, console, JSON, Promise, Math, Date, Object, Array, String, Number, RegExp, Error, isFinite, parseInt});
  vm.runInContext(SRC, ctx, {filename: 'campaigns.js'});
  return {OGC: win.OGC, doc, body, root, fold, win};
}
function reply(status, obj, raw) {
  return Promise.resolve({ok: status >= 200 && status < 300, status, text: () => Promise.resolve(raw !== undefined ? raw : JSON.stringify(obj))});
}
const J = (x) => JSON.parse(JSON.stringify(x));
const tick = () => new Promise(r => setImmediate(r));

// ---- pure logic ------------------------------------------------------------------------------
test('esc escapes markup characters', () => {
  const {OGC} = makeEnv();
  assert.strictEqual(OGC.esc('<img src=x onerror="a()">&\''), '&lt;img src=x onerror=&quot;a()&quot;&gt;&amp;&#39;');
  assert.strictEqual(OGC.esc(null), '');
  assert.strictEqual(OGC.esc(42), '42');
});

test('state defaults match the contract', () => {
  const {OGC} = makeEnv();
  const s = OGC.state;
  assert.deepStrictEqual(J(s.iocs), []); assert.deepStrictEqual(J(s.dropped), []);
  assert.strictEqual(s.name, ''); assert.strictEqual(s.campaign, null); assert.strictEqual(s.dirty, false);
  assert.strictEqual(s.actions, null); assert.strictEqual(s.step, 'type');
  assert.deepStrictEqual(J(s.options), {address_mode: 'mapped', start: '10:00', speed: 'realistic',
    compromised: 'ws', lateral_target: 'server', beacons_per_c2: 4,
    include: ['discovery', 'credential_access', 'lateral_movement', 'exfiltration']});
  const a = OGC._test.defaultOptions(), b = OGC._test.defaultOptions();
  a.include.push('impact'); assert.strictEqual(b.include.length, 4, 'defaults are fresh copies');
});

test('mergeIocs dedupes by type+value and keeps the highest confidence', () => {
  const {OGC} = makeEnv(); const T = OGC._test;
  const first = T.mergeIocs([], [
    {type: 'domain', value: 'Evil.Example', role: 'c2', confidence: 40, source: 'a', tags: ['x']},
    {type: 'ipv4', value: '203.0.113.9', role: 'c2', confidence: 70}]);
  assert.strictEqual(first.added, 2);
  first.list[0]._include = false;
  const second = T.mergeIocs(first.list, [
    {type: 'domain', value: 'evil.example', role: 'payload', confidence: 90, source: 'b', tags: ['y']},
    {type: 'ipv4', value: '203.0.113.9', role: 'c2', confidence: 10},
    {type: 'url', value: '203.0.113.9', role: 'c2', confidence: 10},        // same value, other type: distinct
    {type: 'domain', value: '', role: 'c2'}]);
  assert.strictEqual(second.list.length, 3);
  assert.strictEqual(second.added, 1); assert.strictEqual(second.updated, 1); assert.strictEqual(second.skipped, 2);
  const d = second.list[0];
  assert.strictEqual(d.confidence, 90); assert.strictEqual(d.source, 'b'); assert.strictEqual(d.role, 'payload');
  assert.strictEqual(d._include, false, 'include choice survives a replacement');
  assert.deepStrictEqual(J(d.tags), ['x', 'y']);
  assert.strictEqual(first.list[0].confidence, 40, 'input array records are not mutated');
});

test('a role edited by hand survives a higher-confidence duplicate', () => {
  const {OGC} = makeEnv(); const T = OGC._test;
  const m = T.mergeIocs([], [{type: 'ipv4', value: '198.51.100.1', role: 'c2', confidence: 10}]);
  m.list[0].role = 'scanner'; m.list[0]._roleEdited = true;
  const n = T.mergeIocs(m.list, [{type: 'ipv4', value: '198.51.100.1', role: 'c2', confidence: 80}]);
  assert.strictEqual(n.list[0].role, 'scanner'); assert.strictEqual(n.list[0].confidence, 80);
});

test('normaliseIoc clamps confidence and unknown roles', () => {
  const {OGC} = makeEnv(); const n = OGC._test.normaliseIoc({type: 'ipv4', value: 1, role: 'bogus', confidence: 250});
  assert.strictEqual(n.role, 'unknown'); assert.strictEqual(n.confidence, 100); assert.strictEqual(n.value, '1');
});

test('filterIocs by role, type and text; countsByRole', () => {
  const {OGC} = makeEnv(); const T = OGC._test;
  const l = [{type: 'ipv4', value: '1.2.3.4', role: 'c2', source: 'feodo', why: 'listed', tags: []},
             {type: 'domain', value: 'a.example', role: 'phishing', source: 'openphish', why: 'url', tags: ['kit']},
             {type: 'domain', value: 'b.example', role: 'c2', source: 'otx', why: 'pulse', tags: []}];
  assert.strictEqual(T.filterIocs(l, {role: 'c2'}).length, 2);
  assert.strictEqual(T.filterIocs(l, {type: 'domain'}).length, 2);
  assert.strictEqual(T.filterIocs(l, {role: 'c2', type: 'domain'}).length, 1);
  assert.strictEqual(T.filterIocs(l, {text: 'KIT'}).length, 1, 'text matches tags, case-insensitive');
  assert.strictEqual(T.filterIocs(l, {}).length, 3);
  const c = T.countsByRole(l); assert.strictEqual(c.c2, 2); assert.strictEqual(c.phishing, 1); assert.strictEqual(c.tor, 0);
});

test('includedIocs sends only included records without UI-only fields', () => {
  const {OGC} = makeEnv(); const T = OGC._test;
  const m = T.mergeIocs([], [{type: 'ipv4', value: '1.1.1.1', role: 'c2', confidence: 1}, {type: 'ipv4', value: '2.2.2.2', role: 'c2', confidence: 1}]);
  m.list[1]._include = false; m.list[0]._roleEdited = true;
  const out = T.includedIocs(m.list);
  assert.strictEqual(out.length, 1); assert.strictEqual(out[0].value, '1.1.1.1');
  assert.ok(Object.keys(out[0]).every(k => k[0] !== '_'));
});

test('emptyCampaign is valid-shaped and independent of state options', () => {
  const {OGC} = makeEnv(); const T = OGC._test;
  const c = T.emptyCampaign(OGC.state);
  assert.strictEqual(c.schema, 'opengenerator.campaign/1');
  assert.deepStrictEqual(J([c.iocs, c.stages, c.expect]), [[], [], []]);
  assert.strictEqual(c.meta.name, 'Untitled campaign'); assert.strictEqual(c.meta.id, 'untitled-campaign');
  assert.match(c.meta.created, /^\d{4}-\d\d-\d\d$/);
  assert.strictEqual(c.options.address_mode, 'mapped');
  c.options.include.push('impact'); assert.strictEqual(OGC.state.options.include.length, 4);
  OGC.state.name = 'My  Test/Run!'; assert.strictEqual(T.emptyCampaign(OGC.state).meta.id, 'my-test-run');
});

test('fileSizeWarning triggers above 1 MB only', () => {
  const {OGC} = makeEnv();
  assert.strictEqual(OGC._test.fileSizeWarning(1048576), '');
  assert.match(OGC._test.fileSizeWarning(1048577 * 3), /3\.0 MB/);
});

// ---- el ----------------------------------------------------------------------------------------
test('el never interprets data as markup and handles attrs/children', () => {
  const {OGC} = makeEnv(); let clicked = 0;
  const n = OGC.el('div', {'class': 'a b', title: '<x>', dataset: {k: 1}, disabled: true, onclick: () => clicked++},
    '<script>alert(1)</script>', 5, null, [OGC.el('span', {}, 'in')]);
  assert.strictEqual(n.className, 'a b'); assert.strictEqual(n.getAttribute('title'), '<x>'); assert.strictEqual(n.dataset.k, '1');
  assert.strictEqual(n.disabled, true);
  assert.strictEqual(n.textContent, '<script>alert(1)</script>5in');
  assert.strictEqual(n.children.filter(c => c.tagName === 'SCRIPT').length, 0);
  n.click(); assert.strictEqual(clicked, 0, 'disabled click is ignored by the fake');
});

// ---- api ----------------------------------------------------------------------------------------
test('api maps {"error"}, 404 and bad JSON to Error messages', async () => {
  const q = [() => reply(400, {error: 'Bad thing.'}), () => reply(404, null, 'nope'), () => reply(200, null, '<html>'), () => reply(200, {ok: 1})];
  const calls = [];
  const {OGC} = makeEnv((url, opts) => { calls.push([url, opts]); return q.shift()(); }, {noUI: true});
  await assert.rejects(OGC.api.get('/x'), e => e.message === 'Bad thing.' && e.status === 400);
  await assert.rejects(OGC.api.get('/x'), e => /not available/.test(e.message) && e.status === 404);
  await assert.rejects(OGC.api.post('/x', {a: 1}), e => /not valid JSON/.test(e.message));
  assert.deepStrictEqual(await OGC.api.post('/y', {k: 'v'}), {ok: 1});
  assert.strictEqual(calls[3][1].method, 'POST'); assert.strictEqual(calls[3][1].body, '{"k":"v"}');
  assert.strictEqual(calls[3][1].headers['Content-Type'], 'application/json');
});

test('api reports a network failure plainly', async () => {
  const {OGC} = makeEnv(() => Promise.reject(new TypeError('x')));
  await assert.rejects(OGC.api.get('/x'), e => /Could not reach/.test(e.message));
});

// ---- events, steps, dialog, toast ---------------------------------------------------------------
test('on/emit isolates listener faults and off works', () => {
  const {OGC} = makeEnv(); let n = 0;
  const off = OGC.on('e', () => { throw new Error('boom'); }); OGC.on('e', d => { n += d; });
  const real = console.error; console.error = () => {};
  OGC.emit('e', 2); off(); OGC.emit('e', 3); console.error = real;
  assert.strictEqual(n, 5);
});

test('init mounts steps 1-2, stepper greys unregistered steps, goto and canLeave', async () => {
  const {OGC, root} = makeEnv(() => reply(200, {feeds: [], actions: []}));
  const steps = root.find(n => n.className.split(' ').includes('ogc-step'));
  assert.strictEqual(steps.length, 4);
  assert.deepStrictEqual(steps.map(b => b.disabled), [false, false, true, true]);
  const seen = []; OGC.on('step', d => seen.push(d.step));
  assert.strictEqual(await OGC.goto('indicators'), true);
  assert.strictEqual(OGC.state.step, 'indicators'); assert.deepStrictEqual(seen, ['indicators']);
  assert.strictEqual(await OGC.goto('build'), false, 'unregistered step is refused');
  // register a step that refuses to be left, answer the dialog with Escape
  let entered = 0, mounted = 0;
  OGC.registerStep({id: 'build', title: 'Build', mount() { mounted++; }, onEnter() { entered++; }, canLeave: () => 'You have unsaved edits.'});
  assert.strictEqual(mounted, 1);
  await OGC.goto('build'); assert.strictEqual(entered, 1);
  const p = OGC.goto('indicators');
  const backdrop = FakeDoc.body.children.find(c => c.className === 'ogc-dialog-backdrop');
  assert.ok(backdrop, 'a warning dialog is shown (no alert/confirm)');
  // choose "Leave anyway"
  const btns = backdrop.find(n => n.tagName === 'BUTTON'); assert.deepStrictEqual(btns.map(b => b.textContent), ['Stay', 'Leave anyway']);
  btns[1].click();
  assert.strictEqual(await p, true); assert.strictEqual(OGC.state.step, 'indicators');
  assert.strictEqual(FakeDoc.body.children.some(c => c.className === 'ogc-dialog-backdrop'), false, 'dialog removed');
});

test('dialog resolves with the button value and restores focus', async () => {
  const {OGC, body} = makeEnv(); const opener = new Node_('button'); body.appendChild(opener); opener.focus();
  const p = OGC.dialog({title: 'T <b>', body: 'Hello', buttons: [{label: 'Yes', value: 'y', kind: 'danger'}, {label: 'No', value: 'n'}]});
  assert.strictEqual(p.buttons.length, 2); assert.ok(p.el.getAttribute('aria-modal') === 'true');
  p.buttons[1].click();
  assert.strictEqual(await p, 'n'); assert.strictEqual(FakeDoc.activeElement, opener);
  const p2 = OGC.dialog({title: 'x'}); p2.close('v'); assert.strictEqual(await p2, 'v');
  const p3 = OGC.dialog({title: 'x'}); p3.close(); assert.strictEqual(await p3, null);
});

test('toast writes text into one aria-live region', () => {
  const {OGC, body} = makeEnv();
  OGC.toast('<b>hi</b>', 'error'); OGC.toast('two', 'ok');
  const region = body.children.find(c => c.className === 'ogc-toasts');
  assert.strictEqual(region.getAttribute('aria-live'), 'polite'); assert.strictEqual(region.children.length, 2);
  assert.strictEqual(region.children[0].textContent, '<b>hi</b>');
  assert.match(region.children[0].className, /ogc-toast-error/);
});

test('setCampaign sets state, dirty flag and emits', () => {
  const {OGC} = makeEnv(); const got = [];
  OGC.on('campaign', d => got.push(d));
  OGC.setCampaign({schema: 's'}, {source: 'compile', explain: ['a']});
  assert.strictEqual(OGC.state.dirty, false); assert.deepStrictEqual(Array.from(OGC.state.explain), ['a']);
  OGC.setCampaign({schema: 's'}, {source: 'edit'});
  assert.strictEqual(OGC.state.dirty, true); assert.strictEqual(got.length, 2); assert.strictEqual(got[1].source, 'edit');
});

test('generateExtras defaults to {} and is overridable', () => {
  const {OGC} = makeEnv();
  assert.deepStrictEqual(J(OGC.generateExtras()), {});
  OGC.generateExtras = () => ({campaigns: []}); assert.deepStrictEqual(J(OGC.generateExtras()), {campaigns: []});
  assert.strictEqual(typeof OGC.renderResults, 'undefined', 'defined by the library module');
});

test('actions catalog loads lazily once and emits "actions"; failure is tolerated', async () => {
  let n = 0;
  const {OGC} = makeEnv(() => { n++; return reply(200, {actions: [{token: 't'}], tactics: []}); }, {noUI: true});
  let ev = 0; OGC.on('actions', () => ev++);
  const [a, b] = await Promise.all([OGC.loadActions(), OGC.loadActions()]);
  assert.strictEqual(n, 1); assert.strictEqual(ev, 1); assert.strictEqual(a, b); assert.strictEqual(OGC.state.actions.actions[0].token, 't');
  const env2 = makeEnv(() => reply(404, null, ''), {noUI: true});
  assert.strictEqual(await env2.OGC.loadActions(), null); assert.strictEqual(env2.OGC.state.actions, null);
});

// ---- indicators flow end to end against a fake server --------------------------------------------
test('indicators step: feeds list, key never sent unless typed, parse merge, compile goes to build', async () => {
  const sent = [];
  const server = (url, opts) => {
    const body = opts && opts.body ? JSON.parse(opts.body) : null; sent.push([url, body]);
    if (url === '/api/intel/feeds') return reply(200, {feeds: [
      {id: 'otx', title: 'OTX', group: 'Community', needs_key: true, key_env: 'OTX_KEY', note: 'n'},
      {id: 'urlhaus', title: 'URLhaus', group: 'abuse.ch', needs_key: false, note: ''}]});
    if (url === '/api/intel/parse') return reply(200, {iocs: [
      {type: 'domain', value: 'x.example', role: 'c2', confidence: 50, source: 'paste', why: 'w'},
      {type: 'ipv4', value: '203.0.113.5', role: 'payload', confidence: 60, source: 'paste', why: 'w'}],
      count: 2, dropped: [{value: '10.0.0.1', reason: 'private address'}], formats: 'text'});
    if (url === '/api/intel/fetch') return reply(200, {iocs: [{type: 'ipv4', value: '203.0.113.5', role: 'c2', confidence: 99, source: 'otx', why: 'w2'}], count: 1, dropped: [], error: null});
    if (url === '/api/campaign/compile') return reply(200, {campaign: {schema: 'opengenerator.campaign/1', stages: [1], iocs: [1], meta: {}}, explain: ['ioc 0 -> s1'], errors: [], summary: {stages: 1, actions: 2, iocs: 2, skipped: 0}});
    return reply(404, null, '');
  };
  const {OGC, root} = makeEnv(server);
  OGC.registerStep({id: 'build', title: 'Build', mount() {}});
  await OGC.goto('indicators'); await tick(); await tick();
  const byText = (t) => root.find(n => n.tagName === 'BUTTON' && n.textContent === t)[0];
  const paste = root.find(n => n.tagName === 'TEXTAREA')[0];
  // feeds rendered: OTX has a masked key input, an extra From a URL row exists
  const pw = root.find(n => n.tagName === 'INPUT' && n.getAttribute('type') === 'password');
  assert.strictEqual(pw.length, 1);
  assert.ok(root.find(n => n.className === 'ogc-feed-title' && n.textContent === 'From a URL').length === 1);
  // OTX fetch without a key is refused client-side, nothing sent
  const fetchBtns = root.find(n => n.tagName === 'BUTTON' && n.textContent === 'Fetch 50');
  const otxBtn = fetchBtns.find(b => b.parentNode.textContent.includes('OTX'));
  const before = sent.length; otxBtn.click(); assert.strictEqual(sent.length, before);
  // paste + add
  paste.value = 'x.example\n203.0.113.5'; byText('Add pasted indicators').click(); await tick(); await tick();
  assert.strictEqual(OGC.state.iocs.length, 2); assert.strictEqual(OGC.state.dropped.length, 1);
  const parse = sent.find(s => s[0] === '/api/intel/parse'); assert.deepStrictEqual(parse[1], {text: 'x.example\n203.0.113.5', filename: '', source: 'paste'});
  // type a key, fetch: higher confidence duplicate replaces
  pw[0].value = 'SECRET'; pw[0].fire('input'); otxBtn.click(); await tick(); await tick();
  const f = sent.find(s => s[0] === '/api/intel/fetch'); assert.strictEqual(f[1].key, 'SECRET'); assert.strictEqual(f[1].feed, 'otx');
  assert.strictEqual(OGC.state.iocs.length, 2); assert.strictEqual(OGC.state.iocs.find(i => i.type === 'ipv4').confidence, 99);
  assert.ok(!JSON.stringify(OGC.state).includes('SECRET'), 'key is not kept in state');
  // table rendered with the values as text
  const cells = root.find(n => n.tagName === 'TD' && n.className === 'ogc-value').map(n => n.textContent).sort();
  assert.deepStrictEqual(cells, ['203.0.113.5', 'x.example']);
  // deselect one, compile sends only the included one, then goes to build
  const row0 = root.find(n => n.tagName === 'INPUT' && n.getAttribute('type') === 'checkbox' && /^Use /.test(n.getAttribute('aria-label') || ''))[0];
  row0.checked = false; row0.fire('change');
  byText('Compile campaign').click(); await tick(); await tick();
  const comp = sent.find(s => s[0] === '/api/campaign/compile');
  assert.strictEqual(comp[1].iocs.length, 1); assert.ok(Object.keys(comp[1].iocs[0]).every(k => k[0] !== '_'));
  assert.strictEqual(comp[1].options.address_mode, 'mapped');
  assert.strictEqual(OGC.state.campaign.stages.length, 1); assert.strictEqual(OGC.state.step, 'build');
  assert.deepStrictEqual(Array.from(OGC.state.explain), ['ioc 0 -> s1']);
});

// ---- optional Keychain storage for feed keys ----------------------------------------------------
test('indicators step: Keychain option appears only when available; saved key is used server-side', async () => {
  for (const available of [false, true]) {
    const sent = []; let stored = [];
    const server = (url, opts) => {
      const body = opts && opts.body ? JSON.parse(opts.body) : null; sent.push([url, body]);
      if (url === '/api/keys/status') return reply(200, {available, stored: stored.slice()});
      if (url === '/api/keys/save') { stored.push(body.id); return reply(200, {ok: true}); }
      if (url === '/api/keys/forget') { stored = stored.filter(x => x !== body.id); return reply(200, {ok: true}); }
      if (url === '/api/intel/feeds') return reply(200, {feeds: [{id: 'otx', title: 'OTX', group: 'Community', needs_key: true, key_env: 'OTX_KEY', note: 'n'}]});
      if (url === '/api/intel/fetch') return reply(200, {iocs: [], count: 0, dropped: [], error: null});
      return reply(404, null, '');
    };
    const {OGC, root} = makeEnv(server);
    OGC.registerStep({id: 'build', title: 'Build', mount() {}});
    await OGC.goto('indicators'); for (let i = 0; i < 6; i++) await tick();
    const rem = () => root.find(n => n.tagName === 'INPUT' && n.getAttribute('type') === 'checkbox' && /Keychain/.test(n.getAttribute('aria-label') || ''));
    const text = () => root.textContent;
    assert.strictEqual(rem().length, available ? 1 : 0);
    assert.ok(!/Remember in the macOS Keychain/.test(text()) === !available);
    if (!available) continue;
    const pw = root.find(n => n.tagName === 'INPUT' && n.getAttribute('type') === 'password')[0];
    const otxBtn = root.find(n => n.tagName === 'BUTTON' && n.textContent === 'Fetch 50')[0];
    pw.value = 'SECRET'; pw.fire('input'); rem()[0].checked = true;
    otxBtn.click(); for (let i = 0; i < 8; i++) await tick();
    const save = sent.find(s => s[0] === '/api/keys/save');
    assert.deepStrictEqual(save[1], {id: 'feed:otx', key: 'SECRET'});
    assert.strictEqual(sent.find(s => s[0] === '/api/intel/fetch')[1].key, 'SECRET');
    // now stored: field emptied, label shown, next fetch sends use_stored and no key
    assert.strictEqual(pw.value, ''); assert.ok(/Using the saved key/.test(text())); assert.strictEqual(rem().length, 0);
    sent.length = 0;
    otxBtn.click(); for (let i = 0; i < 6; i++) await tick();
    const f2 = sent.find(s => s[0] === '/api/intel/fetch')[1];
    assert.strictEqual(f2.use_stored, true); assert.ok(!f2.key); assert.ok(!JSON.stringify(f2).includes('SECRET'));
    // Forget returns to the checkbox
    root.find(n => n.tagName === 'BUTTON' && n.textContent === 'Forget')[0].click();
    for (let i = 0; i < 6; i++) await tick();
    assert.deepStrictEqual(sent.find(s => s[0] === '/api/keys/forget')[1], {id: 'feed:otx'});
    assert.strictEqual(rem().length, 1); assert.ok(!/Using the saved key/.test(text()));
    assert.ok(!JSON.stringify(OGC.state).includes('SECRET'));
  }
});

test('table caps rendering at 500 rows with a show-more control', async () => {
  const many = []; for (let i = 0; i < 1200; i++) many.push({type: 'ipv4', value: '203.0.' + (i >> 8) + '.' + (i & 255), role: 'c2', confidence: 5, source: 's', why: 'w'});
  const {OGC, root} = makeEnv((url) => url === '/api/intel/feeds' ? reply(200, {feeds: []}) : reply(200, {iocs: many, dropped: []}));
  await OGC.goto('indicators'); await tick();
  root.find(n => n.tagName === 'TEXTAREA')[0].value = 'x';
  root.find(n => n.tagName === 'BUTTON' && n.textContent === 'Add pasted indicators')[0].click(); await tick(); await tick();
  assert.strictEqual(OGC.state.iocs.length, 1200);
  assert.strictEqual(root.find(n => n.tagName === 'TD' && n.className === 'ogc-value').length, 500);
  const more = root.find(n => n.tagName === 'BUTTON' && /^Show more/.test(n.textContent))[0];
  more.click(); assert.strictEqual(root.find(n => n.tagName === 'TD' && n.className === 'ogc-value').length, 1000);
});

test('indicator cards, traffic preview toggle and the plan summary', async () => {
  const ioc = {type: 'ipv4', value: '203.0.113.9', role: 'c2', confidence: 5, source: 's', why: 'w',
    card: {what: '203.0.113.9 IP address: a command-and-control server', traffic: 'Sends: repeated beacons.'}};
  const calls = [];
  const {OGC, root} = makeEnv((url, body) => {
    calls.push(url);
    if (url === '/api/intel/feeds') return reply(200, {feeds: []});
    if (url === '/api/campaign/preview') return reply(200, {observable: true, actions: [{title: 'HTTPS beacon', protocols: ['TLS'], from: 'ws', to: 'c2:0', summary: 'Beacons.'}]});
    if (url === '/api/campaign/observability') return reply(200, {observability: [], plan: [{name: 'Execution', narrative: 'the payload runs', actions: 1}, {name: 'Discovery', narrative: 'the operator looks around', actions: 3}]});
    return reply(200, {iocs: [ioc], dropped: []});
  }, {realTimers: true});
  await OGC.goto('indicators'); await tick();
  root.find(n => n.tagName === 'TEXTAREA')[0].value = 'x';
  root.find(n => n.tagName === 'BUTTON' && n.textContent === 'Add pasted indicators')[0].click(); await tick(); await tick();
  assert.ok(root.find(n => n.tagName === 'DIV' && n.textContent === ioc.card.what).length >= 1, 'card text is shown');
  assert.ok(root.find(n => n.tagName === 'DIV' && n.textContent === ioc.card.traffic).length >= 1);
  const btn = root.find(n => n.tagName === 'BUTTON' && n.textContent === 'Preview traffic')[0];
  btn.click(); await tick(); await tick();
  assert.ok(calls.includes('/api/campaign/preview'));
  assert.ok(root.find(n => n.tagName === 'DIV' && /^HTTPS beacon \(TLS\): ws to c2:0/.test(n.textContent)).length === 1);
  await new Promise(r => setTimeout(r, 700)); await tick();
  assert.ok(calls.includes('/api/campaign/observability'));
  assert.ok(root.find(n => n.tagName === 'DIV' && n.textContent === 'This selection will build 2 stages:').length === 1);
  assert.ok(root.find(n => n.tagName === 'DIV' && /^Discovery \(3 actions\): the operator looks around/.test(n.textContent)).length === 1);
});

test('step 1: start from scratch and open a saved campaign', async () => {
  const {OGC, root} = makeEnv(() => reply(200, {}));
  OGC.registerStep({id: 'build', title: 'Build', mount() {}});
  OGC.registerStep({id: 'save', title: 'Save & run', mount() {}});
  root.find(n => n.tagName === 'BUTTON' && n.textContent === 'Open the library')[0].click(); await tick();
  assert.strictEqual(OGC.state.step, 'save'); assert.strictEqual(OGC.state.intent, 'open');
  await OGC.goto('type');
  root.find(n => n.tagName === 'BUTTON' && n.textContent === 'Start empty')[0].click(); await tick();
  assert.strictEqual(OGC.state.step, 'build'); assert.strictEqual(OGC.state.campaign.schema, 'opengenerator.campaign/1');
  assert.strictEqual(OGC.state.dirty, false);
});

test('a template loads its indicators and sets the goal options', async () => {
  const cat = {goals: [{id: 'balanced', title: 'Balanced', plain: 'Default.', options: {}},
                       {id: 'c2-beaconing', title: 'C2 only', plain: 'Only the command channel.', options: {include: [], beacons_per_c2: 12}}],
               templates: [{id: 'beacon-only', title: 'Beacon-only test', goal: 'c2-beaconing', plain: 'Two servers.',
                            iocs: [{type: 'ipv4', value: '203.0.113.13', role: 'c2', confidence: 80, source: 'template', why: 'template command server'}]}]};
  const {OGC, root} = makeEnv((url) => url === '/api/intel/feeds' ? reply(200, {feeds: []}) :
    url === '/api/campaign/templates' ? reply(200, cat) : reply(200, {observability: [], plan: []}));
  await OGC.goto('indicators'); await tick(); await tick();
  const tpl = root.find(n => n.tagName === 'SELECT' && n.id === 'ogc-tpl')[0];
  assert.ok(!tpl.disabled);
  assert.strictEqual(root.find(n => n.tagName === 'SELECT' && n.id === 'ogc-goal')[0].children.length, 2);
  tpl.value = 'beacon-only'; tpl.fire('change');
  assert.strictEqual(OGC.state.iocs.length, 1);
  assert.strictEqual(OGC.state.iocs[0].value, '203.0.113.13');
  assert.deepStrictEqual(OGC.state.options.include, []);
  assert.strictEqual(OGC.state.options.beacons_per_c2, 12);
  assert.strictEqual(OGC.state.name, 'Beacon-only test');
});
