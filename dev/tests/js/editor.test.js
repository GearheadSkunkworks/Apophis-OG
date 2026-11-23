'use strict';
// node --test dev/tests/js/editor.test.js
const test = require('node:test');
const plain = (x) => JSON.parse(JSON.stringify(x));
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

/* ---- minimal fake DOM, enough to run mount/render and look at the result ---- */
class El {
  constructor(tag) { this.tagName = tag.toUpperCase(); this.children = []; this.attrs = {}; this.listeners = {}; this.style = {}; this.className = ''; this._text = ''; this.value = ''; this.parentNode = null; this.checked = false; }
  get firstChild() { return this.children[0] || null; }
  appendChild(c) { if (c.parentNode) c.parentNode.removeChild(c); c.parentNode = this; this.children.push(c); return c; }
  insertBefore(c, ref) { c.parentNode = this; const i = ref ? this.children.indexOf(ref) : -1; if (i < 0) this.children.push(c); else this.children.splice(i, 0, c); return c; }
  removeChild(c) { const i = this.children.indexOf(c); if (i >= 0) this.children.splice(i, 1); c.parentNode = null; return c; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  hasAttribute(k) { return k in this.attrs; }
  removeAttribute(k) { delete this.attrs[k]; }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  fire(t, ev) { (this.listeners[t] || []).forEach((f) => f(ev || {})); }
  focus() { this.focused = true; }
  set textContent(v) { this.children = []; this._text = String(v); }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
  all() { let out = []; this.children.forEach((c) => { if (c instanceof El) { out.push(c); out = out.concat(c.all()); } }); return out; }
  querySelector(sel) { const m = /^\[data-fk="(.*)"\]$/.exec(sel); return m ? this.all().find((e) => e.attrs['data-fk'] === m[1]) || null : null; }
}
class Text { constructor(t) { this._text = t; this.parentNode = null; } get textContent() { return this._text; } }

function load(opts) {
  opts = opts || {};
  const handlers = {};
  const calls = [];
  const steps = {};
  const head = new El('head'), body = new El('body');
  const doc = { createElement: (t) => new El(t), createTextNode: (t) => new Text(t), head, body, activeElement: null,
                getElementById: (id) => head.children.find((c) => c.id === id) || null };
  const OGC = {
    state: { campaign: null, actions: opts.actions || null, explain: ['IOC 1 -> s1 -> https_beacon'], dirty: false },
    api: {
      get: (p) => { calls.push(['GET', p]); return opts.get ? opts.get(p) : Promise.reject(new Error('no endpoint')); },
      post: (p, b) => { calls.push(['POST', p, b]); return opts.post ? opts.post(p, b) : Promise.reject(new Error('no endpoint')); }
    },
    on: (e, f) => { (handlers[e] = handlers[e] || []).push(f); },
    emit: (e, d) => (handlers[e] || []).forEach((f) => f(d)),
    setCampaign(c, o) { this.state.campaign = c; this.emit('campaign', o); },
    registerStep: (s) => { steps[s.id] = s; },
    goto: () => {}
  };
  const win = { OGC, document: doc };
  const ctx = vm.createContext({ window: win, document: doc, console, setTimeout, clearTimeout, JSON, Math, Object, Array, String, Number, isFinite, parseInt, Promise, Date });
  vm.runInContext(fs.readFileSync(path.join(__dirname, '..', '..', 'ui', 'campaigns-editor.js'), 'utf8'), ctx, { filename: 'campaigns-editor.js' });
  return { OGC, T: OGC._test.editor, steps, calls, doc, body };
}

const { T } = load();

const CATALOG = {
  actions: [
    { token: 'https_beacon', title: 'HTTPS beacon', tactic: 'command-and-control', techniques: ['T1071.001'], protocols: ['TLS'], summary: 'Periodic TLS beacons.', params: { count: { type: 'int', default: 4, help: 'beacons' }, jitter: { type: 'float', default: 0.1, help: '' }, ua: { type: 'str', default: 'x', help: '' }, flag: { type: 'bool', default: false, help: '' }, ports: { type: 'list', default: [443], help: '' } }, src: 'internal', dst: 'external', needs: [], ot: false },
    { token: 'wmi_exec', title: 'WMI', tactic: 'lateral-movement', techniques: ['T1047'], protocols: ['DCERPC'], summary: 's', params: {}, src: 'internal', dst: 'internal', needs: ['FILE1'], ot: false }
  ],
  tactics: [{ slug: 'execution', name: 'Execution', id: 'TA0002' }, { slug: 'command-and-control', name: 'Command and Control', id: 'TA0011' }, { slug: 'lateral-movement', name: 'Lateral Movement', id: 'TA0008' }]
};

test('nextStageId is unique and monotonic', () => {
  assert.strictEqual(T.nextStageId([]), 's1');
  assert.strictEqual(T.nextStageId([{ id: 's1' }, { id: 's3' }]), 's4');
  assert.strictEqual(T.nextStageId([{ id: 'custom' }, { id: 's1' }]), 's2');
});

test('stage add, duplicate, move, remove', () => {
  const c = T.blankCampaign('x');
  T.addStage(c, 'execution', CATALOG.tactics);
  T.addStage(c, 'command-and-control', CATALOG.tactics);
  assert.deepStrictEqual(plain(c.stages.map((s) => s.id)), ['s1', 's2']);
  assert.strictEqual(c.stages[1].name, 'Command and Control');
  T.addAction(c, 0, { action: 'a', from: 'ws', to: 'server' });
  assert.strictEqual(T.duplicateStage(c, 0), 1);
  assert.deepStrictEqual(plain(c.stages.map((s) => s.id)), ['s1', 's3', 's2']);
  assert.strictEqual(c.stages[1].name, 'Execution (copy)');
  c.stages[1].actions[0].from = 'dc';
  assert.strictEqual(c.stages[0].actions[0].from, 'ws', 'duplicate is a deep copy');
  assert.strictEqual(T.moveItem(c.stages, 0, -1), -1);
  assert.strictEqual(T.moveItem(c.stages, 0, 1), 1);
  assert.deepStrictEqual(plain(c.stages.map((s) => s.id)), ['s3', 's1', 's2']);
  c.expect = [{ technique: 'T1', stage: 's1' }, { technique: 'T2', stage: 's2' }];
  assert.ok(T.removeStage(c, 1));
  assert.deepStrictEqual(plain(c.expect.map((e) => e.stage)), ['s2'], 'expect entries for the removed stage are dropped');
  assert.strictEqual(T.removeStage(c, 9), false);
  assert.strictEqual(T.addStage(c, 'execution', CATALOG.tactics), 2);
  assert.strictEqual(c.stages[2].id, 's4', 'ids are not reused while others exist');
});

test('action duplicate, remove, move between stages', () => {
  const c = T.blankCampaign();
  T.addStage(c, 'execution', CATALOG.tactics); T.addStage(c, 'execution', CATALOG.tactics);
  T.addAction(c, 0, { action: 'a' }); T.addAction(c, 0, { action: 'b' });
  assert.strictEqual(T.duplicateAction(c, 0, 0), 1);
  assert.deepStrictEqual(plain(c.stages[0].actions.map((a) => a.action)), ['a', 'a', 'b']);
  assert.ok(T.moveAction(c, 0, 2, 1));
  assert.deepStrictEqual(plain(c.stages[1].actions.map((a) => a.action)), ['b']);
  assert.ok(T.removeAction(c, 0, 0));
  assert.strictEqual(T.removeAction(c, 0, 5), false);
  assert.strictEqual(T.totalActions(c), 2);
  assert.strictEqual(T.moveAction(c, 0, 0, 0), false);
});

test('clone is deep; techniques', () => {
  const c = T.blankCampaign();
  const d = T.clone(c); d.meta.name = 'other';
  assert.notStrictEqual(c.meta.name, 'other');
  const st = { techniques: [] };
  assert.ok(T.addTechnique(st, ' t1071.001 '));
  assert.strictEqual(T.addTechnique(st, 'T1071.001'), false);
  assert.ok(T.removeTechnique(st, 'T1071.001'));
  assert.ok(T.validTechniqueId('T1059')); assert.ok(T.validTechniqueId('T1059.003'));
  assert.ok(!T.validTechniqueId('T10')); assert.ok(!T.validTechniqueId('<img>'));
});

test('param coercion and range checks', () => {
  const i = { type: 'int', default: 4 };
  assert.deepStrictEqual(JSON.parse(JSON.stringify(T.coerceParam(i, ' 7 '))), { ok: true, value: 7 });
  assert.strictEqual(T.coerceParam(i, '7.5').ok, false);
  assert.strictEqual(T.coerceParam(i, 'abc').ok, false);
  assert.strictEqual(T.coerceParam(i, '-1').ok, false);
  assert.strictEqual(T.coerceParam(i, '1e12').ok, false);
  assert.strictEqual(T.coerceParam(i, '').reset, true);
  assert.strictEqual(T.coerceParam({ type: 'int', default: -5 }, '-3').value, -3);
  assert.strictEqual(T.coerceParam({ type: 'float', default: 0.1 }, '0.25').value, 0.25);
  assert.strictEqual(T.coerceParam({ type: 'float', default: 0.1 }, 'NaN').ok, false);
  assert.strictEqual(T.coerceParam({ type: 'bool', default: false }, true).value, true);
  assert.deepStrictEqual(Array.from(T.coerceParam({ type: 'list', default: [443] }, '80, 8080,,').value), [80, 8080]);
  assert.strictEqual(T.coerceParam({ type: 'list', default: [443] }, '80, x').ok, false);
  assert.deepStrictEqual(Array.from(T.coerceParam({ type: 'list', default: null }, 'a, b').value), ['a', 'b']);
  assert.strictEqual(T.coerceParam({ type: 'str', default: 'x' }, 'a\u0001b').ok, false);
  assert.strictEqual(T.coerceParam({ type: 'str', default: 'x' }, 'hello').value, 'hello');
  assert.strictEqual(T.paramToText({ type: 'list', default: [1, 2] }, undefined), '1, 2');
  assert.strictEqual(T.paramToText({ type: 'str', default: null }, undefined), '');
});

test('seconds clamp', () => {
  assert.strictEqual(T.clampSeconds('5000000', 1, 60), 86400);
  assert.strictEqual(T.clampSeconds('-3', 1, 60), 1);
  assert.strictEqual(T.clampSeconds('abc', 1, 60), 60);
  assert.strictEqual(T.clampSeconds('2.5', 0, 0), 2.5);
  assert.strictEqual(T.parseNum(''), null); assert.strictEqual(T.parseNum('0x10'), null);
});

test('endpoint refs', () => {
  assert.deepStrictEqual({ ...T.parseRef('c2:0') }, { valid: true, raw: 'c2:0', base: 'c2', scope: 'external', index: 0, suffix: '' });
  assert.strictEqual(T.parseRef('host:FILE1').suffix, 'FILE1');
  assert.strictEqual(T.parseRef('host:').valid, false);
  assert.strictEqual(T.parseRef('c2:x').valid, false);
  assert.strictEqual(T.parseRef('c2').valid, false);
  assert.strictEqual(T.parseRef('ws').scope, 'internal');
  assert.strictEqual(T.parseRef('attacker').scope, 'external');
  assert.strictEqual(T.parseRef(7).valid, false);
  assert.strictEqual(T.formatRef('c2', '3'), 'c2:3');
  assert.strictEqual(T.formatRef('c2', 'zz'), 'c2:0');
  assert.strictEqual(T.formatRef('host', ' FILE2 '), 'host:FILE2');
  assert.strictEqual(T.formatRef('dc', 9), 'dc');
  const ext = T.refChoices('external').map((c) => c.base);
  assert.ok(ext.includes('c2') && ext.includes('attacker') && !ext.includes('ws'));
  const int = T.refChoices('internal').map((c) => c.base);
  assert.ok(int.includes('host') && int.includes('any_ws') && !int.includes('c2'));
  assert.strictEqual(T.refChoices('any').length, int.length + ext.length);
  assert.ok(T.refMatches('internal', 'ws') && !T.refMatches('internal', 'c2:0') && T.refMatches('any', 'c2:0') && !T.refMatches('any', 'junk'));
  assert.strictEqual(T.defaultEndpoint('internal', 'from', { compromised: 'ws2' }), 'ws2');
  assert.strictEqual(T.defaultEndpoint('internal', 'from', { compromised: 'c2:0' }), 'ws');
  assert.strictEqual(T.defaultEndpoint('internal', 'to', { lateral_target: 'FILE1' }), 'host:FILE1');
  assert.strictEqual(T.defaultEndpoint('internal', 'to', { lateral_target: 'dc' }), 'dc');
  assert.strictEqual(T.defaultEndpoint('external', 'to', {}), 'attacker');
  const a = T.newActionFor(CATALOG.actions[0], { compromised: 'ws' });
  assert.deepStrictEqual({ ...a, params: { ...a.params } }, { action: 'https_beacon', from: 'ws', to: 'attacker', params: {}, explain: '' });
});

test('timeline maths', () => {
  const c = { options: { start: '10:00', speed: 'realistic' }, stages: [
    { id: 's1', name: 'A', tactic: 'execution', duration_s: 60, fast_s: 20 },
    { id: 's2', name: 'B', tactic: 'command-and-control', duration_s: 180, fast_s: 40 }] };
  let tl = T.timeline(c);
  assert.strictEqual(tl.total_s, 240);
  assert.strictEqual(tl.segments[1].offset_s, 60);
  assert.strictEqual(tl.segments[0].left_pct, 0);
  assert.strictEqual(Math.round(tl.segments[1].left_pct), 25);
  assert.strictEqual(Math.round(tl.segments[1].width_pct), 75);
  assert.strictEqual(tl.segments[1].start_clock, '10:01');
  assert.strictEqual(tl.end_clock, '10:04');
  c.options.speed = 'fast';
  tl = T.timeline(c);
  assert.strictEqual(tl.total_s, 60);
  assert.strictEqual(T.parseStart('25:00'), 36000);
  assert.strictEqual(T.parseStart('09:30'), 34200);
  assert.strictEqual(T.fmtClock(86400 + 61), '00:01:01');
  assert.strictEqual(T.timeline({ stages: [] }).total_s, 0);
  assert.strictEqual(T.fmtDuration(150), '2 min 30 s');
  assert.strictEqual(T.fmtDuration(7200), '2 h');
});

test('error location parsing and grouping', () => {
  const c = { stages: [{ id: 's1', actions: [{}, {}] }, { id: 's2', actions: [{}] }] };
  assert.deepStrictEqual({ ...T.parseErrorLocation('stages[0].actions[1].params.count: expected int', c) }, { stage: 0, action: 1, text: 'stages[0].actions[1].params.count: expected int' });
  assert.strictEqual(T.parseErrorLocation('stages[1].name: required non-empty string', c).action, null);
  assert.strictEqual(T.parseErrorLocation('stages[7].name: x', c).stage, null);
  assert.strictEqual(T.parseErrorLocation('stages[1].actions[9].to: x', c).action, null);
  assert.strictEqual(T.parseErrorLocation('stage s2: action 0 failed', c).action, 0);
  assert.strictEqual(T.parseErrorLocation('stage zz: broken', c).stage, null);
  assert.strictEqual(T.parseErrorLocation('iocs[0]: bad', c).stage, null);
  assert.strictEqual(T.parseErrorLocation('options: unknown key', c).stage, null);
  const g = T.groupErrors(['stages[0].actions[1].to: bad', 'stages[0].name: bad', 'meta.name: required', 'stages[1].actions[0].from: x'], c);
  assert.strictEqual(g.count, 4);
  assert.deepStrictEqual(plain(g.general), ['meta.name: required']);
  assert.strictEqual(g.stages[0].length, 1);
  assert.strictEqual(g.actions['0:1'].length, 1);
  assert.strictEqual(g.actions['1:0'].length, 1);
});

test('tactic coverage and picker grouping', () => {
  const c = { stages: [{ id: 's1', tactic: 'execution', techniques: ['T1204.002'], actions: [{ action: 'https_beacon' }] }] };
  const cov = T.tacticCoverage(c, CATALOG.tactics, CATALOG.actions);
  assert.deepStrictEqual(plain(cov.map((t) => t.covered)), [true, true, false]);
  assert.deepStrictEqual(Array.from(cov[0].techniques), ['T1204.002']);
  assert.deepStrictEqual(Array.from(cov[1].techniques), ['T1071.001']);
  let g = T.pickerGroups(CATALOG.actions, CATALOG.tactics, '', 'lateral-movement');
  assert.strictEqual(g[0].tactic, 'lateral-movement');
  g = T.pickerGroups(CATALOG.actions, CATALOG.tactics, 'tls beacon');
  assert.strictEqual(g.length, 1);
  assert.strictEqual(g[0].actions[0].token, 'https_beacon');
  assert.strictEqual(T.pickerGroups(CATALOG.actions, CATALOG.tactics, 'zzz').length, 0);
  assert.deepStrictEqual({ ...T.normCatalog([{ token: 'a' }]) }.tactics.length, 0);
});

test('linked IOCs and estimate line', () => {
  const c = { iocs: [{ type: 'domain', value: 'a.example', role: 'c2', why: 'listed as C2' }] };
  const l = T.linkedIocs(c, { ioc: [0, 5] });
  assert.strictEqual(l.length, 1); assert.strictEqual(l[0].why, 'listed as C2');
  const e = T.estimateLine({ flows: 12, minutes_realistic: 3.5, minutes_fast: 1 }, { stages: [{ actions: [{}] }] });
  assert.strictEqual(e.flows, 12); assert.strictEqual(e.actions, 1);
  assert.strictEqual(T.estimateLine(null, {}), null);
});

/* ---- registration and a real render through the fake DOM ---- */
test('registers the build step', () => {
  const { steps } = load();
  assert.ok(steps.build);
  assert.strictEqual(typeof steps.build.mount, 'function');
  assert.strictEqual(steps.build.canLeave(), true);
});

test('empty state without a campaign, start from scratch works', () => {
  const env = load({ actions: CATALOG, post: () => Promise.resolve({ errors: ['stages: required non-empty list'] }) });
  const box = new El('div');
  env.steps.build.mount(box);
  assert.ok(box.textContent.includes('No campaign to edit yet'));
  const btn = box.all().find((e) => e.tagName === 'BUTTON' && e.textContent === 'Start from scratch');
  btn.fire('click');
  assert.ok(env.OGC.state.campaign);
  assert.ok(env.OGC.state.dirty);
  assert.ok(box.textContent.includes('no stages yet'));
  assert.ok(env.doc.getElementById('ogc-editor-style'), 'style injected');
});

test('render, edit, validate, estimate with a sample campaign', async () => {
  const camp = { schema: 'opengenerator.campaign/1', meta: { name: 'N<b>', id: 'n', seed: 5, description: '', actor: '' },
    options: { start: '10:00', speed: 'realistic', compromised: 'ws', lateral_target: 'server' },
    iocs: [{ type: 'domain', value: '<img src=x onerror=alert(1)>', role: 'c2', why: 'listed' }],
    stages: [{ id: 's1', name: 'Run', tactic: 'execution', techniques: ['T1204.002', 'bad'], narrative: '', duration_s: 60, fast_s: 20,
      actions: [{ action: 'https_beacon', from: 'ws', to: 'c2:0', params: { count: 2 }, ioc: [0], explain: 'x' }] }], expect: [] };
  const env = load({
    actions: CATALOG,
    post: (p, b) => (p.endsWith('validate') ? Promise.resolve({ errors: ['stages[0].actions[0].params.count: expected int'] }) : Promise.resolve({ flows: 3, minutes_realistic: 2, minutes_fast: 1, errors: [] })),
    get: () => Promise.resolve({ techniques: [] })
  });
  env.OGC.state.campaign = camp;
  const box = new El('div');
  env.steps.build.mount(box);
  const text = box.textContent;
  assert.ok(text.includes('HTTPS beacon'));
  assert.ok(text.includes('<img src=x onerror=alert(1)>'), 'hostile text shown as text');
  assert.ok(text.includes('bad (invalid)'), 'invalid technique flagged');
  assert.ok(text.includes('Command and Control (covered)'));
  assert.ok(text.includes('listed'), 'IOC why shown');
  // edit stage name: no re-render, campaign updated, dirty
  const nameIn = box.all().find((e) => e.attrs['aria-label'] === 'Stage 1 name');
  nameIn.value = 'Renamed'; nameIn.fire('input');
  assert.strictEqual(env.OGC.state.campaign.stages[0].name, 'Renamed');
  assert.strictEqual(camp.stages[0].name, 'Run', 'the original object was not mutated');
  assert.ok(env.OGC.state.dirty);
  // duplicate the action (structural)
  box.all().find((e) => e.attrs['aria-label'] === 'Duplicate action 1').fire('click');
  assert.strictEqual(env.OGC.state.campaign.stages[0].actions.length, 2);
  // bad param: no commit
  const count = box.all().find((e) => e.attrs['aria-label'] === 'count');
  count.value = 'abc'; count.fire('change');
  assert.strictEqual(env.OGC.state.campaign.stages[0].actions[0].params.count, 2);
  assert.ok(box.textContent.includes('Enter a number.'));
  // validate pins the error to the action
  env.steps.build.onEnter();
  await new Promise((r) => setTimeout(r, 20));
  assert.ok(box.textContent.includes('1 problem'));
  assert.ok(box.textContent.includes('stages[0].actions[0].params.count: expected int'));
  assert.ok(env.calls.some((c) => c[0] === 'POST' && c[1] === '/api/campaign/validate'));
});

test('missing endpoints are tolerated', async () => {
  const env = load({});   // every call rejects, no catalog
  env.OGC.state.campaign = T.blankCampaign();
  const box = new El('div');
  env.steps.build.mount(box);
  env.steps.build.onEnter();
  await new Promise((r) => setTimeout(r, 20));
  assert.ok(box.textContent.includes('Validation is unavailable') || box.textContent.includes('Checking'));
  assert.ok(box.textContent.includes('action catalog could not be loaded'));
});
