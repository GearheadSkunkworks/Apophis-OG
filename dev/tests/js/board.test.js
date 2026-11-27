'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SRC = fs.readFileSync(path.join(__dirname, '..', '..', 'ui', 'campaigns-board.js'), 'utf8');

/* minimal fake DOM, enough for render() */
function fakeEnv(api, opts) {
  opts = opts || {};
  class El {
    constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.listeners = {}; this._text = ''; this.style = {}; this.className = ''; this.width = 960; this.height = 480; this.clientWidth = 0; this.value = ''; }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    getAttribute(k) { return this.attrs[k] == null ? null : this.attrs[k]; }
    appendChild(c) { this.children.push(c); c.parentNode = this; return c; }
    removeChild(c) { this.children = this.children.filter(x => x !== c); }
    get firstChild() { return this.children[0] || null; }
    addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
    fire(t) { (this.listeners[t] || []).forEach(f => f({})); }
    set textContent(v) { this._text = String(v); this.children = []; }
    get textContent() { return this._text + this.children.map(c => c.textContent).join(' '); }
    getContext() { return opts.ctx; }
    all(pred, out) { out = out || []; if (pred(this)) out.push(this); this.children.forEach(c => c.all && c.all(pred, out)); return out; }
  }
  const document = { createElement: t => new El(t), createElementNS: (ns, t) => new El(t), createTextNode: s => { const e = new El('#text'); e._text = String(s); e.all = (p, o) => o || []; return e; } };
  const sandbox = { window: { OGC: { api } }, document, console, Promise, setTimeout };
  if (opts.matchMedia) sandbox.window.matchMedia = opts.matchMedia;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(SRC, sandbox, { filename: 'campaigns-board.js' });
  return { OGC: sandbox.window.OGC, El };
}

const { OGC: OGC0 } = fakeEnv({});
const raw = OGC0.board._test;
const T = {};
for (const k of Object.keys(raw)) T[k] = typeof raw[k] === 'function' ? (...a) => { const r = raw[k](...a); return r === undefined ? r : JSON.parse(JSON.stringify(r)); } : raw[k];

const ENTRIES = [
  { stage: 's1', stage_name: 'Recon', action: 'dns_lookup', status: 'ok', ts: 1000, first_ts: 1000, last_ts: 1010, techniques: ['T1071.004'],
    from_host: { name: 'ws1', ip: '10.0.0.5' }, to_host: { name: 'ns', ip: '198.18.0.9' }, ioc: [0], packets: 4, bytes: 400 },
  { stage: 's2', stage_name: 'C2', action: 'https_beacon', status: 'ok', ts: 1060, first_ts: 1060, last_ts: 1120, techniques: ['T1071.001'],
    from_host: { name: 'ws1', ip: '10.0.0.5' }, to_host: { name: 'x', ip: '203.0.113.5' }, ioc: [1], packets: 40, bytes: 9000 },
  { stage: 's2', stage_name: 'C2', action: 'https_beacon', status: 'skipped', ts: 1200, last_ts: 1200, ioc: [1] },
  { stage: 's3', stage_name: 'Exfil', action: 'upload', status: 'ok', ts: 1300, last_ts: 1330, ioc: [2, 1] },
  { stage: 's9', action: 'bad', status: 'ok' }               // no timestamp: ignored by the clock
];
const IOCS = [
  { index: 0, value: 'mapped.example', role: 'c2', address: '198.18.4.7' },
  { index: 1, value: '203.0.113.5', role: 'c2', address: '203.0.113.5' },
  { index: 2, value: 'files.example', role: 'exfil', address: '192.168.1.1' }
];
const STAGES = [{ id: 's1', name: 'Recon', tactic: 'reconnaissance' }, { id: 's2', name: 'C2', tactic: 'command-and-control' },
  { id: 's3', name: 'Exfil', tactic: 'exfiltration' }, { id: 's4', name: 'Impact', tactic: 'impact' }];

test('address classification keeps mapped and private addresses out of the lookup', () => {
  assert.strictEqual(T.classifyAddress('198.18.4.7'), 'mapped');
  assert.strictEqual(T.classifyAddress('198.19.255.1'), 'mapped');
  assert.strictEqual(T.classifyAddress('198.20.0.1'), 'public');
  assert.strictEqual(T.classifyAddress('203.0.113.5'), 'public');
  for (const a of ['10.1.1.1', '127.0.0.1', '169.254.1.1', '172.16.0.1', '172.31.9.9', '192.168.0.1', '100.64.0.1', '224.0.0.1', '0.0.0.0']) assert.strictEqual(T.classifyAddress(a), 'private', a);
  assert.strictEqual(T.classifyAddress('172.32.0.1'), 'public');
  for (const a of ['example.com', '', null, undefined, '300.1.1.1', '1.2.3', '::1', 'http://1.2.3.4']) assert.strictEqual(T.classifyAddress(a), 'none', String(a));
});

test('clock formatting', () => {
  assert.strictEqual(T.fmtClock(0), 'T+00:00');
  assert.strictEqual(T.fmtClock(65.9), 'T+01:05');
  assert.strictEqual(T.fmtClock(3725), 'T+1:02:05');
  assert.strictEqual(T.fmtClock(-4), 'T+00:00');
  assert.strictEqual(T.fmtClock('x'), 'T+00:00');
});

test('clock model maps entries to relative events', () => {
  const m = T.clockModel(ENTRIES);
  assert.strictEqual(m.t0, 1000);
  assert.strictEqual(m.duration, 330);
  assert.deepStrictEqual(m.events.map(e => e.i), [0, 1, 2, 3]);
  assert.deepStrictEqual(m.events.map(e => e.t), [0, 60, 200, 300]);
  assert.strictEqual(m.events[1].end, 120);
  assert.deepStrictEqual(T.clockModel([]), { t0: 0, duration: 0, events: [] });
  assert.deepStrictEqual(T.clockModel(null).events, []);
  assert.strictEqual(T.clockModel([{ ts: 5 }]).duration, 1);
  // out-of-order input sorts by time
  assert.deepStrictEqual(T.clockModel([{ ts: 50 }, { ts: 10 }]).events.map(e => e.i), [1, 0]);
});

test('reached entries follow the clock', () => {
  const m = raw.clockModel(ENTRIES);
  assert.deepStrictEqual(Array.from(raw.reached(m, 0)), [0]);
  assert.deepStrictEqual(Array.from(raw.reached(m, 59.9)), [0]);
  assert.deepStrictEqual(Array.from(raw.reached(m, 60)), [0, 1]);
  assert.deepStrictEqual(Array.from(raw.reached(m, 9999)), [0, 1, 2, 3]);
});

test('arc progress', () => {
  assert.strictEqual(T.arcProgress(5, 10, 4, false), 0);
  assert.strictEqual(T.arcProgress(10, 10, 4, false), 0);
  assert.strictEqual(T.arcProgress(12, 10, 4, false), 0.5);
  assert.strictEqual(T.arcProgress(99, 10, 4, false), 1);
  assert.strictEqual(T.arcProgress(10, 10, 4, true), 1);   // reduced motion: lit at once
  assert.strictEqual(T.arcProgress(5, 10, 4, true), 0);
  assert.strictEqual(T.arcProgress(5, null, 4, false), 0);
  assert.strictEqual(T.arcProgress(11, 10, 0, false), 0.25);  // zero duration falls back to the default
});

test('indicator timeline: first seen, mapped, private', () => {
  const m = raw.clockModel(ENTRIES);
  const tl = T.iocTimeline(IOCS, ENTRIES, m);
  assert.deepStrictEqual(tl.map(x => x.kind), ['mapped', 'public', 'private']);
  assert.deepStrictEqual(tl.map(x => x.firstSeen), [0, 60, 300]);
  assert.deepStrictEqual(tl[1].entries, [1, 2, 3]);
  assert.deepStrictEqual(tl.map(x => x.n), [1, 2, 3]);
  // the row carries the indicator's own fields; the geo-only locAddr/viaValue are gone
  assert.deepStrictEqual(tl.map(x => x.index), [0, 1, 2]);
  assert.deepStrictEqual(tl.map(x => x.value), ['mapped.example', '203.0.113.5', 'files.example']);
  assert.deepStrictEqual(tl.map(x => x.role), ['c2', 'c2', 'exfil']);
  assert.deepStrictEqual(tl.map(x => x.address), ['198.18.4.7', '203.0.113.5', '192.168.1.1']);
  assert.ok(!('locAddr' in tl[0]) && !('viaValue' in tl[0]));
  assert.deepStrictEqual(T.iocTimeline(null, null, m), []);
  // an indicator never used by any action has no first-seen time
  assert.strictEqual(T.iocTimeline([{ index: 7, value: 'a', address: '8.8.8.8' }], ENTRIES, m)[0].firstSeen, null);
});

test('stage states follow the clock', () => {
  const m = raw.clockModel(ENTRIES);
  const at = t => T.stageStates({ stages: STAGES }, ENTRIES, m, t).map(s => s.state);
  assert.deepStrictEqual(at(0), ['active', 'pending', 'pending', 'none']);
  assert.deepStrictEqual(at(10), ['done', 'pending', 'pending', 'none']);
  assert.deepStrictEqual(at(100), ['done', 'active', 'pending', 'none']);
  assert.deepStrictEqual(at(250), ['done', 'done', 'pending', 'none']);
  assert.deepStrictEqual(at(330), ['done', 'done', 'done', 'none']);
  // no campaign file: stages come from the entries
  const d = T.stageStates(null, ENTRIES, m, 0);
  assert.deepStrictEqual(d.map(s => s.id), ['s1', 's2', 's3', 's9']);
  assert.strictEqual(d[3].state, 'none');
});

test('detection pins come only from matched detections in the supplied result', () => {
  const m = raw.clockModel(ENTRIES);
  assert.deepStrictEqual(T.detectionPins(null, ENTRIES, m), []);
  assert.deepStrictEqual(T.detectionPins({}, ENTRIES, m), []);
  const fb = { detections: [
    { id: 'a', title: 'Beaconing', risk: 70, matched: true, matched_actions: [3, 1], techniques: ['T1071.001'] },
    { id: 'b', title: 'Unrelated', matched: false, matched_actions: [] },
    { id: 'c', title: 'Odd', matched: true, matched_actions: [99] },
    { id: 'd', matched: true }
  ] };
  const p = T.detectionPins(fb, ENTRIES, m);
  assert.strictEqual(p.length, 1);
  // the pin lands on its first matched action in clock order
  assert.strictEqual(p[0].n, 1); assert.strictEqual(p[0].t, 60); assert.strictEqual(p[0].entry, 1);
  assert.strictEqual(p[0].id, 'a'); assert.strictEqual(p[0].risk, 70);
  assert.strictEqual(p[0].title, 'Beaconing'); assert.deepStrictEqual(p[0].techniques, ['T1071.001']);
  assert.ok(!('iocN' in p[0]));
  // a pin whose only matched action is a mapped-range one still pins, at that action
  const q = T.detectionPins({ detections: [{ matched: true, matched_actions: [0], title: 't' }] }, ENTRIES, m);
  assert.strictEqual(q[0].entry, 0); assert.strictEqual(q[0].t, 0);
});

test('event table is the text alternative', () => {
  const m = raw.clockModel(ENTRIES), tl = raw.iocTimeline(IOCS, ENTRIES, m);
  const t = T.buildEventTable(ENTRIES, m, tl);
  assert.strictEqual(t.rows.length, 4);
  assert.deepStrictEqual(t.headers, ['Clock', 'Stage', 'Action', 'Status', 'From', 'To', 'Protocol', 'Indicators', 'Techniques']);
  assert.deepStrictEqual(t.keys, ['time', 'stage', 'action', 'status', 'from', 'to', 'proto', 'indicators', 'techniques']);
  assert.strictEqual(t.headers.length, t.keys.length);
  assert.deepStrictEqual(t.rows[0], { time: 'T+00:00', stage: 'Recon', action: 'dns_lookup', status: 'ok', from: 'ws1', to: 'ns', proto: '', indicators: '1', techniques: 'T1071.004' });
  assert.strictEqual(t.rows[3].indicators, '2, 3');
  assert.strictEqual(t.rows[2].status, 'skipped');
  // the Protocol column joins entry.protocols
  const pm = raw.clockModel([{ ts: 1, protocols: ['DNS', 'UDP'] }]);
  assert.strictEqual(T.buildEventTable([{ ts: 1, protocols: ['DNS', 'UDP'] }], pm, []).rows[0].proto, 'DNS, UDP');
  assert.deepStrictEqual(T.buildEventTable([], raw.clockModel([]), []).rows, []);
});

/* ---- render smoke tests with a fake DOM ---- */
const flush = () => new Promise(r => setTimeout(r, 0));
const noopCtx = new Proxy({}, { get: (o, k) => (k in o ? o[k] : () => {}), set: (o, k, v) => { o[k] = v; return true; } });
const CAMP = { entries: ENTRIES, iocs: IOCS };
const WORLD = { countries: [{ cc: 'NL', name: 'Netherlands', lat: 52, lon: 5, polygons: [[[3, 51], [7, 51], [7, 53], [3, 53]]] }] };

test('render: shows the flow map, stage strip, scope threat list and text table', async () => {
  // The board makes no network calls: even a rejecting API renders fully.
  const api = { get: () => Promise.reject(new Error('no network')), post: () => Promise.reject(new Error('no network')) };
  const { OGC, El } = fakeEnv(api, { ctx: noopCtx });
  const c = new El('div');
  const ctl = OGC.board.render(c, CAMP, { stages: STAGES }, null);
  await flush(); await flush(); await flush();
  const txt = c.textContent;
  assert.match(txt, /Recon/);                 // stage strip
  assert.match(txt, /hosts across/);           // flow-map note (N hosts across M zones, K flows)
  assert.match(txt, /Inbound threat list/);    // threat list caption
  assert.match(txt, /Scope/);                  // the Country column is now a Scope column
  assert.match(txt, /external/);               // kindLabel scope value for a public/mapped indicator
  assert.match(txt, /Text alternative/);       // text table still present
  const svg = c.all(e => e.tag === 'svg')[0];  // the flow map is inline SVG, not a canvas
  assert.ok(svg);
  assert.strictEqual(svg.getAttribute('role'), 'img');
  assert.ok(svg.getAttribute('aria-label'));
  assert.strictEqual(c.all(e => e.tag === 'canvas').length, 0);
  assert.strictEqual(c.all(e => e.tag === 'table').length, 2); // threat list + text alternative (no pins without feedback)
  ctl.destroy();
});

test('render: scrubber moves the clock and updates the lists', async () => {
  const api = { get: () => Promise.resolve(WORLD), post: () => Promise.resolve({ results: {} }) };
  const { OGC, El } = fakeEnv(api, { ctx: noopCtx });
  const c = new El('div');
  OGC.board.render(c, CAMP, { stages: STAGES }, null);
  await flush(); await flush(); await flush();
  const scrub = c.all(e => e.attrs.type === 'range')[0];
  assert.strictEqual(scrub.attrs.max, '330');
  scrub.value = '310'; scrub.fire('input');
  assert.match(c.textContent, /T\+05:10 \/ T\+05:30/);
  assert.match(c.textContent, /T\+05:00/);               // third indicator now has a first-seen time
  const pausedBtn = c.all(e => e.className.indexOf('ogcb-play') >= 0)[0];
  assert.strictEqual(pausedBtn.getAttribute('aria-label'), 'Play the clock');
});

test('render: feedback adds the detection pin table, nothing invented', async () => {
  const api = { get: () => Promise.resolve(WORLD), post: () => Promise.resolve({ results: { '203.0.113.5': { cc: 'NL', country: 'Netherlands', lat: 52, lon: 5 } } }) };
  const { OGC, El } = fakeEnv(api, { ctx: noopCtx });
  const c = new El('div');
  OGC.board.render(c, CAMP, { stages: STAGES }, { detections: [{ id: '1', title: 'Beaconing', matched: true, matched_actions: [1] }, { id: '2', title: 'Stray', matched: false }] });
  await flush(); await flush(); await flush();
  const t = c.textContent;
  assert.match(t, /Beaconing/);
  assert.doesNotMatch(t, /Stray/);
  const none = new El('div');
  OGC.board.render(none, CAMP, { stages: STAGES }, { detections: [] });
  await flush(); await flush(); await flush();
  assert.match(none.textContent, /no detections matched to an action/);
});

test('render: builds the flow map, strip, threats and clock with no network dependency', async () => {
  // Even with a rejecting API the board renders fully: the zone flow map is drawn from the
  // campaign alone -- no geo-world file, no lookup, no network of any kind.
  const api = { get: () => Promise.reject(new Error('404')), post: () => Promise.reject(new Error('404')) };
  const { OGC, El } = fakeEnv(api, { ctx: noopCtx });
  const c = new El('div');
  OGC.board.render(c, CAMP, { stages: STAGES }, null);
  await flush(); await flush(); await flush();
  const t = c.textContent;
  assert.match(t, /hosts across/);
  assert.match(t, /Recon/);
  assert.match(t, /Inbound threat list/);
  assert.match(t, /T\+00:00 \/ T\+05:30/);
});

test('render: no canvas context and no entries do not throw', async () => {
  const api = { get: () => Promise.resolve(WORLD), post: () => Promise.resolve({}) };
  const { OGC, El } = fakeEnv(api, { ctx: null });
  const c = new El('div');
  OGC.board.render(c, CAMP, null, null);
  await flush(); await flush(); await flush();
  assert.match(c.textContent, /Inbound threat list/);
  const e = new El('div');
  OGC.board.render(e, { entries: [], iocs: [] }, null, null);
  assert.match(e.textContent, /no campaign traffic/);
  OGC.board.render(new El('div'), null, null, null);
  assert.doesNotThrow(() => OGC.board.render(null, CAMP, null, null).destroy());
});

test('render: reduced motion disables the play button but not the scrubber', async () => {
  const api = { get: () => Promise.resolve(WORLD), post: () => Promise.resolve({}) };
  const { OGC, El } = fakeEnv(api, { ctx: noopCtx, matchMedia: () => ({ matches: true }) });
  const c = new El('div');
  OGC.board.render(c, CAMP, null, null);
  const play = c.all(e => e.className.indexOf('ogcb-play') >= 0)[0];
  assert.ok('disabled' in play.attrs);
  play.fire('click');
  assert.strictEqual(play._text, 'Play');
  const scrub = c.all(e => e.attrs.type === 'range')[0];
  assert.ok(!('disabled' in scrub.attrs));
  assert.match(c.textContent, /Reduced motion is on/);
});

test('no vendor names in the source', () => {
  assert.doesNotMatch(SRC, new RegExp(['Extra' + 'Hop', 'Reveal' + 'X', 'Vec' + 'tra', 'Dark' + 'trace', 'Crowd' + 'Strike'].join('|'), 'i'));
  assert.doesNotMatch(SRC, /innerHTML|insertAdjacentHTML|eval\(|new\s+Function/);
});
