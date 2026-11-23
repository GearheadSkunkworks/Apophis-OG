'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

function load() {
  const sandbox = { window: {}, console };
  sandbox.window.OGC = {};
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(path.join(__dirname, '..', '..', 'ui', 'campaigns-sensor.js'), 'utf8'),
    sandbox, { filename: 'campaigns-sensor.js' });
  return sandbox.window.OGC;
}
const OGC = load();
const raw = OGC.sensor._test;
const T = {};
for (const k of Object.keys(raw)) T[k] = typeof raw[k] === 'function' ? (...a) => {
  const r = raw[k](...a);
  return (r && typeof r.then === 'function') ? r.then(x => JSON.parse(JSON.stringify(x))) : (r && typeof r === 'object' ? JSON.parse(JSON.stringify(r)) : r);
} : raw[k];

const SC = { entries: [{ stage: 's1', action: 'a', ts: 1 }], iocs: [{ index: 0, value: '1.2.3.4' }] };
const CF = { stages: [{ id: 's1', name: 'Exec', tactic: 'execution', extra: 1 }], expect: [{ technique: 'T1', stage: 's1' }] };
const RESULT = {
  ok: true, window: { from_ms: 0, until_ms: 1000 }, count: 2,
  score: { testable: 3, detected: 1, partial: 1, missed: 1, percent: 50, by_tactic: { execution: { testable: 3, detected: 1, percent: 33 } } },
  techniques: [{ technique: 'T1105', name: '=cmd|x', tactic: 'execution', status: 'detected', stages: ['s1'], actions: ['a'], detections: [7], note: 'n' },
               { technique: 'T2', name: 'Two', tactic: 'c2', status: 'missed', stages: [], actions: [], detections: [], note: '' }],
  actions: [{ stage: 's1', action: 'a', ts: 5, status: 'not_run', detections: [] }],
  vulnerabilities: { count: 2, note: 'carried' },
  detections: [{ id: 7, title: '+evil, "x"', techniques: ['T1'], tactics: [], participants: ['198.18.0.1'], start_ms: 9, matched: false },
               { id: 8, title: 'ok', matched: true }],
  unmatched: 1
};

test('status labels use words', () => {
  assert.strictEqual(T.statusLabel('detected'), 'Detected');
  assert.strictEqual(T.statusLabel('related'), 'Related detection');
  assert.strictEqual(T.statusLabel('missed'), 'Missed');
  assert.strictEqual(T.statusLabel('not_run'), 'Not run');
  assert.strictEqual(T.statusLabel('weird'), 'Unknown');
  assert.strictEqual(T.statusLabel(undefined), 'Unknown');
});

test('score line', () => {
  assert.match(T.scoreLine(RESULT.score), /^50% coverage: 1 detected, 1 related, 1 missed, out of 3/);
  assert.match(T.scoreLine({ testable: 0 }), /Nothing in this campaign is testable/);
  assert.strictEqual(T.scoreLine(null), '');
});

test('offset and sensor validation', () => {
  assert.deepStrictEqual(T.parseOffset(''), { ok: true, value: 0 });
  assert.strictEqual(T.parseOffset('-3600').value, -3600);
  assert.strictEqual(T.parseOffset('+5.5').value, 5.5);
  for (const bad of ['abc', '1e3', '--1', '1 2']) assert.strictEqual(T.parseOffset(bad).ok, false, bad);
  assert.strictEqual(T.validSensor('10.0.0.5:443'), '');
  assert.strictEqual(T.validSensor('sensor.lab.example'), '');
  for (const bad of ['', '  ', 'https://x', 'x/path', 'u:p@h', 'a b']) assert.notStrictEqual(T.validSensor(bad), '', bad);
});

test('buildRequest follows the contract and trims stage fields', () => {
  const b = T.buildRequest({ sensor: ' h ', key: 'K', offset_s: -5 }, SC, CF);
  assert.deepStrictEqual(Object.keys(b).sort(), ['entries', 'expect', 'iocs', 'key', 'lookahead_s', 'min_risk', 'offset_s', 'sensor', 'slack_s', 'stages']);
  assert.strictEqual(b.sensor, 'h'); assert.strictEqual(b.offset_s, -5);
  assert.deepStrictEqual(b.stages, [{ id: 's1', name: 'Exec', tactic: 'execution' }]);
  assert.strictEqual(b.entries.length, 1);
  const e = T.buildRequest({ sensor: 'h', key: 'k' }, null, null);
  assert.deepStrictEqual([e.entries, e.iocs, e.expect, e.stages], [[], [], [], []]);
});

test('CSV cells are quoted and formula-guarded', () => {
  assert.strictEqual(T.csvCell('a"b'), '"a""b"');
  assert.strictEqual(T.csvCell('=1+1'), '"\'=1+1"');
  assert.strictEqual(T.csvCell('+x'), '"\'+x"');
  assert.strictEqual(T.csvCell('-x'), '"\'-x"');
  assert.strictEqual(T.csvCell('@SUM'), '"\'@SUM"');
  assert.strictEqual(T.csvCell('\tx'), '"\'\tx"');
  assert.strictEqual(T.csvCell(null), '""');
  assert.strictEqual(T.csvCell(['a', 'b']), '"a; b"');
  assert.strictEqual(T.csvCell(12), '"12"');
  assert.strictEqual(T.csvCell('a,b\nc'), '"a,b\nc"');
});

test('CSV build covers techniques, actions and unmatched detections', () => {
  const csv = T.buildCsv(RESULT);
  const lines = csv.trim().split('\r\n');
  assert.strictEqual(lines.length, 1 + 2 + 1 + 1);
  assert.match(lines[0], /^"section","technique"/);
  assert.ok(csv.includes('"\'=cmd|x"'));
  assert.ok(csv.includes('"\'+evil, ""x"""'));
  assert.ok(csv.includes('"Detected"') && csv.includes('"Missed"') && csv.includes('"Not run"'));
  assert.ok(!csv.includes('"ok"'), 'matched detections are not listed as unmatched');
  assert.strictEqual(T.buildCsv(null).trim().split('\r\n').length, 1);
});

test('JSON download has the result and never a key or sensor', () => {
  const j = JSON.parse(T.coverageJson(Object.assign({ key: 'SECRET', sensor: 'h' }, RESULT)));
  assert.strictEqual(j.score.percent, 50);
  assert.ok(!('key' in j) && !('sensor' in j));
  assert.ok(!T.coverageJson(RESULT).includes('SECRET'));
  assert.doesNotThrow(() => T.coverageJson(null));
});

test('testConnection posts to /api/sensor/check and reports identity', async () => {
  const calls = [];
  const api = { post: (p, b) => { calls.push([p, b]); return Promise.resolve({ ok: true, identity: { hostname: 'h1', platform: 'p', version: '9' } }); } };
  const r = await T.testConnection(api, { sensor: 'h:443', key: 'K' });
  assert.strictEqual(r.ok, true); assert.strictEqual(r.text, 'Connected: h1, p, 9.');
  assert.strictEqual(calls[0][0], '/api/sensor/check'); assert.deepStrictEqual(Object.keys(calls[0][1]).sort(), ['key', 'sensor']);
  const none = await T.testConnection(api, { sensor: '', key: 'K' });
  assert.strictEqual(none.ok, false); assert.strictEqual(calls.length, 1);
  const nokey = await T.testConnection(api, { sensor: 'h', key: '' });
  assert.strictEqual(nokey.ok, false); assert.strictEqual(calls.length, 1);
});

test('errors are scrubbed of the key and handled for ok:false, rejection and throw', async () => {
  const k = 'sup3rsecret';
  const a1 = { post: () => Promise.resolve({ ok: false, error: 'bad key ' + k }) };
  const a2 = { post: () => Promise.reject(new Error('HTTP 500 ' + k)) };
  const a3 = { post: () => { throw new Error('sync ' + k); } };
  for (const api of [a1, a2, a3]) {
    const r = await T.testConnection(api, { sensor: 'h', key: k });
    assert.strictEqual(r.ok, false); assert.ok(!r.error.includes(k)); assert.ok(r.error.includes('[key]'));
  }
  const r = await T.fetchScore(a1, { sensor: 'h', key: k, offset_s: '0' }, SC, CF);
  assert.ok(!r.error.includes(k));
});

test('fetchScore validates, posts the contract body and normalises the result', async () => {
  const calls = [];
  const api = { post: (p, b) => { calls.push([p, b]); return Promise.resolve(RESULT); } };
  const r = await T.fetchScore(api, { sensor: 'h', key: 'K', offset_s: '-30' }, SC, CF);
  assert.strictEqual(r.ok, true); assert.strictEqual(calls[0][0], '/api/campaign/feedback');
  assert.strictEqual(calls[0][1].offset_s, -30);
  assert.strictEqual(r.result.techniques.length, 2); assert.strictEqual(r.result.score.percent, 50);
  for (const [form, sc] of [[{ sensor: '', key: 'K' }, SC], [{ sensor: 'h', key: '' }, SC], [{ sensor: 'h', key: 'K', offset_s: 'x' }, SC], [{ sensor: 'h', key: 'K' }, { entries: [] }]]) {
    const bad = await T.fetchScore(api, form, sc, CF);
    assert.strictEqual(bad.ok, false);
  }
  assert.strictEqual(calls.length, 1);
});

test('empty and malformed results normalise to safe shapes', () => {
  const n = T.normaliseResult({ ok: true });
  assert.deepStrictEqual([n.techniques, n.actions, n.detections, n.count, n.unmatched], [[], [], [], 0, 0]);
  assert.strictEqual(T.normaliseResult(null).score, null);
  assert.deepStrictEqual(T.normaliseResult({ techniques: 'x' }).techniques, []);
});

test('script exposes OGC.sensor without a DOM and render is absent', () => {
  assert.strictEqual(typeof OGC.sensor._test.buildCsv, 'function');
  assert.strictEqual(OGC.sensor.render, undefined);
});

test('saved Keychain key: requests carry use_stored and never a key; a typed key wins', async () => {
  const calls = [];
  const api = { post: (p, b) => { calls.push([p, b]); return Promise.resolve({ ok: true, identity: { hostname: 'h1' }, count: 0, score: {}, techniques: [], actions: [], detections: [] }); } };
  const r = await T.testConnection(api, { sensor: 'h', key: '', use_stored: true });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(JSON.stringify(calls[0][1]), '{"sensor":"h","use_stored":true}');
  const typed = await T.testConnection(api, { sensor: 'h', key: 'K', use_stored: true });
  assert.strictEqual(typed.ok, true); assert.strictEqual(JSON.stringify(calls[1][1]), '{"sensor":"h","key":"K"}');
  const s = await T.fetchScore(api, { sensor: 'h', key: '', use_stored: true, offset_s: '0' }, SC, CF);
  assert.strictEqual(s.ok, true);
  assert.strictEqual(calls[2][0], '/api/campaign/feedback');
  assert.strictEqual(calls[2][1].use_stored, true); assert.strictEqual(calls[2][1].key, '');
  const b = T.buildRequest({ sensor: 'h', key: 'K', use_stored: true }, SC, CF);
  assert.ok(!('use_stored' in b)); assert.strictEqual(b.key, 'K');
  const none = await T.testConnection(api, { sensor: 'h', key: '' });
  assert.strictEqual(none.ok, false);
});

test('keyItemId builds a valid Keychain id or nothing', () => {
  assert.strictEqual(T.keyItemId(' Sensor1.Example.com:443 '), 'sensor:sensor1.example.com:443');
  assert.strictEqual(T.keyItemId(''), '');
  assert.strictEqual(T.keyItemId('bad host'), '');
  assert.strictEqual(T.keyItemId('x'.repeat(80)), '');
});
