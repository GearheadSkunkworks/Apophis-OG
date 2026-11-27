'use strict';
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const O = require(path.join(__dirname, '..', '..', 'ui', 'build-options.js'));
const S = require(path.join(__dirname, '..', '..', 'ui', 'slice-preview.js'));
const T = require(path.join(__dirname, '..', '..', 'ui', 'build-options.json'));

test('everything off sends nothing, so a default build is unchanged', () => {
  assert.deepStrictEqual(O.collect(T, O.defaults(T)), {});
  assert.strictEqual(O.summary(T, O.defaults(T), 'network'), 'Off');
});

test('vlan: scheme subnet, fixed with an id, and an outer tag only when asked for', () => {
  const st = O.defaults(T);
  st.vlan.on = true;
  assert.deepStrictEqual(O.collect(T, st), {network_options: {vlan: {scheme: 'subnet'}}});
  st.vlan.p.scheme = 'fixed'; st.vlan.p.vid = 20;
  assert.deepStrictEqual(O.collect(T, st), {network_options: {vlan: {scheme: 'fixed', vid: 20}}});
  st.vlan.p.qinq = true; st.vlan.p.svid = 300;
  assert.deepStrictEqual(O.collect(T, st), {network_options: {vlan: {scheme: 'fixed', vid: 20, qinq: 300}}});
  st.vlan.p.scheme = 'subnet';                       // a hidden id is not sent
  assert.deepStrictEqual(O.collect(T, st).network_options.vlan, {scheme: 'subnet', qinq: 300});
});

test('exports are a sorted list of the rows switched on', () => {
  const st = O.defaults(T);
  st.pcapng.on = true; st.truth.on = true;
  assert.deepStrictEqual(O.collect(T, st), {exports: ['pcapng', 'truth']});
  assert.strictEqual(O.summary(T, st, 'exports'), '2 on');
  st.pcapng.on = false;
  assert.strictEqual(O.summary(T, st, 'exports'), 'On: ' + T.options.find(r => r.id === 'truth').label);
});

test('the estimate grows only for switched-on rows, from the row figures', () => {
  const st = O.defaults(T);
  assert.deepStrictEqual(O.extras(T, st, 1, 1), {gb: 0, seconds: 0, files: 0, names: []});
  st.pcapng.on = true; st.vlan.on = true;
  const x = O.extras(T, st, 2, 1.5);
  const pn = T.options.find(r => r.id === 'pcapng').est;
  assert.ok(Math.abs(x.gb - (pn.pcap_ratio * 1.5 + 4 * 2e6 / 1e9)) < 1e-9);
  assert.strictEqual(x.files, 1);
});

test('slice preview mirrors the slicer: padding, merged stretches, honest counts', () => {
  const sc = {observed: {packets: 40, first_ts: 1300, last_ts: 1805}, active_spans: [[1300, 1310, 11], [1800, 1805, 6]]};
  const a = S.preview(sc, 'A', 10, null);
  assert.deepStrictEqual([a.ok, a.exact, a.spans, a.seconds], [true, false, 1, 505 + 22]);
  const c = S.preview(sc, 'C', 10, null);
  assert.deepStrictEqual([c.exact, c.packets, c.spans, c.seconds], [true, 17, 2, 10 + 22 + 5 + 22]);
  assert.strictEqual(S.preview(sc, 'B', 10, null).exact, false);       // background rides along
  assert.strictEqual(S.preview(sc, 'C', 600, null).spans, 1);          // wide padding merges the stretches
  assert.strictEqual(S.preview({observed: {packets: 3, first_ts: 1, last_ts: 2}}, 'B', 0, null).ok, false);
  assert.strictEqual(S.preview({observed: {packets: 0, first_ts: null}}, 'A', 0, null).ok, false);
  assert.strictEqual(S.fmtDuration(45), '45 seconds'); assert.strictEqual(S.fmtDuration(600), '10 minutes');
});
