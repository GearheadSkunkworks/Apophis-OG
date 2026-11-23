'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

function load() {
  const sandbox = { window: {}, console };
  sandbox.window.OGC = { registered: [], registerStep(s) { this.registered.push(s); } };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(path.join(__dirname, '..', '..', 'ui', 'campaigns-library.js'), 'utf8'),
    sandbox, { filename: 'campaigns-library.js' });
  return sandbox.window.OGC;
}
const raw = load()._test;
// results come from another vm realm; normalise so deepStrictEqual compares structure only
const T = {};
for (const k of Object.keys(raw)) T[k] = typeof raw[k] === 'function' ? (...a) => { const r = raw[k](...a); return r === undefined ? r : JSON.parse(JSON.stringify(r)); } : raw[k];

test('slugify and safe filename', () => {
  assert.strictEqual(T.slugify('PHP2Shell Demo!'), 'php2shell-demo');
  assert.strictEqual(T.slugify('../../etc/passwd'), 'etc-passwd');
  assert.strictEqual(T.slugify('   '), 'campaign');
  assert.strictEqual(T.slugify(null), 'campaign');
  assert.ok(T.slugify('x'.repeat(200)).length <= 64);
  assert.match(T.slugify('Ünï cödé'), /^[a-z0-9_-]{1,64}$/);
  assert.strictEqual(T.safeFilename('A/B\\C"'), 'a-b-c.campaign.json');
});

test('relative time', () => {
  const now = Date.parse('2026-11-19T12:00:00Z');
  assert.strictEqual(T.relativeTime(now / 1000 - 10, now), 'just now');
  assert.strictEqual(T.relativeTime('2026-11-19T11:30:00Z', now), '30 minutes ago');
  assert.strictEqual(T.relativeTime('2026-11-19T09:00:00Z', now), '3 hours ago');
  assert.strictEqual(T.relativeTime('2026-11-18T12:00:00Z', now), '1 day ago');
  assert.strictEqual(T.relativeTime('2026-08-19T12:00:00Z', now), '3 months ago');
  assert.strictEqual(T.relativeTime('2027-01-01T00:00:00Z', now), 'just now');
  assert.strictEqual(T.relativeTime('garbage', now), '');
  assert.strictEqual(T.relativeTime(undefined, now), '');
});

test('REAL confirmation is exact', () => {
  assert.ok(T.realConfirmed('REAL'));
  for (const s of ['real', 'Real', 'REAL ', ' REAL', '', 'REALL', null, undefined]) assert.ok(!T.realConfirmed(s), String(s));
});

test('generateExtras logic', () => {
  const c = { meta: { name: 'X' }, stages: [] };
  assert.deepStrictEqual(T.buildExtras({ armed: false, campaign: c, mode: 'mapped' }), {});
  assert.deepStrictEqual(T.buildExtras({ armed: true, campaign: null }), {});
  assert.deepStrictEqual(T.buildExtras({ armed: true, campaign: c, check: { errors: ['bad'] } }), {});
  assert.deepStrictEqual(T.buildExtras({ armed: true, campaign: c, check: { errors: [] }, mode: 'mapped' }),
    { campaigns: [c], address_mode: 'mapped', confirm_real_addresses: false });
  assert.deepStrictEqual(T.buildExtras({ armed: true, campaign: c, check: null, mode: 'real', confirmed: false }),
    { campaigns: [c], address_mode: 'real', confirm_real_addresses: false });
  assert.strictEqual(T.buildExtras({ armed: true, campaign: c, mode: 'real', confirmed: true }).confirm_real_addresses, true);
  assert.strictEqual(T.buildExtras({ armed: true, campaign: c, mode: 'mapped', confirmed: true }).confirm_real_addresses, false);
  assert.deepStrictEqual(T.buildExtras(null), {});
});

test('applyMeta copies and does not mutate', () => {
  const c = { meta: { name: 'A', id: 'a' }, stages: [] };
  const d = T.applyMeta(c, ' New ', 'desc');
  assert.strictEqual(d.meta.name, 'New'); assert.strictEqual(d.meta.description, 'desc');
  assert.strictEqual(c.meta.name, 'A');
  assert.strictEqual(T.applyMeta(null, 'x', 'y'), null);
  assert.strictEqual(T.applyMeta(c, '  ', null).meta.name, 'A');
});

test('campaignSummary', () => {
  const c = { iocs: [{}, {}], stages: [{ techniques: ['T1', 'T2'], actions: [{}, {}] }, { techniques: ['T2'], actions: [{}] }] };
  assert.deepStrictEqual(T.campaignSummary(c, null), { stages: 2, actions: 3, iocs: 2, techniques: 2, estimate: null });
  assert.deepStrictEqual(T.campaignSummary(null).stages, 0);
});

// shape taken from a real build (php2shell fixture, scale 0.001): console lines + counts
const CONSOLE = [
  '=== Campaign: T (mapped addresses) ===', '',
  '[10:00:00] Stage 1/6: Execution (T1105) [execution]',
  '    the payload is fetched and runs on the workstation',
  '  [10:00:00] $ payload_download filename=invoice.exe filetype=exe path=/invoice.exe scheme=https size=150000 ws (10.10.10.147) -> ioc:2 (198.19.120.208)',
  '      186 packets, 159.5 KB, DNS/HTTP/HTTPS', '',
  '[10:00:25] Stage 2/6: Command And Control (T1071.001, T1573.002) [command-and-control]',
  '  [10:00:25] $ beacon sleep 60 20 -> 198.18.162.20 (https_beacon x4)',
  '      92 packets, 18.1 KB, DNS/TLS/HTTPS',
  '=== 2 of 2 actions emitted 278 packets (177 KB) ==='
];
const ENTRIES = [
  { stage: 's1', stage_name: 'Execution', action: 'payload_download', from: 'ws', to: 'payload:0', ioc: [2], packets: 186, bytes: 163000,
    protocols: ['DNS', 'HTTP'], techniques: ['T1105'], status: 'ok', from_host: { name: 'WS1', ip: '10.10.10.147' }, to_host: { name: 'x', ip: '198.19.120.208' } },
  { stage: 's2', stage_name: 'C2', action: 'https_beacon', from: 'ws', to: 'c2:0', ioc: [0], packets: 92, bytes: 18000, protocols: ['TLS'], techniques: ['T1071.001'], status: 'ok' },
  { stage: 's2', stage_name: 'C2', action: 'ldap_recon', from: 'ws', to: 'dc', ioc: [], packets: 0, bytes: 0, protocols: [], techniques: ['T1087.002'], status: 'skipped', error: 'missing host DC9' },
  { stage: 's3', stage_name: 'Impact', action: 'x', from: 'ws', to: 'dc', ioc: [], packets: 0, bytes: 0, status: 'failed', error: 'boom' }
];
const SUMMARY = {
  campaign: { built: ['t'], exports: { t: { campaign: '/tmp/o.campaign.json', stix: '/tmp/o.campaign-iocs.stix.json', navigator: '/tmp/o.attack-navigator.json', report: '/tmp/o.campaign-report.md' } },
              errors: [{ stage: 's2', action: 'ldap_recon', error: 'missing host DC9' }, 'plain'], actions: 4, emitted: 2,
              entries: ENTRIES,
              iocs: [{ index: 0, type: 'ipv4', value: '203.0.113.77', role: 'c2', address: '198.18.162.20' },
                     { index: 2, type: 'url', value: 'https://files.example/invoice.exe', role: 'payload', address: '198.19.120.208' },
                     { index: 5, type: 'sha256', value: 'abc', role: 'payload', address: '' }] },
  campaign_console: CONSOLE
};

test('parseConsole fallback matches real console format', () => {
  const e = T.parseConsole(CONSOLE);
  assert.strictEqual(e.length, 2);
  assert.strictEqual(e[0].stage, 's1'); assert.strictEqual(e[0].action, 'payload_download');
  assert.strictEqual(e[0].packets, 186); assert.deepStrictEqual(e[0].protocols, ['DNS', 'HTTP', 'HTTPS']);
  assert.strictEqual(e[0].status, 'ok');
  assert.strictEqual(e[1].action, 'beacon'); assert.strictEqual(e[1].packets, 92);
  assert.deepStrictEqual(T.parseConsole(null), []);
});

test('actionRows from entries and from console only', () => {
  const r = T.actionRows(SUMMARY);
  assert.strictEqual(r.length, 4);
  assert.strictEqual(r[0].status, 'ok'); assert.strictEqual(r[0].packets, 186);
  assert.match(r[0].from, /WS1/); assert.strictEqual(r[2].status, 'skipped'); assert.strictEqual(r[3].status, 'failed');
  const r2 = T.actionRows({ campaign: { actions: 2 }, campaign_console: CONSOLE });
  assert.strictEqual(r2.length, 2); assert.strictEqual(r2[0].status, 'ok');
  assert.deepStrictEqual(T.actionRows({}), []);
  assert.deepStrictEqual(T.actionRows(undefined), []);
});

test('iocRows only observable, emitted indicators', () => {
  const rows = T.iocRows(SUMMARY, null);
  assert.strictEqual(rows.length, 2);
  assert.deepStrictEqual(rows.map(r => r.address), ['198.19.120.208', '198.18.162.20']);
  assert.strictEqual(rows[0].packets, 186);
  assert.deepStrictEqual(T.iocRows({ campaign: {} }, null), []);
  const noTable = T.iocRows({ campaign: { entries: ENTRIES } }, { iocs: [{ type: 'ipv4', value: '1.2.3.4', role: 'c2' }, 0, { type: 'url', value: 'u', role: 'payload' }] });
  assert.strictEqual(noTable.length, 2);
});

test('coverage computation', () => {
  const camp = { expect: [{ technique: 'T1105', stage: 's1' }, { technique: 'T1087.002', stage: 's2' }, { technique: 'T9', stage: 's3' }] };
  const c = T.coverage(SUMMARY, camp);
  assert.strictEqual(c.known, true);
  assert.deepStrictEqual(c.rows.map(r => r.state), ['covered', 'missing', 'missing']);
  assert.strictEqual(c.covered, 1); assert.strictEqual(c.missing, 2);
  const u = T.coverage({ campaign: {} }, camp);
  assert.strictEqual(u.known, false); assert.ok(u.rows.every(r => r.state === 'unknown'));
  assert.deepStrictEqual(T.coverage(null, null).rows, []);
});

test('headline, exportList, errorList tolerate missing keys', () => {
  assert.match(T.headline(SUMMARY), /^2 of 4 actions emitted, 278 packets/);
  assert.match(T.headline({ campaign: { error: 'X: y' } }), /could not be added: X: y/);
  assert.strictEqual(T.headline({ campaign: {} }), '0 of 0 actions emitted');
  assert.strictEqual(T.exportList(SUMMARY).length, 4);
  assert.deepStrictEqual(T.exportList({}), []);
  assert.deepStrictEqual(T.exportList({ campaign: { exports: { a: null } } }), []);
  assert.deepStrictEqual(T.errorList(SUMMARY), ['stage s2, ldap_recon: missing host DC9', 'plain']);
  assert.deepStrictEqual(T.errorList(null), []);
  assert.strictEqual(T.fmtBytes(1536), '1.5 KB');
});

test('script registers nothing without a DOM and does not throw', () => {
  const o = load();
  assert.strictEqual(typeof o._test.slugify, 'function');
  assert.strictEqual(o.registered.length, 0);
});
