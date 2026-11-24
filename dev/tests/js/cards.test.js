'use strict';
// node --test dev/tests/js/cards.test.js
// Pure logic of dev/ui/scenario-cards.js plus its DOM builders against a tiny fake DOM.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const C = require(path.join(__dirname, '..', '..', 'ui', 'scenario-cards.js'));

class N {
  constructor(tag) {
    this.nodeType = tag === '#text' ? 3 : 1; this.tagName = tag.toUpperCase(); this.children = []; this.parentNode = null;
    this.attributes = {}; this.listeners = {}; this.dataset = {}; this._text = ''; this.className = ''; this.hidden = false;
    this.disabled = false; this.style = {setProperty(k, v) { this[k] = v; }};
  }
  get firstChild() { return this.children[0] || null; }
  appendChild(c) { if (c.parentNode) c.parentNode.removeChild(c); c.parentNode = this; this.children.push(c); return c; }
  removeChild(c) { const i = this.children.indexOf(c); if (i >= 0) this.children.splice(i, 1); c.parentNode = null; return c; }
  setAttribute(k, v) { this.attributes[k] = String(v); }
  getAttribute(k) { return this.attributes[k] === undefined ? null : this.attributes[k]; }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  click() { (this.listeners.click || []).forEach(f => f({preventDefault() {}, stopPropagation() {}})); }
  focus() { DOC.activeElement = this; }
  set textContent(v) { this.children = []; this._text = String(v); }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  find(p, out = []) { if (p(this)) out.push(this); this.children.forEach(c => c.find && c.find(p, out)); return out; }
}
const DOC = {activeElement: null, createElement: t => new N(t), createTextNode: t => { const n = new N('#text'); n._text = t; return n; }};
const mk = (name, prefix, cat, extra) => Object.assign({name, prefix, title: name + ' title', note: 'note ' + name, window: 'Start +8:05 → +8:20',
  pinned: false, recipe_driven: false, ot_only: false, meta: cat ? {category: cat, protocols: ['DNS'], hosts: ['h1'], steps: ['a', 'b', 'c', 'd'],
  expected_observation: 'obs ' + name, confidence: 'high', zone_path: ['user']} : undefined}, extra || {});
const TAX = {families: {SEC: ['Initial access', 'Discovery'], PERF: ['Capacity'], CRYP: ['Weak TLS'], REPLAY: ['Incident replay'], CUSTOM: ['Custom recipe']}};
const MODS = [mk('s1', 'NDR', 'Initial access'), mk('s2', 'NDR', 'Initial access'), mk('s3', 'NDR', 'Discovery'), mk('s4', 'NDR', null),
  mk('p1', 'NPM', 'Capacity'), mk('c1', 'CRP', 'Weak TLS'), mk('r1', 'IR', 'Incident replay'), mk('r2', 'IR', 'Incident replay'),
  mk('pin', 'NPM', null, {pinned: true}), mk('ot1', 'NDR', 'Discovery', {ot_only: true}), mk('rd', 'CUSTOM', null, {recipe_driven: true})];

test('shownModules drops pinned, recipe-driven and (without OT) OT-only', () => {
  assert.deepStrictEqual(C.shownModules(MODS).map(m => m.name), ['s1', 's2', 's3', 's4', 'p1', 'c1', 'r1', 'r2']);
  assert.ok(C.shownModules(MODS, {otLive: true}).some(m => m.name === 'ot1'));
});

test('grouping and counts, with an Uncategorised fallback bucket', () => {
  const model = C.buildModel(C.shownModules(MODS), TAX);
  assert.deepStrictEqual(model.map(f => f.key), ['SEC', 'PERF', 'CRYP', 'REPLAY']);
  const sec = model[0].categories;
  assert.deepStrictEqual(sec.map(c => c.name + ':' + c.items.length), ['Initial access:2', 'Discovery:1', 'Uncategorised:1']);
  assert.strictEqual(model[3].categories.length, 1);                       // replays are one entry
  const sel = new Set(['s1', 's4']);
  assert.deepStrictEqual(C.countsFor(sec[0].items, sel), {selected: 1, available: 2});
  assert.deepStrictEqual(C.countsFor(sec[2].items, sel), {selected: 1, available: 1});
});

test('empty taxonomy still groups everything (all Uncategorised) without throwing', () => {
  const model = C.buildModel(C.shownModules(MODS), {});
  assert.deepStrictEqual(model[0].categories.map(c => c.name), ['Initial access', 'Discovery', 'Uncategorised']);
});

test('coverage counts categories with a selection; replay and fallback are outside the total', () => {
  const model = C.buildModel(C.shownModules(MODS), TAX);
  let cov = C.coverage(model, new Set());
  assert.strictEqual(cov.total, 4);                                          // Initial access, Discovery, Capacity, Weak TLS
  assert.strictEqual(cov.covered, 0);
  cov = C.coverage(model, new Set(['s1', 's2', 'p1', 'r1', 's4']));
  assert.strictEqual(cov.covered, 2);
  assert.strictEqual(cov.text, '2 of 4 categories covered');
  assert.deepStrictEqual(cov.replay, {selected: 1, available: 2});
  assert.strictEqual(cov.pct, 50);
});

test('custom recipes become one static entry only when present', () => {
  assert.ok(!C.buildModel(C.shownModules(MODS), TAX).some(f => f.key === 'CUSTOM'));
  const m = C.buildModel(C.shownModules(MODS), TAX, {customRecipes: 2});
  const cus = m.find(f => f.key === 'CUSTOM');
  assert.ok(cus && cus.categories[0].static && cus.categories[0].recipes === 2);
  assert.strictEqual(C.coverage(m, new Set()).total, 4);
});

test('filter by text, family and category', () => {
  const shown = C.shownModules(MODS);
  assert.deepStrictEqual(C.filterModules(shown, {family: 'PERF'}).map(m => m.name), ['p1']);
  assert.deepStrictEqual(C.filterModules(shown, {category: 'SEC|Initial access'}).map(m => m.name), ['s1', 's2']);
  assert.deepStrictEqual(C.filterModules(shown, {category: 'SEC|Uncategorised'}).map(m => m.name), ['s4']);
  assert.deepStrictEqual(C.filterModules(shown, {category: 'REPLAY|*'}).map(m => m.name), ['r1', 'r2']);
  assert.deepStrictEqual(C.filterModules(shown, {text: 'weak tls'}).map(m => m.name), ['c1']);      // category
  assert.deepStrictEqual(C.filterModules(shown, {text: 'DNS capacity'}).map(m => m.name), ['p1']);  // protocol + category, AND
  assert.deepStrictEqual(C.filterModules(shown, {text: 'note s3'}).map(m => m.name), ['s3']);
  assert.deepStrictEqual(C.filterModules(shown, {text: 'zzz'}), []);
  assert.deepStrictEqual(C.familyCounts(shown), {ALL: 8, SELECTED: 0, OT: 0, SEC: 4, PERF: 1, CRYP: 1, REPLAY: 2});
});

test('parseWindow handles clock, hour and minute forms and rejects clock ranges', () => {
  const a = C.parseWindow('Start +8:05 → +8:20');
  assert.strictEqual(a.startMin, 485); assert.strictEqual(a.endMin, 500);
  assert.ok(Math.abs(a.left - 100 * 485 / 960) < 1e-9);
  assert.strictEqual(C.parseWindow('Start +8h → +9:45').endMin, 585);
  assert.strictEqual(C.parseWindow('Start +45m → +15h').startMin, 45);
  assert.strictEqual(C.parseWindow('10:15–21:00'), null);
  assert.strictEqual(C.parseWindow(''), null);
});

test('tab trap wraps at both edges and pulls stray focus in', () => {
  assert.strictEqual(C.wrapIndex(3, 2, false), 0);
  assert.strictEqual(C.wrapIndex(3, 0, true), 2);
  assert.strictEqual(C.wrapIndex(3, 1, false), 2);
  assert.strictEqual(C.wrapIndex(3, -1, false), 0);
  const box = new N('div'), a = new N('button'), dis = new N('button'), b = new N('button'), hid = new N('button'), neg = new N('button');
  dis.disabled = true; hid.hidden = true; neg.setAttribute('tabindex', '-1');
  [a, dis, neg, b, hid].forEach(x => box.appendChild(x));
  assert.deepStrictEqual(C.focusables(box), [a, b]);
  let prevented = 0; const ev = shift => ({key: 'Tab', shiftKey: shift, preventDefault() { prevented++; }});
  DOC.activeElement = b; assert.ok(C.trapTab(box, ev(false), DOC)); assert.strictEqual(DOC.activeElement, a);
  DOC.activeElement = a; assert.ok(C.trapTab(box, ev(true), DOC)); assert.strictEqual(DOC.activeElement, b);
  DOC.activeElement = new N('input'); assert.ok(C.trapTab(box, ev(false), DOC)); assert.strictEqual(DOC.activeElement, a);
  assert.strictEqual(prevented, 3);
  assert.ok(!C.trapTab(box, {key: 'Enter', preventDefault() {}}, DOC));
});

test('card renderer: fields, steps, chips, slot, no innerHTML use with server text', () => {
  const m = mk('x1', 'NDR', 'Discovery', {title: '<img src=x onerror=alert(1)>', note: '<b>n</b>'});
  m.meta.confidence = 'medium';
  const dlg = C.buildCard(DOC, m, {family: 'SEC', selected: false, canVisualize: true, pos: 2, count: 5, hasPrev: true, hasNext: false}, {});
  const all = dlg.find(() => true);
  assert.strictEqual(dlg.getAttribute('role'), 'dialog'); assert.strictEqual(dlg.getAttribute('aria-modal'), 'true');
  const title = all.find(n => n.getAttribute('id') === 'scard-title');
  assert.strictEqual(dlg.getAttribute('aria-labelledby'), 'scard-title');
  assert.strictEqual(title.textContent, '<img src=x onerror=alert(1)>');         // text, not markup
  assert.ok(!all.some(n => n.tagName === 'IMG'));
  const txt = dlg.textContent;
  ['Needs verification', 'Your sensor should show', 'obs x1', 'DNS', 'Hosts: h1', 'step by step', 'not visible on the wire', '2 of 5', 'Add to capture', 'Discovery'].forEach(s => assert.ok(txt.includes(s), s));
  assert.strictEqual(all.filter(n => n.tagName === 'LI').length, 4);
  assert.ok(all.some(n => n.className === 'wstrip'));
  const slot = all.find(n => n.className === 'scard-explainer-slot')[0] || all.filter(n => n.className === 'scard-explainer-slot')[0];
  assert.ok(slot && slot.children.length === 0 && slot.dataset.scenario === 'x1');
  const act = a => all.filter(n => n.dataset.act === a)[0];
  assert.ok(!act('prev').disabled); assert.ok(act('next').disabled); assert.ok(!act('viz').disabled);
});

test('card for a scenario without meta shows only existing fields', () => {
  const m = mk('x2', 'NDR', null);
  const dlg = C.buildCard(DOC, m, {family: 'SEC', selected: true, canVisualize: false, pos: 1, count: 1, hasPrev: false, hasNext: false}, {});
  const txt = dlg.textContent;
  assert.ok(txt.includes('note x2') && txt.includes('Uncategorised') && txt.includes('Remove from capture'));
  ['Your sensor should show', 'step by step', 'Hosts:', 'Needs verification'].forEach(s => assert.ok(!txt.includes(s), s));
  const all = dlg.find(() => true);
  assert.ok(all.filter(n => n.dataset.act === 'viz')[0].disabled);
});

test('rail renders pressed state, counts, per-category actions only on the active category', () => {
  const model = C.buildModel(C.shownModules(MODS), TAX);
  const host = new N('nav'); const calls = [];
  const cbs = {onCategory: k => calls.push(['cat', k]), onSelectAll: c => calls.push(['all', c.name]), onClear: c => calls.push(['clear', c.name])};
  C.renderRail(DOC, host, model, {category: 'SEC|Discovery', selected: new Set(['s3'])}, cbs);
  const btns = host.find(n => n.tagName === 'BUTTON');
  const disc = btns.find(b => b.dataset.key === 'SEC|Discovery' && !b.dataset.act);
  assert.strictEqual(disc.getAttribute('aria-pressed'), 'true');
  assert.ok(disc.textContent.includes('1 selected of 1'));
  assert.strictEqual(btns.filter(b => b.dataset.act).length, 2);
  btns.find(b => b.dataset.act === 'all').click(); btns.find(b => b.dataset.act === 'clear').click();
  disc.click();
  assert.deepStrictEqual(calls, [['all', 'Discovery'], ['clear', 'Discovery'], ['cat', null]]);   // click on the active category clears the filter
  assert.strictEqual(btns[0].textContent, 'All scenarios1 selected of 8');
});

test('coverage renderer gives a text equivalent', () => {
  const host = new N('div');
  C.renderCoverage(DOC, host, {covered: 7, total: 13, pct: 54, replay: {selected: 0, available: 9}, custom: null, text: '7 of 13 categories covered'});
  assert.strictEqual(host.getAttribute('aria-label'), '7 of 13 categories covered');
  assert.ok(host.textContent.includes('7 of 13 categories covered'));
});

test('XSS: rail, tools and rows never turn server text into elements', () => {
  const evil = [mk('e1', 'NDR', '<img onerror=1>', {title: '<script>x</script>'})];
  const model = C.buildModel(evil, TAX);
  const host = new N('nav');
  C.renderRail(DOC, host, model, {category: null, selected: new Set()}, {});
  assert.ok(!host.find(n => n.tagName === 'IMG' || n.tagName === 'SCRIPT').length);
  assert.ok(host.textContent.includes('<img onerror=1>'));
});

test('card shows the protocol check state and marks unconfirmed protocols', () => {
  const m = mk('s1', 'NDR', 'Discovery');
  m.meta.protocols = ['DNS', 'CAPWAP'];
  m.meta.protocols_check = {status: 'partial', checked: ['DNS'], carrier_only: [], unverified: ['CAPWAP']};
  const dlg = C.buildCard(DOC, m, {family: 'SEC', pos: 1, count: 1}, {});
  const chips = dlg.find(n => /cchip/.test(n.className)).map(n => n.textContent);
  assert.ok(chips.includes('Protocols partly checked'));
  const p = dlg.find(n => /pchip/.test(n.className));
  assert.deepStrictEqual(p.map(n => /pchip-un/.test(n.className)), [false, true]);
});

test('a multi-stage chain also covers the categories it passes through', () => {
  const chain = mk('chain', 'NDR', 'Multi-stage campaign', {}); chain.meta.also_categories = ['Impact'];
  const lone = mk('lone', 'NDR', 'Impact');
  const model = C.buildModel([chain, lone], {SEC: ['Impact', 'Multi-stage campaign']}, {});
  assert.strictEqual(C.coverage(model, new Set(['chain'])).covered, 2);   // its own category and Impact
  assert.strictEqual(C.coverage(model, new Set(['lone'])).covered, 1);
});

test('card says whether a scenario is fixed in size or grows with the size setting', () => {
  const a = mk('fix', 'NDR', 'Discovery'); a.meta.scale = {behaviour: 'fixed', points: []};
  const b = mk('grow', 'NDR', 'Discovery'); b.meta.scale = {behaviour: 'scales', points: []};
  const chips = m => C.buildCard(DOC, m, {family: 'SEC', pos: 1, count: 1}, {}).find(n => /cchip/.test(n.className)).map(n => n.textContent);
  assert.ok(chips(a).includes('Fixed size'));
  assert.ok(chips(b).includes('Grows with size'));
});

test('Selected and OT are filters of their own, and Selected follows the selection', () => {
  const a = mk('a', 'NDR', 'Discovery'), b = mk('b', 'NDR', 'Impact', {ot_only: true}), c = mk('c', 'NPM', 'Capacity');
  const all = [a, b, c];
  assert.deepStrictEqual(C.filterModules(all, {family: 'SELECTED', selected: new Set(['a', 'c'])}).map(m => m.name), ['a', 'c']);
  assert.deepStrictEqual(C.filterModules(all, {family: 'SELECTED', selected: new Set()}).map(m => m.name), []);
  assert.deepStrictEqual(C.filterModules(all, {family: 'OT'}).map(m => m.name), ['b']);
  const n = C.familyCounts(all, new Set(['a']));
  assert.strictEqual(n.SELECTED, 1); assert.strictEqual(n.OT, 1);
});

test('an open category lists its scenarios with a tick box each, and ticking reports the change', () => {
  const a = mk('a', 'NDR', 'Initial access'), b = mk('b', 'NDR', 'Initial access'), c = mk('c', 'NDR', 'Discovery');
  const model = C.buildModel([a, b, c], {SEC: ['Initial access', 'Discovery']}, {});
  const host = new N('nav'); const got = [];
  const key = model[0].categories.filter(x => x.name === 'Initial access')[0].key;
  C.renderRail(DOC, host, model, {category: key, selected: new Set(['a'])}, {onCategory() {}, onSelectAll() {}, onClear() {}, onItem: (n, on) => got.push([n, on]), onOpen() {}});
  const boxes = host.find(n => n.tagName === 'INPUT');
  assert.strictEqual(boxes.length, 2);                                   // only the open category lists its scenarios
  assert.deepStrictEqual(boxes.map(x => x.checked), [true, false]);
  boxes[1].checked = true; boxes[1].listeners.change[0]({});
  assert.deepStrictEqual(got, [['b', true]]);
  const closed = new N('nav');
  C.renderRail(DOC, closed, model, {category: null, selected: new Set()}, {onCategory() {}, onSelectAll() {}, onClear() {}, onItem() {}, onOpen() {}});
  assert.strictEqual(closed.find(n => n.tagName === 'INPUT').length, 0);
});

test('keepAnchored scrolls by exactly how far the acted-on item moved, and not at all when it did not', () => {
  const scrolls = [];
  const doc = {defaultView: {scrollBy: (x, y) => scrolls.push(y)}};
  const at = top => ({getBoundingClientRect: () => ({top})});
  C.keepAnchored(doc, at(340), 300);                 // the item moved down 40 px, so scroll down 40 to put it back
  C.keepAnchored(doc, at(300), 300);                 // unchanged
  C.keepAnchored(doc, at(300.3), 300);               // sub-pixel noise is ignored
  C.keepAnchored(doc, null, 300);                    // nothing to anchor to
  C.keepAnchored(doc, at(340), null);                // nothing was focused before the rebuild
  assert.deepStrictEqual(scrolls, [40]);
});

test('shift helpers: effective window, limits, linked pairs, collect and load', () => {
  const C = require(path.join(__dirname, '..', '..', 'ui', 'scenario-cards.js'));
  const a = {name: 'a', start_min: 60, end_min: 120, shift_limits: [-60, 30], shift_partner: 'b', window: 'Start +1h → +2h'};
  const b = {name: 'b', start_min: 90, end_min: 150, shift_limits: [-20, 100], shift_partner: 'a', window: 'Start +1:30 → +2:30'};
  const lock = {name: 'c', start_min: 10, end_min: 20, shift_limits: null, window: 'Start +10m → +20m'};
  const mods = [a, b, lock];
  assert.strictEqual(C.winOf(a).text, 'Start +1h → +2h');
  assert.strictEqual(C.formatWindow(45, 125), 'Start +45m → +2:05');
  assert.strictEqual(C.setShift(mods, 'a', 500, new Set(['a', 'b'])), 30);           // held to a's own limit
  assert.strictEqual(b.shift, 30);                                                   // the partner moves with it
  assert.strictEqual(C.setShift(mods, 'b', -50, new Set(['a', 'b'])), -20);          // the pair's shared range
  assert.strictEqual(a.shift, -20);
  assert.strictEqual(C.winOf(a).text, 'Start +40m → +1:40');
  assert.strictEqual(C.setShift(mods, 'a', 10, new Set(['a'])), 10);                 // partner not in the capture: alone
  assert.strictEqual(b.shift, -20);
  assert.strictEqual(C.setShift(mods, 'c', 5, null), 0);                             // locked
  assert.deepStrictEqual(C.collectShifts(mods, new Set(['a'])), {a: 10});
  C.loadShifts(mods, {a: -999, b: 7, c: 3});
  assert.deepStrictEqual([a.shift, b.shift, lock.shift], [-60, 7, 0]);
  C.loadShifts(mods, null);
  assert.deepStrictEqual(C.collectShifts(mods), {});
});
