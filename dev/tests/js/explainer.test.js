'use strict';
// node --test dev/tests/js/explainer.test.js
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const X = require(path.join(__dirname, '..', '..', 'ui', 'explainer.js'));

class N {
  constructor(tag) { this.nodeType = 1; this.tagName = tag; this.children = []; this.parentNode = null; this.attributes = {}; this.listeners = {};
    this.dataset = {}; this._text = ''; this.className = ''; this.disabled = false; this.style = {setProperty(k, v) { this[k] = v; }}; }
  get firstChild() { return this.children[0] || null; }
  appendChild(c) { c.parentNode = this; this.children.push(c); return c; }
  removeChild(c) { const i = this.children.indexOf(c); if (i >= 0) this.children.splice(i, 1); return c; }
  setAttribute(k, v) { this.attributes[k] = String(v); }
  getAttribute(k) { return this.attributes[k] === undefined ? null : this.attributes[k]; }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  click() { (this.listeners.click || []).forEach(f => f({})); }
  set textContent(v) { this.children = []; this._text = String(v); }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  find(p, out = []) { if (p(this)) out.push(this); this.children.forEach(c => c.find(p, out)); return out; }
}
const DOC = {createElement: t => new N(t), createElementNS: (ns, t) => new N(t)};
const timers = {fns: [], set(f) { this.fns.push(f); return this.fns.length; }, clear(id) { this.fns[id - 1] = null; },
  tick() { this.fns.forEach(f => f && f()); }};
const mkEx = (extra) => X.buildExplainer(DOC, Object.assign({steps: ['a', 'b', 'c', 'd'], zonePath: ['user', 'server', 'edge'],
  setTimer: f => timers.set(f), clearTimer: id => timers.clear(id)}, extra || {}));
const caption = ex => ex.el.find(n => n.className === 'xplain-cap')[0];

test('hopForStep spreads steps over hops and handles a one-zone path', () => {
  assert.strictEqual(X.hopForStep(0, 4, 3), 0);
  assert.strictEqual(X.hopForStep(1, 4, 3), 0);
  assert.strictEqual(X.hopForStep(2, 4, 3), 1);
  assert.strictEqual(X.hopForStep(3, 4, 3), 1);
  assert.strictEqual(X.hopForStep(2, 4, 1), -1);
});

test('cleanPath drops unknown zones and repeats', () => {
  assert.deepStrictEqual(X.cleanPath(['user', 'user', 'mars', 'server']), ['user', 'server']);
  assert.deepStrictEqual(X.cleanPath(null), []);
});

test('zoneCounts counts a scenario once per zone and tolerates missing meta', () => {
  const c = X.zoneCounts([{meta: {zone_path: ['user', 'server', 'user']}}, {meta: {zone_path: ['ot']}}, {}, null]);
  assert.deepStrictEqual(c, {user: 1, server: 1, edge: 0, ot: 1});
  assert.ok(X.touchesZone({meta: {zone_path: ['edge']}}, 'edge'));
  assert.ok(!X.touchesZone({}, 'edge'));
});

test('drawMap marks hot zones and builds keyboard-operable zone buttons', () => {
  let got = null;
  const m = X.drawMap(DOC, {interactive: true, counts: {user: 3, server: 2, edge: 0, ot: 1}, onZone: z => { got = z; }});
  const g = m.zones.user;
  assert.strictEqual(g.getAttribute('role'), 'button');
  assert.strictEqual(g.getAttribute('tabindex'), '0');
  assert.match(g.getAttribute('aria-label'), /User network, 3 scenarios/);
  g.listeners.keydown[0]({key: 'Enter', preventDefault() {}});
  assert.strictEqual(got, 'user');
  g.click();
  assert.strictEqual(got, 'user');
});

test('explainer steps, bounds and caption', () => {
  const ex = mkEx();
  assert.strictEqual(caption(ex).textContent, 'a');
  ex.next(); ex.next();
  assert.strictEqual(ex.index(), 2);
  assert.strictEqual(caption(ex).textContent, 'c');
  ex.goto(99); assert.strictEqual(ex.index(), 3);
  ex.goto(-5); assert.strictEqual(ex.index(), 0);
  const prev = ex.el.find(n => n.attributes['data-act'] === 'xprev')[0];
  assert.ok(prev.disabled);
});

test('autoplay advances once through, then rests and stops', () => {
  timers.fns = [];
  const ex = mkEx({autoplay: true});
  assert.ok(ex.playing());
  timers.tick(); timers.tick(); timers.tick();
  assert.strictEqual(ex.index(), 3);
  timers.tick();
  assert.ok(!ex.playing());
  assert.strictEqual(caption(ex).getAttribute('aria-live'), 'polite');
});

test('manual step pauses autoplay', () => {
  timers.fns = [];
  const ex = mkEx({autoplay: true});
  ex.el.find(n => n.attributes['data-act'] === 'xnext')[0].click();
  assert.ok(!ex.playing());
  assert.strictEqual(ex.index(), 1);
});

test('reduced motion never auto-plays and disables play', () => {
  timers.fns = [];
  const ex = mkEx({autoplay: true, reduced: true});
  assert.ok(!ex.playing());
  assert.ok(ex.el.find(n => n.attributes['data-act'] === 'xplay')[0].disabled);
  assert.strictEqual(ex.el.getAttribute('data-reduced'), '1');
});

test('step list highlighting follows the current step', () => {
  const list = new N('ol'); for (let i = 0; i < 4; i++) { const li = new N('li'); li.className = 'stp2 on'; list.appendChild(li); }
  const ex = mkEx({listEl: list});
  ex.goto(2);
  assert.deepStrictEqual(list.children.map(li => li.className), ['stp2', 'stp2', 'stp2 cur', 'stp2']);
});

test('untrusted caption text is set as text, not markup', () => {
  const ex = mkEx({steps: ['<img src=x onerror=alert(1)>']});
  assert.strictEqual(caption(ex).textContent, '<img src=x onerror=alert(1)>');
  assert.strictEqual(caption(ex).children.length, 0);
});
