'use strict';
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const H = require(path.join(__dirname, '..', '..', 'ui', 'help.js'));

const A = [
  {id: 'replay-a-capture', kind: 'workflow', title: 'Replay a capture', summary: 'Send a capture onto a network interface.', keywords: ['play back', 'send traffic'], where: 'Replay', related: [], body: 'Pick an interface.'},
  {id: 'build-a-capture', kind: 'workflow', title: 'Build a capture', summary: 'Make a pcap of a full day.', keywords: ['make a pcap', 'fake traffic'], where: 'Compose', related: [], body: 'Choose scenarios and press Generate.'},
  {id: 'lab-modules', kind: 'tool', title: 'Modules', summary: 'Load extra traffic modules.', keywords: ['plugins'], where: 'Lab', related: [], body: 'Replay is not involved.'}
];

test('search ignores filler words and finds by plain phrasing', () => {
  const p = H.prepare(A);
  assert.strictEqual(H.search(p, 'how do I replay a capture')[0].id, 'replay-a-capture');
  assert.strictEqual(H.search(p, 'make fake traffic')[0].id, 'build-a-capture');
  assert.strictEqual(H.search(p, 'captures')[0].kind, 'workflow');         // plural stems to the same word
});

test('every query word must hit, so a longer question narrows the list', () => {
  const p = H.prepare(A);
  assert.ok(H.search(p, 'replay').length >= 2);
  assert.deepStrictEqual(H.search(p, 'replay zebra').map(a => a.id), []);
  assert.deepStrictEqual(H.search(p, '   '), []);
});

test('title hits rank above body hits', () => {
  const r = H.search(H.prepare(A), 'replay');
  assert.strictEqual(r[0].id, 'replay-a-capture');
  assert.strictEqual(r[r.length - 1].id, 'lab-modules');
});

test('parseBody reads headings, steps, bullets, links and code', () => {
  const b = H.parseBody('Intro with [[build-a-capture]] and [[lab-modules|the tool]].\n\n## Steps\n1. Open `Compose`.\n   Then wait.\n2. Press Generate.\n\n- one\n- two');
  assert.deepStrictEqual(b.map(x => x.t), ['p', 'h', 'ol', 'ul']);
  assert.deepStrictEqual(b[0].runs.filter(r => r.link).map(r => r.link), ['build-a-capture', 'lab-modules']);
  assert.strictEqual(b[0].runs.find(r => r.link === 'lab-modules').text, 'the tool');
  assert.strictEqual(b[2].items.length, 2);
  assert.ok(b[2].items[0].some(r => r.code === 'Compose'));
  assert.ok(b[2].items[0].some(r => /Then wait/.test(r.text || '')));   // continuation line joins its step
  assert.deepStrictEqual(H.articleLinks(b), ['build-a-capture', 'lab-modules']);
});

test('markup is never treated as HTML', () => {
  const b = H.parseBody('<img src=x onerror=alert(1)> **bold**');
  assert.strictEqual(b[0].runs.length, 1);
  assert.ok(b[0].runs[0].text.indexOf('<img') === 0);   // kept as text; the renderer uses textContent only
});
