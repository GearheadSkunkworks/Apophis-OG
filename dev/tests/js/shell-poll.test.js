'use strict';
// guardedPoll lives in the inline script of ui/index.html; pull its source out and run it alone.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const html = fs.readFileSync(path.join(__dirname, '..', '..', 'ui', 'index.html'), 'utf8');
const m = html.match(/function guardedPoll\(tick, onLost\)\{[\s\S]*?\n\}\n/);
assert.ok(m, 'guardedPoll not found in index.html');
const guardedPoll = new Function(m[0] + '; return guardedPoll;')();

test('guardedPoll skips overlapping ticks', async () => {
  let calls = 0, release;
  const p = guardedPoll(() => { calls++; return new Promise(r => { release = r; }); }, () => {});
  const first = p();
  await p();
  assert.strictEqual(calls, 1);
  release(); await first;
  const second = p(); release(); await second;
  assert.strictEqual(calls, 2);
});

test('guardedPoll swallows errors and calls onLost after 5 in a row, once', async () => {
  let lost = 0;
  const p = guardedPoll(async () => { throw new Error('down'); }, () => { lost++; });
  for(let i = 0; i < 4; i++) await p();
  assert.strictEqual(lost, 0);
  await p(); await p();
  assert.strictEqual(lost, 1);
});

test('guardedPoll resets the failure count on success', async () => {
  let lost = 0, fail = true;
  const p = guardedPoll(async () => { if(fail) throw new Error('x'); }, () => { lost++; });
  for(let i = 0; i < 4; i++) await p();
  fail = false; await p(); fail = true;
  for(let i = 0; i < 4; i++) await p();
  assert.strictEqual(lost, 0);
});
