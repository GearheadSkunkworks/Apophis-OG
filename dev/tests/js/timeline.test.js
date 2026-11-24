'use strict';
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const T = require(path.join(__dirname, '..', '..', 'ui', 'timeline.js'));

test('layout stacks overlapping markers into separate rows and reuses free rows', () => {
  const r = T.layout([{name: 'a', left: 0, width: 10}, {name: 'b', left: 5, width: 10}, {name: 'c', left: 12, width: 5}, {name: 'd', left: 20, width: 5}]);
  const row = n => r.items.find(i => i.name === n).row;
  assert.strictEqual(row('a'), 0); assert.strictEqual(row('b'), 1);
  assert.strictEqual(row('c'), 0);          // a ended at 10, so row 0 is free again
  assert.strictEqual(row('d'), 0);
  assert.strictEqual(r.rows, 2);
});

test('layout of nothing has one row and is stable for equal starts', () => {
  assert.strictEqual(T.layout([]).rows, 1);
  const r = T.layout([{name: 'b', left: 1, width: 4}, {name: 'a', left: 1, width: 4}]);
  assert.deepStrictEqual(r.items.map(i => i.name), ['a', 'b']);
});

test('ruler uses elapsed hours, never clock times', () => {
  const l = T.rulerLabels().map(x => x.text);
  assert.strictEqual(l[0], 'start'); assert.strictEqual(l[l.length - 1], '16 h');
  assert.ok(l.every(t => !/:/.test(t) && !/[ap]m/i.test(t)));
});

test('blocks that end and start together get different rows, so they never touch', () => {
  const r = T.layout([{name: 'a', left: 0, width: 10}, {name: 'b', left: 10, width: 10}]);
  assert.notStrictEqual(r.items[0].row, r.items[1].row);
  const far = T.layout([{name: 'a', left: 0, width: 10}, {name: 'b', left: 11, width: 10}]);
  assert.strictEqual(far.items[1].row, 0);      // a clear gap lets them share a row
});

test('dragging moves a marker by its share of the 16 hours, in whole minutes, held to its limits', () => {
  assert.strictEqual(T.dragShift(0, 100, 960, [-60, 60]), 60);        // 100 px of 960 = 100 min, held to +60
  assert.strictEqual(T.dragShift(0, 30, 960, [-60, 60]), 30);
  assert.strictEqual(T.dragShift(10, -45, 960, [-60, 60]), -35);
  assert.strictEqual(T.dragShift(0, 1, 1920, [-60, 60]), 1);          // 1 px of 1920 = 0.5 min rounds to 1: one-minute steps
  assert.strictEqual(T.dragShift(5, 40, 0, [-60, 60]), 5);            // no width, no move
  assert.strictEqual(T.dragShift(5, 40, 960, null), 5);               // locked scenarios never move
});
