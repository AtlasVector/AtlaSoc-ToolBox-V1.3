// Regression tests for the Windows Event ID reference (src/lib/utilities/eventIds.js).
// Run with: node --test tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { searchEventIds, WINDOWS_EVENT_IDS } from '../src/lib/utilities/eventIds.js';

const VALID_SEVERITIES = ['info', 'suspicious', 'critical'];

test('partial prefix surfaces multiple matches while typing', () => {
  const r = searchEventIds('462');
  const ids = r.map(m => m.id);
  assert.deepEqual(ids, [4624, 4625]);
});

test('a full ID that is also unambiguous returns a single match', () => {
  const r = searchEventIds('7045');
  assert.equal(r.length, 1);
  assert.equal(r[0].id, 7045);
});

test('results are sorted ascending by ID', () => {
  const r = searchEventIds('4');
  for (let i = 1; i < r.length; i++) assert.ok(r[i].id > r[i - 1].id);
  assert.ok(r.some(m => m.id === 4104));
});

test('no matches returns an empty array, not an error', () => {
  assert.deepEqual(searchEventIds('9999'), []);
});

test('empty or whitespace query returns an empty array', () => {
  assert.deepEqual(searchEventIds(''), []);
  assert.deepEqual(searchEventIds('   '), []);
});

test('every table entry has a valid severity and a non-empty key-fields list', () => {
  for (const [id, entry] of Object.entries(WINDOWS_EVENT_IDS)) {
    assert.ok(VALID_SEVERITIES.includes(entry.severity), `${id} has invalid severity "${entry.severity}"`);
    assert.ok(Array.isArray(entry.keyFields) && entry.keyFields.length > 0, `${id} is missing keyFields`);
  }
});
