// Regression tests for the source-tab pill logic (src/lib/sourceBadges.js).
// Run with: node --test tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { freshnessBadge, statusBadge } from '../src/lib/sourceBadges.js';

test('freshnessBadge reports STALE, then CACHED, then nothing', () => {
  assert.equal(freshnessBadge({ _stale: true, _cached: true }), 'STALE');
  assert.equal(freshnessBadge({ _stale: false, _cached: true }), 'CACHED');
  assert.equal(freshnessBadge({ _stale: false, _cached: false }), null);
});

test('statusBadge never claims LIVE for a stale or cached response', () => {
  assert.equal(statusBadge({ _stale: true }, null), null);
  assert.equal(statusBadge({ _cached: true }, null), null);
});

test('statusBadge reports LIVE only for a fresh, error-free response', () => {
  assert.equal(statusBadge({}, null), 'LIVE');
});

test('statusBadge prioritizes emptyState (INFO) and error (ERR) over freshness', () => {
  assert.equal(statusBadge({ _stale: true }, 'not configured'), 'INFO');
  assert.equal(statusBadge({ _stale: true, error: 'boom' }, null), 'ERR');
});
