// Regression tests for the shared retry helper (functions/api/[[route]].js).
// Run with: node --test tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { withRetry } from '../functions/api/[[route]].js';

test('retries a transient (429) failure and eventually succeeds', async () => {
  let calls = 0;
  const result = await withRetry(async () => {
    calls++;
    if (calls < 2) { const e = new Error('rate limited'); e.status = 429; throw e; }
    return 'ok';
  });
  assert.equal(result, 'ok');
  assert.equal(calls, 2);
});

test('does not retry a non-429 4xx client error', async () => {
  let calls = 0;
  await assert.rejects(withRetry(async () => {
    calls++;
    const e = new Error('bad request');
    e.status = 400;
    throw e;
  }));
  assert.equal(calls, 1);
});

test('does not retry a timeout (AbortSignal.timeout) — retrying just re-spends the same timeout budget', async () => {
  let calls = 0;
  await assert.rejects(withRetry(async () => {
    calls++;
    const e = new DOMException('The operation was aborted due to timeout', 'TimeoutError');
    throw e;
  }));
  assert.equal(calls, 1);
});

test('does not retry a manually-aborted request (AbortController)', async () => {
  let calls = 0;
  await assert.rejects(withRetry(async () => {
    calls++;
    const e = new DOMException('This operation was aborted', 'AbortError');
    throw e;
  }));
  assert.equal(calls, 1);
});
