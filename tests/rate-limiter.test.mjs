// Regression tests for the KV-backed rate limiter (functions/api/[[route]].js).
// Run with: node --test tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isRateLimited } from '../functions/api/[[route]].js';

// Minimal in-memory stand-in for the Cloudflare KV binding.
function fakeKV() {
  const store = new Map();
  return {
    async get(key) { return store.has(key) ? store.get(key) : null; },
    async put(key, value) { store.set(key, value); },
  };
}

test('allows requests when no KV binding is configured (local dev)', async () => {
  assert.equal(await isRateLimited(undefined, '1.2.3.4'), false);
});

test('allows requests under the per-IP cap', async () => {
  const kv = fakeKV();
  for (let i = 0; i < 5; i++) {
    assert.equal(await isRateLimited(kv, '1.2.3.4', 5, 1000), false);
  }
});

test('blocks once the per-IP cap is exceeded', async () => {
  const kv = fakeKV();
  for (let i = 0; i < 3; i++) await isRateLimited(kv, '1.2.3.4', 3, 1000);
  assert.equal(await isRateLimited(kv, '1.2.3.4', 3, 1000), true);
});

test('does not let a different IP bypass its own per-IP cap', async () => {
  const kv = fakeKV();
  for (let i = 0; i < 3; i++) await isRateLimited(kv, '1.2.3.4', 3, 1000);
  assert.equal(await isRateLimited(kv, '5.6.7.8', 3, 1000), false);
});

test('blocks once the coarse global cap is exceeded, even across many IPs', async () => {
  const kv = fakeKV();
  for (let i = 0; i < 3; i++) {
    assert.equal(await isRateLimited(kv, `10.0.0.${i}`, 100, 3), false);
  }
  assert.equal(await isRateLimited(kv, '10.0.0.99', 100, 3), true);
});

test('fails CLOSED (blocks) when the KV binding throws', async () => {
  const brokenKV = {
    async get() { throw new Error('KV unavailable'); },
    async put() {},
  };
  assert.equal(await isRateLimited(brokenKV, '1.2.3.4'), true);
});
