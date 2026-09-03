// Regression tests for the client-side session cache in getLiveResults
// (src/lib/api.js) — re-analyzing the same indicator should not re-fire a
// fetch per source. Run with: node --test tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getLiveResults, ENDPOINT_MAP } from '../src/lib/api.js';

function fakeOkResponse(source) {
  return { ok: true, json: async () => ({ data: { source }, status: 'clean', cached: false, stale: false }) };
}

test('a repeat lookup of the same indicator reuses the cached result instead of refetching', async () => {
  const realFetch = global.fetch;
  let calls = 0;
  global.fetch = async (url) => { calls++; return fakeOkResponse(url); };
  try {
    const expectedCalls = Object.values(ENDPOINT_MAP).filter(types => types.includes('ip')).length;

    const first = await getLiveResults('203.0.113.9', 'ip');
    assert.equal(calls, expectedCalls);
    assert.equal(first.length, expectedCalls);

    const second = await getLiveResults('203.0.113.9', 'ip');
    assert.equal(calls, expectedCalls, 'second lookup of the same indicator must not fire new network calls');
    assert.deepEqual(second, first);
  } finally {
    global.fetch = realFetch;
  }
});

test('lookups of different indicators are not conflated by the cache', async () => {
  const realFetch = global.fetch;
  let calls = 0;
  global.fetch = async (url) => { calls++; return fakeOkResponse(url); };
  try {
    const expectedCalls = Object.values(ENDPOINT_MAP).filter(types => types.includes('domain')).length;
    await getLiveResults('example-a.com', 'domain');
    const callsAfterFirst = calls;
    await getLiveResults('example-b.com', 'domain');
    assert.equal(calls, callsAfterFirst + expectedCalls);
  } finally {
    global.fetch = realFetch;
  }
});
