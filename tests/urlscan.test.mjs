// Regression tests for URLScan result validation (functions/api/[[route]].js).
// Run with: node --test tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handleURLScan, urlscanDomainMatches } from '../functions/api/[[route]].js';

function fakeSearchResponse(domain) {
  return {
    ok: true,
    json: async () => ({
      results: [{
        _id: 'abc123',
        page: { domain, ip: '1.2.3.4', country: 'US', server: 'nginx', title: `${domain} title` },
        verdicts: {},
      }],
    }),
  };
}

test('urlscanDomainMatches accepts exact, subdomain, and parent-domain relations', () => {
  assert.equal(urlscanDomainMatches('eu.qualtrics.com', 'eu.qualtrics.com'), true);
  assert.equal(urlscanDomainMatches('qualtrics.com', 'eu.qualtrics.com'), true);
  assert.equal(urlscanDomainMatches('eu.qualtrics.com', 'qualtrics.com'), true);
});

test('urlscanDomainMatches rejects unrelated domains', () => {
  assert.equal(urlscanDomainMatches('eu.qualtrics.com', 'echogear.com'), false);
  assert.equal(urlscanDomainMatches('google.com', 'notgoogle.com'), false);
});

test('handleURLScan discards a top hit for an unrelated domain instead of returning it', async () => {
  const realFetch = global.fetch;
  global.fetch = async () => fakeSearchResponse('echogear.com');
  try {
    const result = await handleURLScan('eu.qualtrics.com', 'domain', {});
    assert.deepEqual(result, { source: 'URLScan.io', found: false });
  } finally {
    global.fetch = realFetch;
  }
});

test('handleURLScan returns the hit when its domain matches the query', async () => {
  const realFetch = global.fetch;
  global.fetch = async () => fakeSearchResponse('eu.qualtrics.com');
  try {
    const result = await handleURLScan('eu.qualtrics.com', 'domain', {});
    assert.equal(result.found, true);
    assert.equal(result.title, 'eu.qualtrics.com title');
  } finally {
    global.fetch = realFetch;
  }
});
