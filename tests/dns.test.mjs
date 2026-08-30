// Regression tests for the DNS Lookup panel's row flattening (src/lib/dns.js).
// Run with: node --test tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { flattenDnsRecords } from '../src/lib/dns.js';

test('labels a CNAME-chased answer by its own type, not the queried type', () => {
  // eu.qualtrics.com has no MX record but does have a CNAME, so a DoH
  // resolver returns the CNAME as the answer to an MX query too.
  const cname = { name: 'eu.qualtrics.com', type: 'CNAME', TTL: 300, data: 'cloudenhanced.qualtrics.com.edgekey.net.' };
  const records = {
    A: [cname],
    AAAA: [cname],
    CNAME: [cname],
    MX: [cname],
  };
  const rows = flattenDnsRecords(records, ['A', 'AAAA', 'CNAME', 'MX']);
  assert.deepEqual(rows, [cname]);
  assert.equal(rows[0].type, 'CNAME');
});

test('keeps distinct records for the same queried type separate', () => {
  const records = {
    A: [
      { name: 'example.com', type: 'A', TTL: 300, data: '1.1.1.1' },
      { name: 'example.com', type: 'A', TTL: 300, data: '2.2.2.2' },
    ],
  };
  const rows = flattenDnsRecords(records, ['A']);
  assert.equal(rows.length, 2);
  assert.deepEqual(rows.map(r => r.data), ['1.1.1.1', '2.2.2.2']);
});

test('preserves queried-type order for unrelated record sets', () => {
  const records = {
    A: [{ name: 'x', type: 'A', TTL: 60, data: '1.1.1.1' }],
    TXT: [{ name: 'x', type: 'TXT', TTL: 60, data: 'v=spf1 -all' }],
  };
  const rows = flattenDnsRecords(records, ['A', 'TXT']);
  assert.deepEqual(rows.map(r => r.type), ['A', 'TXT']);
});
