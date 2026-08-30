// Pure helper for the DNS Lookup source panel (src/components/sources/DNS.jsx).
// Kept separate so the row logic is unit-testable.

// A name with no record of the queried type (e.g. no MX) but an existing
// CNAME still gets that CNAME back in the answer to an MX query — so the
// same record can show up identically under several queried-type buckets.
// Flatten to one row per distinct (type, data) pair, labeled by the
// record's own actual type rather than the type it was queried under.
export function flattenDnsRecords(records, types) {
  const seen = new Set();
  const rows = [];
  for (const type of types) {
    for (const rec of records[type] || []) {
      const key = `${rec.type}:${rec.data}`;
      if (seen.has(key)) continue;
      seen.add(key);
      rows.push(rec);
    }
  }
  return rows;
}
