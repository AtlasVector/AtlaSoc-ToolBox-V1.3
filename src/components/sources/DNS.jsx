import React from 'react';
import { InfoRow, renderError } from '../ui.jsx';
import { flattenDnsRecords } from '../../lib/dns.js';

export function renderDNS(d) {
  if (d.error) return renderError(d);
  const records = d.records || {};
  const types = d.queriedTypes || Object.keys(records);
  if (!d.found) return <div style={{padding:'20px 0',textAlign:'center',color:'var(--text-muted)',fontSize:13}}>No DNS records found for {d.domain}</div>;
  const rows = flattenDnsRecords(records, types);
  return (
    <div>
      {rows.map((rec, i) => (
        <InfoRow key={`${rec.type}-${rec.data}-${i}`} label={rec.type !== rows[i - 1]?.type ? rec.type : ''} value={rec.data} mono/>
      ))}
    </div>
  );
}
