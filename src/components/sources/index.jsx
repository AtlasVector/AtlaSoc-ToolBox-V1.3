import React from 'react';
import { renderVT } from './VirusTotal.jsx';
import { renderAbuse } from './AbuseIPDB.jsx';
import { renderShodan } from './Shodan.jsx';
import { renderGreyNoise } from './GreyNoise.jsx';
import { renderOTX } from './OTX.jsx';
import { renderURLScan } from './URLScan.jsx';
import { renderWHOIS } from './WHOIS.jsx';
import { renderMalwareBazaar } from './MalwareBazaar.jsx';
import { renderCVE } from './CVE.jsx';
import { renderDNS } from './DNS.jsx';

// ─── Source panel dispatch ─────────────────────────────────────────────────
export function renderSource(d) {
  const payload = d.data || d;
  try {
    if (payload.source === 'VirusTotal') return renderVT(payload);
    if (payload.source === 'AbuseIPDB') return renderAbuse(payload);
    if (payload.source === 'Shodan') return renderShodan(payload);
    if (payload.source === 'GreyNoise') return renderGreyNoise(payload);
    if (payload.source === 'AlienVault OTX') return renderOTX(payload);
    if (payload.source === 'URLScan.io') return renderURLScan(payload);
    if (payload.source === 'WHOIS / RDAP') return renderWHOIS(payload);
    if (payload.source === 'MalwareBazaar') return renderMalwareBazaar(payload);
    if (payload.source === 'NVD / NIST' || payload.source === 'CIRCL CVE Search') return renderCVE(payload);
    if (payload.source === 'DNS Lookup') return renderDNS(payload);
    return null;
  } catch(e) {
    return <div style={{padding:16,color:'var(--text-muted)',fontSize:13,background:'var(--surface3)',borderRadius:8}}>
      <div style={{color:'var(--amber)',fontWeight:600,marginBottom:6}}>⚠ Could not render {payload.source} results</div>
      <div style={{fontFamily:'var(--mono)',fontSize:11,opacity:0.7}}>{e.message}</div>
    </div>;
  }
}
