import React from 'react';
import { InfoRow } from '../ui.jsx';

export function renderWHOIS(d) {
  if (d.error) return <div style={{padding:'24px 0',textAlign:'center',color:'var(--text-muted)'}}><div style={{fontSize:32,marginBottom:8}}>📋</div><div style={{color:'var(--amber)',fontWeight:600,marginBottom:4}}>WHOIS lookup failed</div><div style={{fontSize:12}}>{d.error}</div></div>;
  const nameservers = d.nameservers || [];
  const status = Array.isArray(d.status) ? d.status : [d.status].filter(Boolean);
  return (
    <div>
      {d.handle && <InfoRow label="Handle" value={d.handle} mono/>}
      {d.name && <InfoRow label="Name" value={d.name}/>}
      {d.registrar && <InfoRow label="Registrar" value={d.registrar}/>}
      {d.privacyProtected && <InfoRow label="Privacy" value="Protected (Redacted)" color="var(--text-muted)"/>}
      {d.created && <InfoRow label="Created" value={d.created} mono/>}
      {d.updated && <InfoRow label="Updated" value={d.updated} mono/>}
      {d.expires && <InfoRow label="Expires" value={d.expires} mono/>}
      {d.country && <InfoRow label="Country" value={d.country}/>}
      {d.asn && <InfoRow label="ASN" value={d.asn} mono/>}
      {d.cidr && <InfoRow label="CIDR" value={d.cidr} mono/>}
      {d.startAddress && <InfoRow label="IP Range Start" value={d.startAddress} mono/>}
      {d.endAddress && <InfoRow label="IP Range End" value={d.endAddress} mono/>}
      {nameservers.map((ns,i)=><InfoRow key={i} label={i===0?'Nameservers':''} value={ns} mono/>)}
      {status.length > 0 && <InfoRow label="Status" value={status.join(', ')} mono/>}
    </div>
  );
}
