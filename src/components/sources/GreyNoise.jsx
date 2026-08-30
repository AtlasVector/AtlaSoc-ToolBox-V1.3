import React from 'react';
import { InfoRow, Tag, renderError } from '../ui.jsx';

export function renderGreyNoise(d) {
  if (d.error) return renderError(d);
  if (!d.found) return <div style={{padding:'24px 0',textAlign:'center',color:'var(--text-muted)'}}><div style={{fontSize:32,marginBottom:8}}>🌫️</div><div>No GreyNoise data found for this IP</div></div>;
  const classification = d.classification || 'unknown';
  return (
    <div style={{display:'flex',flexDirection:'column',gap:12}}>
      <div style={{display:'flex',gap:8,flexWrap:'wrap'}}>
        <Tag text={classification} danger={classification==='malicious'} warn={classification==='unknown'}/>
        {d.noise && <Tag text="internet scanner" warn/>}
        {d.riot && <Tag text="known benign service (RIOT)"/>}
      </div>
      {d.name && <InfoRow label="Actor / Name" value={d.name}/>}
      {d.lastSeen && <InfoRow label="Last Seen" value={d.lastSeen} mono/>}
      {d.message && <InfoRow label="Message" value={d.message}/>}
    </div>
  );
}
