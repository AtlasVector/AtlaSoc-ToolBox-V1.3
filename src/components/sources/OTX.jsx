import React from 'react';
import { InfoRow, Tag, ScoreRing, renderError } from '../ui.jsx';

export function renderOTX(d) {
  if (d.error) return renderError(d);
  const pulses = d.pulses ?? 0;
  const threatScore = d.threatScore ?? 0;
  const malwareFamilies = d.malwareFamilies || [];
  const adversaries = d.adversaries || [];
  const categories = d.categories || [];
  return (
    <div style={{display:'flex',flexDirection:'column',gap:16}}>
      <div style={{display:'flex',gap:20,alignItems:'center'}}>
        <ScoreRing score={pulses} max={50} label="Pulses" color={pulses>10?'var(--danger)':pulses>2?'var(--amber)':'var(--safe)'}/>
        <ScoreRing score={threatScore} max={10} label="Threat Score" color={threatScore>7?'var(--danger)':threatScore>4?'var(--amber)':'var(--safe)'}/>
        <div style={{flex:1}}>
          {d.firstSeen && <InfoRow label="First Seen" value={d.firstSeen} mono/>}
          {d.lastSeen && <InfoRow label="Last Seen" value={d.lastSeen} mono/>}
          {d.relatedIndicators != null && <InfoRow label="Related IoCs" value={d.relatedIndicators} mono/>}
        </div>
      </div>
      {malwareFamilies.length > 0 && <div><span style={{fontSize:11,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'0.05em'}}>Malware Families</span><div style={{display:'flex',gap:4,marginTop:6,flexWrap:'wrap'}}>{malwareFamilies.map(m=><Tag key={m} text={m} danger/>)}</div></div>}
      {adversaries.length > 0 && <div><span style={{fontSize:11,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'0.05em'}}>Adversaries</span><div style={{display:'flex',gap:4,marginTop:6}}>{adversaries.map(a=><Tag key={a} text={a} danger/>)}</div></div>}
      {categories.length > 0 && <div><span style={{fontSize:11,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'0.05em'}}>Categories</span><div style={{display:'flex',gap:4,marginTop:6,flexWrap:'wrap'}}>{categories.map(c=><Tag key={c} text={c} warn/>)}</div></div>}
      {malwareFamilies.length===0 && adversaries.length===0 && pulses===0 && <div style={{color:'var(--text-muted)',fontSize:13,padding:'8px 0'}}>No threat intelligence pulses found for this indicator.</div>}
    </div>
  );
}
