import React from 'react';
import { InfoRow, Tag, DetectionBar, renderError } from '../ui.jsx';

export function renderVT(d) {
  if (d.error) return renderError(d);
  const score = d.reputation ?? null;
  const harmless = d.harmless ?? 0;
  const suspicious = d.suspicious ?? 0;
  const undetected = d.undetected ?? 0;
  const engines = d.engines || [];
  return (
    <div style={{display:'flex',flexDirection:'column',gap:16}}>
      <DetectionBar detected={d.detected} total={d.total}/>
      <div style={{display:'flex',gap:16,flexWrap:'wrap'}}>
        {harmless > 0 && <span style={{fontSize:12,color:'var(--safe)'}}>✓ {harmless} harmless</span>}
        {suspicious > 0 && <span style={{fontSize:12,color:'var(--amber)'}}>⚠ {suspicious} suspicious</span>}
        {undetected > 0 && <span style={{fontSize:12,color:'var(--text-muted)'}}>— {undetected} undetected</span>}
      </div>
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12}}>
        <div>
          {d.country && <InfoRow label="Country" value={d.country}/>}
          {d.asOwner && <InfoRow label="AS Owner" value={d.asOwner}/>}
          {d.asn && <InfoRow label="ASN" value={String(d.asn)} mono/>}
          {d.network && <InfoRow label="Network" value={d.network} mono/>}
          {d.continent && <InfoRow label="Continent" value={d.continent}/>}
          {d.registrar && <InfoRow label="Registrar" value={d.registrar}/>}
          {d.creationDate && <InfoRow label="Created" value={d.creationDate} mono/>}
          {d.fileType && <InfoRow label="File Type" value={d.fileType}/>}
          {d.fileSize && <InfoRow label="File Size" value={d.fileSize}/>}
          {d.firstSeen && <InfoRow label="First Seen" value={d.firstSeen} mono/>}
          {d.lastAnalysis && <InfoRow label="Last Analysis" value={d.lastAnalysis} mono/>}
          {score != null && <InfoRow label="Reputation" value={score > 0 ? `+${score}` : String(score)} color={score>0?'var(--safe)':score<0?'var(--danger)':'var(--text-muted)'}/>}
          {d.permalink && <InfoRow label="Full Report" value={<a href={d.permalink} target="_blank" rel="noreferrer" style={{color:'var(--accent)',fontSize:12}}>Open in VirusTotal ↗</a>}/>}
        </div>
        <div>
          {d.categories?.length > 0 && <div style={{marginBottom:10}}><span style={{fontSize:11,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'0.05em'}}>Categories</span><div style={{display:'flex',flexWrap:'wrap',gap:4,marginTop:4}}>{d.categories.map(c=><Tag key={c} text={c} danger/>)}</div></div>}
          {d.tags?.length > 0 && <div style={{marginBottom:10}}><span style={{fontSize:11,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'0.05em'}}>Tags</span><div style={{display:'flex',flexWrap:'wrap',gap:4,marginTop:4}}>{d.tags.map(t=><Tag key={t} text={t} danger={t!=='clean'}/>)}</div></div>}
          {engines.length > 0 && <div><span style={{fontSize:11,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'0.05em'}}>Detections ({engines.length})</span><div style={{marginTop:6,display:'flex',flexDirection:'column',gap:3}}>{engines.map((e,i)=><div key={i} style={{display:'flex',gap:6,fontSize:11,padding:'3px 0',borderBottom:'1px solid var(--border)'}}><span style={{color:e.category==='malicious'?'var(--danger)':'var(--amber)',flexShrink:0,width:14}}>{'●'}</span><span style={{color:'var(--text-dim)',flexShrink:0,minWidth:100}}>{e.name}</span><span style={{fontFamily:'var(--mono)',color:'var(--text-muted)',wordBreak:'break-all'}}>{e.result}</span></div>)}</div></div>}
        </div>
      </div>
    </div>
  );
}
