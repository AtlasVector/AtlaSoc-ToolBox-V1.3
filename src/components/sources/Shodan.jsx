import React from 'react';
import { InfoRow, Tag, renderError } from '../ui.jsx';

export function renderShodan(d) {
  if (d.error) return renderError(d);
  if (!d.found) return <div style={{padding:'24px 0',textAlign:'center',color:'var(--text-muted)'}}><div style={{fontSize:32,marginBottom:8}}>📡</div><div>No Shodan data found for this IP</div></div>;
  const ports = d.ports || [];
  const hostnames = d.hostnames || [];
  const vulns = d.vulns || [];
  const tags = d.tags || [];
  const services = d.services || [];
  return (
    <div>
      {ports.length > 0 && <div style={{marginBottom:12}}>
        <span style={{fontSize:11,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'0.05em'}}>Open Ports</span>
        <div style={{display:'flex',gap:6,flexWrap:'wrap',marginTop:6}}>
          {ports.map(p=><span key={p} style={{padding:'3px 10px',borderRadius:4,background:'var(--surface3)',fontFamily:'var(--mono)',fontSize:12,color:p===3389||p===23?'var(--danger)':p===22||p===21?'var(--amber)':'var(--text)'}}>{p}</span>)}
        </div>
      </div>}
      {d.asn && <InfoRow label="ASN" value={d.asn} mono/>}
      {(d.org||d.isp) && <InfoRow label="Organization" value={d.org||d.isp}/>}
      {d.country && <InfoRow label="Country" value={d.country}/>}
      {d.city && <InfoRow label="City" value={d.city}/>}
      {d.os && <InfoRow label="OS" value={d.os}/>}
      {hostnames.map((h,i)=><InfoRow key={i} label={i===0?'Hostname':''} value={h} mono/>)}
      {d.lastSeen && <InfoRow label="Last Seen" value={d.lastSeen} mono/>}
      {vulns.length > 0 && <div style={{marginTop:12}}><span style={{fontSize:11,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'0.05em'}}>Vulnerabilities</span><div style={{display:'flex',gap:4,flexWrap:'wrap',marginTop:6}}>{vulns.map(v=><Tag key={v} text={v} danger/>)}</div></div>}
      {services.length > 0 && <div style={{marginTop:12}}>
        <span style={{fontSize:11,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'0.05em'}}>Services</span>
        {services.map((s,i)=><div key={i} style={{display:'flex',gap:8,padding:'5px 0',borderBottom:'1px solid var(--border)',fontSize:12}}>
          <span style={{fontFamily:'var(--mono)',color:'var(--accent)',width:50,flexShrink:0}}>{s.port}/{s.transport}</span>
          <span style={{color:'var(--text-dim)'}}>{[s.product,s.version].filter(Boolean).join(' ')||'—'}</span>
        </div>)}
      </div>}
      {tags.length > 0 && <div style={{marginTop:12,display:'flex',gap:4,flexWrap:'wrap'}}>{tags.map(t=><Tag key={t} text={t}/>)}</div>}
    </div>
  );
}
