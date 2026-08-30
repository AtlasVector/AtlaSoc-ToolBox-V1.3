import React from 'react';
import { InfoRow, Tag, renderError } from '../ui.jsx';

export function renderURLScan(d) {
  if (d.error) return renderError(d);
  if (!d.found && !d.scanning) return <div style={{padding:'24px 0',textAlign:'center',color:'var(--text-muted)'}}><div style={{fontSize:32,marginBottom:8}}>🌐</div><div>No URLScan results found for this indicator</div></div>;
  if (d.scanning) return <div style={{padding:'24px 0',textAlign:'center',color:'var(--text-muted)'}}><div style={{fontSize:32,marginBottom:8}}>⏳</div><div style={{fontWeight:600,marginBottom:4}}>Scan submitted</div><div style={{fontSize:12,marginBottom:12}}>{d.message}</div>{d.reportUrl&&<a href={d.reportUrl} target="_blank" rel="noreferrer" style={{color:'var(--accent)',fontSize:12}}>View results when ready ↗</a>}</div>;
  const technologies = d.technologies || [];
  const verdicts = d.verdicts || {};
  const isMalicious = verdicts.malicious;
  const isSuspicious = verdicts.suspicious;
  return (
    <div>
      <div style={{display:'flex',gap:20,marginBottom:16,alignItems:'flex-start'}}>
        <div style={{flex:'none',width:180,height:100,background:'var(--surface3)',borderRadius:6,display:'flex',alignItems:'center',justifyContent:'center',border:'1px solid var(--border2)',overflow:'hidden',position:'relative'}}>
          {d.screenshot
            ? <img src={d.screenshot} alt="screenshot" style={{width:'100%',height:'100%',objectFit:'cover'}}/>
            : <div style={{textAlign:'center',color:'var(--text-muted)',fontSize:11}}>
                <div style={{fontSize:20,marginBottom:4}}>🖥</div>
                <div>Screenshot</div>
                <div style={{fontSize:10,marginTop:2}}>Live scan required</div>
              </div>}
        </div>
        <div style={{flex:1}}>
          {d.ip && <InfoRow label="Resolved IP" value={d.ip} mono/>}
          {d.country && <InfoRow label="Country" value={d.country}/>}
          {d.server && <InfoRow label="Server" value={d.server} mono/>}
          {d.title && <InfoRow label="Page Title" value={d.title}/>}
          {d.domainAge && <InfoRow label="Domain Age" value={d.domainAge}/>}
          {d.reportUrl && <InfoRow label="Full Report" value={<a href={d.reportUrl} target="_blank" rel="noreferrer" style={{color:'var(--accent)',fontSize:12}}>Open in URLScan ↗</a>}/>}
        </div>
      </div>
      {technologies.length > 0 && <div><span style={{fontSize:11,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'0.05em'}}>Technologies Detected</span><div style={{display:'flex',gap:4,marginTop:6,flexWrap:'wrap'}}>{technologies.map(t=><Tag key={t} text={t}/>)}</div></div>}
      <div style={{display:'flex',gap:8,marginTop:12}}>
        {isMalicious && <Tag text="malicious verdict" danger/>}
        {isSuspicious && <Tag text="suspicious verdict" warn/>}
        {!isMalicious && !isSuspicious && <Tag text="clean verdict"/>}
      </div>
    </div>
  );
}
