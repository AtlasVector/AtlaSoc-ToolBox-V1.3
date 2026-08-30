import React from 'react';
import { InfoRow, Tag, ScoreRing, renderError } from '../ui.jsx';

export function renderAbuse(d) {
  if (d.error) return renderError(d);
  const score = d.abuseScore ?? 0;
  const scoreColor = score > 80 ? 'var(--danger)' : score > 25 ? 'var(--amber)' : 'var(--safe)';
  return (
    <div style={{display:'flex',flexDirection:'column',gap:16}}>
      <div style={{display:'flex',alignItems:'flex-start',gap:20}}>
        <div style={{display:'flex',flexDirection:'column',alignItems:'center',gap:4,flexShrink:0}}>
          <ScoreRing score={score} label="Abuse Score" color={scoreColor}/>
          <span style={{fontFamily:'var(--mono)',fontSize:16,fontWeight:700,color:scoreColor}}>{score}%</span>
          <span style={{fontSize:10,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'0.05em'}}>confidence</span>
        </div>
        <div style={{flex:1}}>
          {d.countryName && <InfoRow label="Country" value={`${d.countryName} (${d.country})`}/>}
          {!d.countryName && d.country && <InfoRow label="Country" value={d.country}/>}
          {d.isp && <InfoRow label="ISP" value={d.isp}/>}
          {d.domain && <InfoRow label="Domain" value={d.domain} mono/>}
          {d.usageType && <InfoRow label="Usage Type" value={d.usageType}/>}
          {d.ipVersion && <InfoRow label="IP Version" value={`IPv${d.ipVersion}`} mono/>}
          {d.totalReports != null && <InfoRow label="Total Reports" value={d.totalReports} mono/>}
          {d.numDistinctUsers != null && <InfoRow label="Distinct Users" value={d.numDistinctUsers} mono/>}
          {d.lastReported && <InfoRow label="Last Reported" value={d.lastReported} mono/>}
        </div>
      </div>
      <div style={{display:'flex',gap:8,flexWrap:'wrap'}}>
        {d.isWhitelisted && <Tag text="whitelisted"/>}
        {d.tor && <Tag text="TOR exit node" warn/>}
        {score === 0 && <Tag text="no abuse reports"/>}
        {score > 80 && <Tag text="high confidence" danger/>}
        {score > 25 && score <= 80 && <Tag text="suspicious activity" warn/>}
      </div>
      {d.recentReports?.length > 0 && (
        <div>
          <span style={{fontSize:11,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'0.05em'}}>Recent Reports</span>
          <div style={{marginTop:6,display:'flex',flexDirection:'column',gap:6}}>
            {d.recentReports.map((r,i) => (
              <div key={i} style={{padding:'8px 10px',background:'var(--surface3)',borderRadius:6,borderLeft:`3px solid ${scoreColor}`}}>
                <div style={{display:'flex',gap:8,alignItems:'center',marginBottom:r.comment?4:0}}>
                  <span style={{fontFamily:'var(--mono)',fontSize:11,color:'var(--text-muted)'}}>{r.date}</span>
                  {r.categories?.length > 0 && <div style={{display:'flex',gap:3}}>{r.categories.slice(0,4).map(c=><Tag key={c} text={String(c)} warn/>)}</div>}
                </div>
                {r.comment && <div style={{fontSize:11,color:'var(--text-dim)',fontFamily:'var(--mono)',wordBreak:'break-all'}}>{r.comment}</div>}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
