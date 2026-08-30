import React from 'react';
import { InfoRow, Tag, Badge, ScoreRing, renderError } from '../ui.jsx';

export function renderCVE(d) {
  if (d.error) return renderError(d);
  const score = parseFloat(d.cvssScore ?? d.cvss ?? 0);
  const scoreColor = score >= 9 ? 'var(--danger)' : score >= 7 ? 'var(--warning)' : score >= 4 ? 'var(--amber)' : 'var(--safe)';
  const severity = d.severity || (score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : score > 0 ? 'LOW' : null);
  const refs = d.references || [];
  const weaknesses = d.weaknesses || [];
  const affectedProducts = d.affectedProducts || [];
  const hasVector = d.attackVector || d.attackComplexity;

  return (
    <div style={{display:'flex',flexDirection:'column',gap:16}}>
      {/* Header: score + key facts */}
      <div style={{display:'flex',alignItems:'flex-start',gap:20,flexWrap:'wrap'}}>
        <div style={{display:'flex',flexDirection:'column',alignItems:'center',gap:6,flexShrink:0}}>
          <ScoreRing score={score} max={10} label="CVSS Score" color={scoreColor}/>
          {severity && <Badge label={severity} color={scoreColor}/>}
          {d.cvssVersion && <span style={{fontSize:10,color:'var(--text-muted)',fontFamily:'var(--mono)'}}>v{d.cvssVersion}</span>}
        </div>
        <div style={{flex:1,minWidth:200}}>
          {d.id && <InfoRow label="CVE ID" value={<a href={`https://nvd.nist.gov/vuln/detail/${d.id}`} target="_blank" rel="noreferrer" style={{color:'var(--accent)',fontFamily:'var(--mono)',fontSize:12}}>{d.id} ↗</a>}/>}
          {d.vulnStatus && <InfoRow label="Status" value={d.vulnStatus} color={d.vulnStatus==='Analyzed'?'var(--safe)':'var(--text-dim)'}/>}
          {d.published && <InfoRow label="Published" value={d.published} mono/>}
          {d.lastModified && <InfoRow label="Last Modified" value={d.lastModified} mono/>}
          {d.exploitabilityScore != null && <InfoRow label="Exploitability" value={d.exploitabilityScore} mono/>}
          {d.impactScore != null && <InfoRow label="Impact Score" value={d.impactScore} mono/>}
        </div>
        {(d.cisaExploited || weaknesses.length > 0) && (
          <div style={{display:'flex',flexDirection:'column',gap:6,flexShrink:0}}>
            {d.cisaExploited && <Tag text="CISA KEV — actively exploited" danger/>}
            {weaknesses.map(w => <Tag key={w} text={w} warn/>)}
          </div>
        )}
      </div>

      {/* CVSS Vector breakdown */}
      {hasVector && (
        <div style={{background:'var(--surface3)',borderRadius:8,padding:12}}>
          <div style={{fontSize:11,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'0.05em',marginBottom:8}}>CVSS Vector</div>
          {d.vectorString && <div style={{fontFamily:'var(--mono)',fontSize:11,color:'var(--accent)',marginBottom:10,wordBreak:'break-all'}}>{d.vectorString}</div>}
          <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(160px,1fr))',gap:6}}>
            {[
              ['Attack Vector', d.attackVector],
              ['Attack Complexity', d.attackComplexity],
              ['Privileges Required', d.privilegesRequired],
              ['User Interaction', d.userInteraction],
              ['Scope', d.scope],
              ['Confidentiality', d.confidentialityImpact],
              ['Integrity', d.integrityImpact],
              ['Availability', d.availabilityImpact],
            ].filter(([,v]) => v).map(([k,v]) => (
              <div key={k} style={{display:'flex',flexDirection:'column',gap:2,padding:'6px 8px',background:'var(--surface2)',borderRadius:5}}>
                <span style={{fontSize:9,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'0.05em'}}>{k}</span>
                <span style={{fontSize:12,fontWeight:600,color:v==='HIGH'||v==='NETWORK'||v==='CHANGED'?scoreColor:'var(--text)'}}>{v}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Description */}
      {d.description && (
        <div style={{padding:12,background:'var(--surface3)',borderRadius:8,fontSize:13,color:'var(--text-dim)',lineHeight:1.7}}>
          {d.description}
        </div>
      )}

      {/* Affected products */}
      {affectedProducts.length > 0 && (
        <div>
          <span style={{fontSize:11,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'0.05em'}}>Affected Products ({affectedProducts.length})</span>
          <div style={{display:'flex',gap:4,marginTop:6,flexWrap:'wrap',maxHeight:120,overflowY:'auto'}}>
            {affectedProducts.map((p,i) => <Tag key={i} text={p} warn/>)}
          </div>
        </div>
      )}

      {/* References */}
      {refs.length > 0 && (
        <div>
          <span style={{fontSize:11,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'0.05em'}}>References</span>
          <div style={{marginTop:6,display:'flex',flexDirection:'column',gap:4}}>
            {refs.map((r,i) => (
              <div key={i} style={{display:'flex',alignItems:'flex-start',gap:8,padding:'5px 0',borderBottom:'1px solid var(--border)'}}>
                <div style={{flex:1,minWidth:0}}>
                  <a href={r.url} target="_blank" rel="noreferrer" style={{color:'var(--accent)',fontSize:11,fontFamily:'var(--mono)',wordBreak:'break-all'}}>{r.url}</a>
                  {r.source && <span style={{fontSize:10,color:'var(--text-muted)',marginLeft:6}}>{r.source}</span>}
                </div>
                {r.tags?.length > 0 && <div style={{display:'flex',gap:3,flexShrink:0}}>{r.tags.slice(0,2).map(t=><Tag key={t} text={t}/>)}</div>}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
