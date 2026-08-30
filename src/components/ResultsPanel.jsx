import React from 'react';
import { Dot, Badge, ErrorBoundary, STATUS_COLOR, STATUS_LABEL, IOC_LABELS } from './ui.jsx';
import { SOURCE_EMOJI } from '../lib/api.js';
import { freshnessBadge, statusBadge } from '../lib/sourceBadges.js';
import { detectType } from '../lib/detect.js';
import { renderSource } from './sources/index.jsx';

export function overallStatus(sources) {
  if (!sources) return null;
  if (sources.some(s => s.status === 'malicious')) return 'malicious';
  if (sources.some(s => s.status === 'suspicious')) return 'suspicious';
  if (sources.some(s => s.status === 'stale')) return 'stale';
  if (sources.some(s => s.status === 'error')) return 'error';
  if (sources.some(s => s.status === 'clean')) return 'clean';
  return 'unknown';
}

export const ResultsPanel = ({sources, val, isCompact, accent}) => {
  const [tab, setTab] = React.useState(null);
  React.useEffect(() => { setTab(sources[0]?.source || null); }, [val]);
  const activeSource = sources.find(s => s.source === tab) || sources[0];
  const overall = overallStatus(sources);
  return (
    <div style={{flex:1,display:'flex',flexDirection:'column',minHeight:0}}>
      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'12px 16px',background:'var(--surface)',borderRadius:'10px 10px 0 0',border:'1px solid var(--border)',borderBottom:'none'}}>
        <div style={{display:'flex',alignItems:'center',gap:10}}>
          <Dot status={overall}/>
          <span style={{fontFamily:'var(--mono)',fontSize:13,color:'var(--text-dim)'}}>{val}</span>
          <Badge label={IOC_LABELS[detectType(val)]||'Unknown'} color={accent} small/>
        </div>
        <Badge label={STATUS_LABEL[overall]||'Unknown'} color={STATUS_COLOR[overall]||'var(--text-muted)'}/>
      </div>
      <div style={{display:'flex',borderLeft:'1px solid var(--border)',borderRight:'1px solid var(--border)',background:'var(--surface2)',overflowX:'auto'}}>
        {sources.map(s=>{
          const isActive = (tab === s.source) || (!tab && s === sources[0]);
          const emptyState = s.condition === 'not_configured'
            ? `${s.source} is not configured`
            : s.condition === 'endpoint_error'
              ? `Lookup failed: ${s.error || s.conditionMessage || 'unknown error'}`
              : s.condition === 'no_results'
                ? 'No data returned for this indicator'
                : null;
          return (
            <button key={s.source} onClick={()=>setTab(s.source)} style={{padding:'9px 14px',fontSize:12,fontWeight:600,color:isActive?accent:'var(--text-dim)',borderBottom:`2px solid ${isActive?accent:'transparent'}`,borderTop:`2px solid ${isActive?accent+'50':'transparent'}`,background:isActive?`${accent}10`:'transparent',whiteSpace:'nowrap',transition:'all 0.15s',display:'flex',alignItems:'center',gap:5,flexShrink:0}}>
              <Dot status={s.status}/>
              <span style={{fontSize:13}}>{SOURCE_EMOJI[s.source] || '🔍'}</span>
              {s.source}
              {freshnessBadge(s) === 'STALE'
                ? <span style={{fontSize:9,padding:'1px 5px',borderRadius:3,background:'rgba(245,158,11,0.12)',color:'var(--amber)',border:'1px solid rgba(245,158,11,0.3)',fontWeight:700,letterSpacing:'0.05em'}}>STALE</span>
                : freshnessBadge(s) === 'CACHED'
                  ? <span style={{fontSize:9,padding:'1px 5px',borderRadius:3,background:'rgba(148,163,184,0.12)',color:'var(--text-muted)',border:'1px solid rgba(148,163,184,0.3)',fontWeight:700,letterSpacing:'0.05em'}}>CACHED</span>
                  : null}
              {statusBadge(s, emptyState) === 'INFO'
                ? <span style={{fontSize:9,padding:'1px 5px',borderRadius:3,background:'rgba(245,158,11,0.12)',color:'var(--amber)',border:'1px solid rgba(245,158,11,0.3)',fontWeight:700,letterSpacing:'0.05em'}}>INFO</span>
                : statusBadge(s, emptyState) === 'ERR'
                  ? <span style={{fontSize:9,padding:'1px 5px',borderRadius:3,background:'rgba(239,68,68,0.12)',color:'var(--danger)',border:'1px solid rgba(239,68,68,0.3)',fontWeight:700,letterSpacing:'0.05em'}}>ERR</span>
                  : statusBadge(s, emptyState) === 'LIVE'
                    ? <span style={{fontSize:9,padding:'1px 5px',borderRadius:3,background:'rgba(16,185,129,0.12)',color:'var(--safe)',border:'1px solid rgba(16,185,129,0.3)',fontWeight:700,letterSpacing:'0.05em'}}>LIVE</span>
                    : null
              }
            </button>
          );
        })}
      </div>
      <div style={{flex:1,background:'var(--surface)',border:'1px solid var(--border)',borderRadius:'0 0 10px 10px',padding:isCompact?12:16,overflowY:'auto'}}>
        {activeSource && (activeSource.condition === 'no_results' || activeSource.condition === 'not_configured' || activeSource.condition === 'endpoint_error') ? (
          <div style={{padding:24,color:'var(--text-dim)',background:'var(--surface3)',borderRadius:8}}>
            <div style={{fontWeight:600,marginBottom:6,color:'var(--amber)'}}>
              {activeSource.condition === 'not_configured' ? `${activeSource.source} is not configured` : activeSource.condition === 'endpoint_error' ? 'Lookup failed' : 'No results'}
            </div>
            <div style={{fontFamily:'var(--mono)',fontSize:11,opacity:.7}}>
              {activeSource.error || activeSource.conditionMessage || 'Please check the indicator or try again later.'}
            </div>
          </div>
        ) : activeSource && (
          <ErrorBoundary key={activeSource.source} fallback={e =>
            <div style={{padding:16,color:'var(--text-muted)',fontSize:13,background:'var(--surface3)',borderRadius:8}}>
              <div style={{color:'var(--amber)',fontWeight:600,marginBottom:6}}>⚠ Could not render {activeSource.source} results</div>
              <div style={{fontFamily:'var(--mono)',fontSize:11,opacity:0.7}}>{e.message}</div>
            </div>
          }>
            {renderSource(activeSource)}
          </ErrorBoundary>
        )}
      </div>
    </div>
  );
};
