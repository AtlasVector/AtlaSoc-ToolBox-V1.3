import React from 'react';
import { InfoRow, Tag } from './ui.jsx';
import { parseUserAgent } from '../lib/utilities/uaParser.js';
import { searchEventIds } from '../lib/utilities/eventIds.js';

const EmptyState = ({title, message}) => (
  <div style={{padding:24,color:'var(--text-dim)',background:'var(--surface3)',borderRadius:8}}>
    <div style={{fontWeight:600,marginBottom:6,color:'var(--amber)'}}>{title}</div>
    <div style={{fontFamily:'var(--mono)',fontSize:11,opacity:.7}}>{message}</div>
  </div>
);

// Defined at module scope (not inside UtilitiesPanel) so its identity is
// stable across renders — otherwise React remounts the tab buttons on every
// parent render (e.g. every placeholder-typewriter tick), which can swallow clicks.
const TabBtn = ({active, accent, onClick, children}) => (
  <button onClick={onClick} style={{padding:'8px 16px',fontSize:12,fontWeight:600,color:active?accent:'var(--text-dim)',borderBottom:`2px solid ${active?accent:'transparent'}`,background:active?`${accent}10`:'transparent',transition:'all 0.15s'}}>
    {children}
  </button>
);

const UAParserTool = ({accent}) => {
  const [ua, setUa] = React.useState('');
  const result = React.useMemo(() => parseUserAgent(ua), [ua]);
  return (
    <div style={{display:'flex',flexDirection:'column',gap:12}}>
      <textarea
        value={ua}
        onChange={e=>setUa(e.target.value)}
        placeholder={navigator.userAgent}
        rows={3}
        style={{width:'100%',padding:'10px 12px',fontSize:12,fontFamily:'var(--mono)',color:'var(--text)',background:'var(--surface2)',border:'1px solid var(--border2)',borderRadius:8,resize:'vertical'}}
      />
      <div style={{display:'flex',flexWrap:'wrap',alignItems:'baseline',gap:'2px 8px',fontSize:11,color:'var(--text-dim)'}}>
        <span style={{flexShrink:0}}>Your User-Agent:</span>
        <span style={{fontFamily:'var(--mono)',wordBreak:'break-all',flex:'1 1 260px',minWidth:0}}>{navigator.userAgent}</span>
        <button onClick={()=>setUa(navigator.userAgent)} style={{flexShrink:0,color:accent,fontSize:11,fontWeight:600}}>Use mine</button>
      </div>
      {!ua.trim() ? (
        <EmptyState title="No input yet" message="Paste a User-Agent string to parse browser, OS and device info."/>
      ) : result.isBot ? (
        <div style={{background:'var(--surface2)',border:'1px solid var(--border2)',borderRadius:8,padding:'4px 14px'}}>
          <InfoRow label="Type" value={<Tag text="Bot / Automated" warn/>}/>
          <InfoRow label="Identified as" value={result.botName} mono/>
          {result.architecture && <InfoRow label="Architecture" value={result.architecture} mono/>}
        </div>
      ) : (
        <div style={{background:'var(--surface2)',border:'1px solid var(--border2)',borderRadius:8,padding:'4px 14px'}}>
          <InfoRow label="Browser" value={result.browser ? `${result.browser}${result.browserVersion ? ' ' + result.browserVersion : ''}` : 'Unknown'} mono/>
          <InfoRow label="Engine" value={result.engine || 'Unknown'} mono/>
          <InfoRow label="OS" value={result.os ? `${result.os}${result.osVersion ? ' ' + result.osVersion : ''}` : 'Unknown'} mono/>
          <InfoRow label="Device type" value={<Tag text={result.deviceType}/>}/>
          {result.architecture && <InfoRow label="Architecture" value={result.architecture} mono/>}
          {result.embeddedApp && <InfoRow label="Embedded app" value={<Tag text={result.embeddedApp} warn/>}/>}
          {result.isAutomated && <InfoRow label="Automation" value={<Tag text="Headless / automated client" warn/>}/>}
        </div>
      )}
    </div>
  );
};

const SEVERITY_LABEL = { info: 'Info', suspicious: 'Suspicious', critical: 'Critical' };
const SeverityTag = ({severity}) => (
  <Tag text={SEVERITY_LABEL[severity] || severity} danger={severity==='critical'} warn={severity==='suspicious'}/>
);

const EventIdTool = ({accent}) => {
  const [id, setId] = React.useState('');
  const matches = React.useMemo(() => searchEventIds(id), [id]);
  return (
    <div style={{display:'flex',flexDirection:'column',gap:12}}>
      <input
        value={id}
        onChange={e=>setId(e.target.value)}
        placeholder="e.g. 4624 (or 462 for partial matches)"
        inputMode="numeric"
        style={{width:'100%',padding:'10px 12px',fontSize:13,fontFamily:'var(--mono)',color:'var(--text)',background:'var(--surface2)',border:'1px solid var(--border2)',borderRadius:8}}
      />
      {!id.trim() ? (
        <EmptyState title="No input yet" message="Enter a Windows Event ID to look up its meaning — matches show as you type."/>
      ) : matches.length === 0 ? (
        <EmptyState title="Not in reference table" message={`No event ID starting with "${id.trim()}" is in this reference table.`}/>
      ) : matches.length === 1 ? (
        <div style={{background:'var(--surface2)',border:'1px solid var(--border2)',borderRadius:8,padding:'4px 14px'}}>
          <InfoRow label="Event ID" value={matches[0].id} mono/>
          <InfoRow label="Name" value={matches[0].name}/>
          <InfoRow label="Category" value={<Tag text={matches[0].category}/>}/>
          <InfoRow label="Log" value={matches[0].log} mono/>
          <InfoRow label="Severity" value={<SeverityTag severity={matches[0].severity}/>}/>
          {matches[0].attack && <InfoRow label="ATT&CK technique" value={matches[0].attack} mono/>}
          {matches[0].keyFields?.length > 0 && <InfoRow label="Key fields to check" value={matches[0].keyFields.join(', ')} mono/>}
        </div>
      ) : (
        <div style={{display:'flex',flexDirection:'column',gap:6}}>
          {matches.map(m => (
            <button
              key={m.id}
              onClick={()=>setId(String(m.id))}
              style={{display:'flex',alignItems:'baseline',gap:10,textAlign:'left',padding:'8px 14px',fontFamily:'inherit',background:'var(--surface2)',border:'1px solid var(--border2)',borderRadius:8,cursor:'pointer'}}
            >
              <span style={{fontFamily:'var(--mono)',fontSize:13,fontWeight:600,color:accent}}>{m.id}</span>
              <span style={{fontSize:12,color:'var(--text)'}}>{m.name}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
};

export const UtilitiesPanel = ({accent}) => {
  const [tab, setTab] = React.useState('eventid');
  return (
    <div style={{maxWidth:640,margin:'0 auto',width:'100%'}}>
      <div style={{fontSize:11,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'0.06em',fontWeight:600,marginBottom:12}}>Analyst Utilities — local, offline lookups (no external calls)</div>
      <div style={{display:'flex',borderBottom:'1px solid var(--border)',marginBottom:16}}>
        <TabBtn active={tab==='eventid'} accent={accent} onClick={()=>setTab('eventid')}>Windows Event ID</TabBtn>
        <TabBtn active={tab==='ua'} accent={accent} onClick={()=>setTab('ua')}>User-Agent Parser</TabBtn>
      </div>
      {tab === 'ua' ? <UAParserTool accent={accent}/> : <EventIdTool accent={accent}/>}
    </div>
  );
};
