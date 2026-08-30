import React from 'react';
import { detectType } from './lib/detect.js';
import { getLiveResults, ENDPOINT_MAP, SOURCE_META, SOURCE_EMOJI } from './lib/api.js';
import { Badge, Dot, IOC_LABELS, LogoMark, BrandName } from './components/ui.jsx';
import { ResultsPanel, overallStatus } from './components/ResultsPanel.jsx';
import { UtilitiesPanel } from './components/UtilitiesPanel.jsx';

// ─── Typewriter placeholder ──────────────────────────────────────────────────
function usePlaceholder(examples) {
  const [text, setText] = React.useState('');
  const s = React.useRef({ ex: 0, ch: 0, del: false, tid: null });
  React.useEffect(() => {
    const tick = () => {
      const r = s.current, target = examples[r.ex];
      if (!r.del) {
        r.ch++;
        setText(target.slice(0, r.ch));
        if (r.ch === target.length) { r.del = true; r.tid = setTimeout(tick, 1800); return; }
      } else {
        r.ch--;
        setText(target.slice(0, r.ch));
        if (r.ch === 0) { r.del = false; r.ex = (r.ex + 1) % examples.length; }
      }
      r.tid = setTimeout(tick, r.del ? 35 : 72);
    };
    s.current.tid = setTimeout(tick, 900);
    return () => clearTimeout(s.current.tid);
  }, []);
  return text;
}

// ─── Main App ─────────────────────────────────────────────────────────────────
const EXAMPLES = ['8.8.8.8','malicious.ru','https://phish.site/login','44d88612fea8a8f36de82e1278abb02f','CVE-2024-3094'];

const LAYOUT = 'centered';
const ACCENT_COLOR = '#f59e0b';
const DENSITY = 'comfortable';

// Defined at module scope (not inside App) so its identity is stable across
// renders — otherwise React remounts every header button on each render
// (e.g. every placeholder-typewriter tick), which can swallow clicks.
const Btn = ({onClick, children, active, accent, isAccent}) => (
  <button onClick={onClick} style={{padding:'6px 13px',borderRadius:6,background:active||isAccent?`${accent}22`:'var(--surface2)',color:active||isAccent?accent:'var(--text-dim)',border:`1px solid ${active||isAccent?accent+'50':'var(--border2)'}`,fontSize:12,fontWeight:600,display:'flex',alignItems:'center',gap:5,transition:'all 0.15s',letterSpacing:'0.01em'}}>
    {children}
  </button>
);

export default function App() {
  const typedPlaceholder = usePlaceholder(EXAMPLES);
  const [theme, setTheme] = React.useState('dark');
  const [view, setView] = React.useState('search');
  const [query, setQuery] = React.useState('');
  const [bulkMode, setBulkMode] = React.useState(false);
  const [bulkText, setBulkText] = React.useState('');
  const [results, setResults] = React.useState(null);
  const [loading, setLoading] = React.useState(false);
  const [bulkResults, setBulkResults] = React.useState(null);
  const [bulkProgress, setBulkProgress] = React.useState(null);
  const [selectedBulk, setSelectedBulk] = React.useState(0);
  const [activeBulkSource, setActiveBulkSource] = React.useState(0);

  const layout = LAYOUT;
  const accent = ACCENT_COLOR;

  React.useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    document.documentElement.style.setProperty('--accent', accent);
    document.documentElement.style.setProperty('--accent-glow', accent + '26');
    document.documentElement.style.setProperty('--accent-dim', accent + '14');
  }, [theme, accent]);

  const iocType = detectType(query);

  const runSearchFor = async (val) => {
    const trimmed = val.trim();
    if (!trimmed) return;
    const t = detectType(trimmed);
    setLoading(true);
    setResults(null);
    setBulkResults(null);
    setBulkProgress(null);
    const live = await getLiveResults(trimmed, t, setResults);
    setResults(live);
    setLoading(false);
  };

  const runSearch = () => runSearchFor(query);

  const BULK_CONCURRENCY = 3;

  const runBulk = async () => {
    const lines = bulkText.split('\n').map(l=>l.trim()).filter(Boolean).slice(0, 50);
    if (!lines.length) return;
    setLoading(true);
    setResults(null);
    setBulkResults(null);
    setBulkProgress({ done: 0, total: lines.length });
    const res = new Array(lines.length);
    let next = 0;
    let done = 0;
    const worker = async () => {
      while (next < lines.length) {
        const i = next++;
        const val = lines[i];
        const t = detectType(val);
        const sources = await getLiveResults(val, t);
        res[i] = { val, type: t, sources };
        done++;
        setBulkProgress({ done, total: lines.length });
      }
    };
    await Promise.all(Array.from({ length: Math.min(BULK_CONCURRENCY, lines.length) }, worker));
    setBulkResults(res);
    setSelectedBulk(0);
    setActiveBulkSource(0);
    setLoading(false);
    setBulkProgress(null);
  };

  const exportJSON = () => {
    const data = bulkResults
      ? bulkResults.map(r=>({indicator:r.val,type:IOC_LABELS[r.type]||r.type,results:r.sources}))
      : [{indicator:query,type:IOC_LABELS[iocType]||iocType,results}];
    const blob = new Blob([JSON.stringify(data, null, 2)], {type:'application/json'});
    const a = document.createElement('a');
    const blobUrl = URL.createObjectURL(blob);
    a.href = blobUrl;
    a.download = `atlasoc-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(blobUrl);
  };

  const exportPDF = () => window.print();


  const isCompact = DENSITY === 'compact';
  const isSplit = layout === 'split';

  // ── Header ──────────────────────────────────────────────────────────────────
  const resetHome = () => { setView('search'); setResults(null); setBulkResults(null); setBulkProgress(null); setQuery(''); setBulkText(''); setLoading(false); };

  const hasResult = results || bulkResults;

  const header = (
    <header style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:`${isCompact?10:13}px 20px`,background:'var(--surface)',borderBottom:'1px solid var(--border)',flexShrink:0,zIndex:10}}>
      <button onClick={resetHome} style={{display:'flex',alignItems:'center',gap:10,background:'none',border:'none',cursor:'pointer',padding:'2px 6px',borderRadius:8,transition:'background 0.15s'}}>
        <LogoMark size={40} />
        <div style={{textAlign:'left'}}>
          <div style={{fontFamily:'var(--font)',fontWeight:700,fontSize:15,letterSpacing:'-0.02em',lineHeight:1,color:'var(--text)'}}><BrandName accent={accent}/></div>
          <div style={{fontFamily:'var(--font)',fontSize:9,color:'var(--text-muted)',letterSpacing:'0.1em',textTransform:'uppercase',marginTop:2}}>Threat Intelligence</div>
        </div>
      </button>
      <div style={{display:'flex',alignItems:'center',gap:8}}>
        {(hasResult || view === 'utilities') && <Btn accent={accent} onClick={resetHome}>⌂ Home</Btn>}
        {view === 'search' && <Btn accent={accent} onClick={()=>setBulkMode(b=>!b)} active={bulkMode}>{bulkMode?'⊞ Bulk':'⊟ Single'}</Btn>}
        <Btn accent={accent} onClick={()=>setView(v=>v==='utilities'?'search':'utilities')} active={view==='utilities'}>🛠 Utilities</Btn>
        <span style={{padding:'5px 10px',borderRadius:6,border:'1px solid rgba(16,185,129,0.35)',background:'rgba(16,185,129,0.08)',color:'var(--safe)',fontSize:11,fontWeight:700,letterSpacing:'0.06em',display:'flex',alignItems:'center',gap:5}}>
          <span style={{width:6,height:6,borderRadius:'50%',background:'var(--safe)',display:'inline-block',flexShrink:0}}/>
          LIVE
        </span>
        {hasResult && <>
          <Btn accent={accent} onClick={exportJSON}>↓ JSON</Btn>
          <Btn accent={accent} onClick={exportPDF}>⎙ PDF</Btn>
        </>}
        <button onClick={()=>setTheme(theme==='dark'?'light':'dark')} style={{width:34,height:34,borderRadius:7,background:'var(--surface2)',border:'1px solid var(--border2)',fontSize:15,display:'flex',alignItems:'center',justifyContent:'center',cursor:'pointer',transition:'all 0.15s'}}>
          {theme==='dark'?'☀️':'🌙'}
        </button>
      </div>
    </header>
  );

  // ── Search Input ─────────────────────────────────────────────────────────────
  const searchBar = (
    <div style={{display:'flex',flexDirection:'column',gap:8,width:'100%',maxWidth:isSplit?'100%':680}}>
      {!bulkMode ? (
        <div style={{display:'flex',flexDirection:'column',gap:6}}>
          <div style={{display:'flex',alignItems:'center',background:'var(--surface)',border:`1.5px solid ${query&&iocType&&iocType!=='unknown'?accent+'70':'rgba(255,255,255,0.09)'}`,borderRadius:12,overflow:'hidden',transition:'all 0.25s',boxShadow:query&&iocType&&iocType!=='unknown'?`0 0 0 3px ${accent}18, 0 4px 20px rgba(0,0,0,0.3)`:`0 4px 20px rgba(0,0,0,0.3), inset 0 1px 0 rgba(255,255,255,0.04)`}}>
            <div style={{padding:'0 10px 0 16px',fontFamily:'var(--mono)',fontSize:13,color:'var(--accent)',opacity:0.85,userSelect:'none',letterSpacing:'0.02em',display:'flex',alignItems:'center',gap:1}}>{'>'}<span style={{animation:'cur 1s step-end infinite'}}>_</span></div>
            <input
              value={query}
              onChange={e=>setQuery(e.target.value)}
              onKeyDown={e=>e.key==='Enter'&&runSearch()}
              placeholder={typedPlaceholder}
              style={{flex:1,padding:'14px 0',fontSize:14,fontFamily:query?'var(--mono)':'var(--body)',background:'transparent',color:'var(--text)'}}
            />
            {query && iocType && iocType !== 'unknown' && (
              <div style={{padding:'0 12px'}}>
                <Badge label={IOC_LABELS[iocType]||iocType} color={accent} small/>
              </div>
            )}
            <button onClick={runSearch} style={{margin:5,padding:'0 18px',height:38,borderRadius:8,background:accent,color:'#000',fontWeight:700,fontSize:12,letterSpacing:'0.03em',transition:'opacity 0.2s',opacity:query&&iocType&&iocType!=='unknown'?1:0.4,flexShrink:0}}>
              ANALYZE
            </button>
          </div>
          {query && iocType && iocType !== 'unknown' && !hasResult && !loading && (
            <div style={{display:'flex',alignItems:'center',gap:6,flexWrap:'wrap',padding:'2px 4px'}}>
              <span style={{fontSize:10,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'0.06em',flexShrink:0}}>Will query:</span>
              {Object.entries(ENDPOINT_MAP).filter(([,types])=>types.includes(iocType)).map(([ep])=>{
                const m = SOURCE_META[ep];
                return m ? (
                  <span key={ep} style={{display:'inline-flex',alignItems:'center',gap:4,padding:'2px 8px',borderRadius:4,background:'var(--surface2)',border:'1px solid var(--border2)',fontSize:11,color:'var(--text-dim)',fontWeight:500}}>
                    <span style={{fontSize:13}}>{SOURCE_EMOJI[m.name] || ''}</span> {m.name}
                  </span>
                ) : null;
              })}
            </div>
          )}
        </div>
      ) : (
        <div style={{background:'var(--surface)',border:`1.5px solid var(--border)`,borderRadius:10,overflow:'hidden'}}>
          <div style={{padding:'10px 14px',borderBottom:'1px solid var(--border)',display:'flex',justifyContent:'space-between',alignItems:'center'}}>
            <span style={{fontSize:12,color:'var(--text-muted)',fontWeight:500}}>BULK MODE — One indicator per line (max 50)</span>
            {(n => <Badge label={n > 50 ? `${n} → capped at 50` : `${n} indicators`} color={n > 50 ? 'var(--amber)' : accent} small/>)(bulkText.split('\n').filter(l=>l.trim()).length)}
          </div>
          <textarea
            value={bulkText}
            onChange={e=>setBulkText(e.target.value)}
            placeholder={""}
            rows={5}
            style={{display:'block',width:'100%',padding:'12px 14px',fontSize:13,fontFamily:'var(--mono)',color:'var(--text)',background:'transparent',resize:'vertical'}}
          />
          <div style={{padding:'8px 10px',display:'flex',justifyContent:'flex-end',borderTop:'1px solid var(--border)'}}>
            <button onClick={runBulk} style={{padding:'7px 20px',borderRadius:6,background:accent,color:'#000',fontWeight:700,fontSize:13}}>ANALYZE ALL</button>
          </div>
        </div>
      )}
    </div>
  );

  // ── Loading ──────────────────────────────────────────────────────────────────
  const loadingView = (
    <div style={{flex:1,display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'center',gap:16}}>
      <div style={{width:44,height:44,borderRadius:'50%',border:`3px solid var(--border)`,borderTopColor:accent,animation:'spin 0.8s linear infinite'}}/>
      <div style={{color:'var(--text-muted)',fontSize:13}}>
        {bulkProgress ? `Querying threat intelligence sources… (${bulkProgress.done}/${bulkProgress.total})` : 'Querying threat intelligence sources…'}
      </div>
      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
    </div>
  );


  // ── Bulk Results ─────────────────────────────────────────────────────────────
  const bulkView = bulkResults && (
    <div style={{flex:1,display:'flex',gap:0,minHeight:0,borderRadius:10,overflow:'hidden',border:'1px solid var(--border)'}}>
      <div style={{width:220,flexShrink:0,background:'var(--surface)',borderRight:'1px solid var(--border)',overflowY:'auto'}}>
        <div style={{padding:'10px 12px',borderBottom:'1px solid var(--border)',fontSize:11,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'0.05em',fontWeight:600}}>{bulkResults.length} Indicators</div>
        {bulkResults.map((r,i)=>{
          const st = overallStatus(r.sources);
          return (
            <button key={i} onClick={()=>setSelectedBulk(i)} style={{width:'100%',padding:'9px 12px',display:'flex',alignItems:'center',gap:8,background:selectedBulk===i?'var(--surface2)':'transparent',borderLeft:`3px solid ${selectedBulk===i?accent:'transparent'}`,textAlign:'left',transition:'all 0.1s'}}>
              <Dot status={st}/>
              <div style={{flex:1,minWidth:0}}>
                <div style={{fontSize:12,fontFamily:'var(--mono)',color:'var(--text)',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{r.val}</div>
                <div style={{fontSize:10,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'0.04em',marginTop:2}}>{IOC_LABELS[r.type]||'Unknown'}</div>
              </div>
            </button>
          );
        })}
      </div>
      <div style={{flex:1,display:'flex',flexDirection:'column',minWidth:0,background:'var(--surface2)'}}>
        {bulkResults[selectedBulk] && (
          <div style={{flex:1,display:'flex',flexDirection:'column',padding:12,gap:0,minHeight:0}}>
            <ResultsPanel sources={bulkResults[selectedBulk].sources} val={bulkResults[selectedBulk].val} isCompact={isCompact} accent={accent}/>
          </div>
        )}
      </div>
    </div>
  );

  // ── Empty state ──────────────────────────────────────────────────────────────
  const emptyState = (
    <div style={{flex:1,display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'center',padding:32}}>
      <div style={{fontFamily:'var(--mono)',fontSize:12,maxWidth:460,width:'100%'}}>
        <div style={{color:'var(--text-muted)',letterSpacing:'0.1em',marginBottom:14,paddingBottom:10,borderBottom:'1px solid var(--border)',display:'flex',justifyContent:'space-between',alignItems:'center'}}>
          <span>ATLASOC-KIT // THREAT INTELLIGENCE TERMINAL</span>
          <span style={{color:'var(--safe)',fontSize:10}}>● ONLINE</span>
        </div>
        <div style={{display:'flex',flexDirection:'column',gap:5,marginBottom:20}}>
          <div style={{color:'var(--safe)'}}><span style={{color:'var(--text-muted)'}}>{'>'}</span> 7 sources connected · VirusTotal · Shodan · OTX +4</div>
          <div style={{color:'var(--text-muted)'}}><span>{'>'}</span> Session initialised. Awaiting target indicator...</div>
          <div style={{color:'var(--accent)',display:'flex',alignItems:'center',gap:6}}>
            <span>{'>'}</span>
            <span style={{display:'inline-block',width:7,height:13,background:'var(--accent)',animation:'cur 1s step-end infinite',verticalAlign:'middle'}}/>
          </div>
        </div>
        <div style={{color:'var(--text-muted)',marginBottom:8,opacity:0.6}}>{'// quick examples'}</div>
        <div style={{display:'flex',gap:6,flexWrap:'wrap'}}>
          {EXAMPLES.map(ex=>(
            <button key={ex} onClick={()=>{setQuery(ex);setBulkMode(false);}} style={{padding:'4px 10px',borderRadius:4,background:'transparent',border:'1px solid var(--border2)',fontFamily:'var(--mono)',fontSize:11,color:'var(--accent)',transition:'all 0.15s'}}>
              {ex}
            </button>
          ))}
        </div>
      </div>
    </div>
  );

  // ── Utilities view ───────────────────────────────────────────────────────────
  if (view === 'utilities') {
    return (
      <div style={{height:'100vh',display:'flex',flexDirection:'column',overflow:'hidden'}}>
        {header}
        <div style={{flex:1,overflowY:'auto',padding:24}}>
          <UtilitiesPanel accent={accent}/>
        </div>
      </div>
    );
  }

  // ── Centered layout ──────────────────────────────────────────────────────────
  if (layout === 'centered') {
    return (
      <div style={{height:'100vh',display:'flex',flexDirection:'column',overflow:'hidden'}}>
        {header}
        {!hasResult && !loading ? (
          <div style={{flex:1,display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'center',padding:'0 20px',gap:28}}>
            <div style={{width:'100%',maxWidth:680}}>
              <div style={{textAlign:'center',marginBottom:20}}>
                <div style={{fontFamily:'var(--font)',fontWeight:800,fontSize:42,letterSpacing:'-0.04em',color:'var(--text)',marginBottom:10,lineHeight:1,textShadow:`0 0 40px ${accent}55`}}><BrandName accent={accent}/></div>
                <div style={{fontFamily:'var(--mono)',fontSize:12,color:'var(--text-dim)',letterSpacing:'0.12em'}}>
                  <span style={{color:'var(--accent)'}}>{'>'}</span>
                  {' '}MULTI-SOURCE THREAT INTELLIGENCE{' '}
                  <span style={{display:'inline-block',width:7,height:12,background:'var(--accent)',opacity:0.9,animation:'cur 1s step-end infinite',verticalAlign:'middle'}}/>
                </div>
              </div>
              {searchBar}
            </div>
            <div style={{display:'flex',gap:8,flexWrap:'wrap',justifyContent:'center'}}>
              {EXAMPLES.map(ex=>(
                <button key={ex} onClick={()=>{setQuery(ex);setBulkMode(false);}} style={{padding:'5px 12px',borderRadius:6,background:'var(--surface2)',border:`1px solid ${accent}30`,fontFamily:'var(--mono)',fontSize:11,color:accent,transition:'all 0.15s',cursor:'pointer'}}>
                  {ex}
                </button>
              ))}
            </div>
          </div>
        ) : (
          <div style={{flex:1,display:'flex',flexDirection:'column',overflow:'hidden',padding:16,gap:16}}>
            <div style={{display:'flex',justifyContent:'center'}}>{searchBar}</div>
            {loading && loadingView}
            {!loading && results && <ResultsPanel sources={results} val={query} isCompact={isCompact} accent={accent}/>}
            {!loading && bulkResults && bulkView}
          </div>
        )}
      </div>
    );
  }

  // ── Split layout ─────────────────────────────────────────────────────────────
  if (layout === 'split') {
    return (
      <div style={{height:'100vh',display:'flex',flexDirection:'column',overflow:'hidden'}}>
        {header}
        <div style={{flex:1,display:'flex',overflow:'hidden'}}>
          <div style={{width:320,flexShrink:0,borderRight:'1px solid var(--border)',background:'var(--surface)',display:'flex',flexDirection:'column',padding:16,gap:12,overflowY:'auto'}}>
            <div style={{fontSize:11,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'0.06em',fontWeight:600}}>Indicator Input</div>
            {searchBar}
            <div style={{marginTop:8}}>
              <div style={{fontSize:11,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'0.06em',fontWeight:600,marginBottom:8}}>Quick Examples</div>
              <div style={{display:'flex',flexDirection:'column',gap:4}}>
                {EXAMPLES.map(ex=>(
                  <button key={ex} onClick={()=>{setQuery(ex);setBulkMode(false);runSearchFor(ex);}} style={{padding:'6px 10px',borderRadius:6,background:'var(--surface2)',border:'1px solid var(--border)',fontFamily:'var(--mono)',fontSize:11,color:'var(--text-muted)',textAlign:'left',transition:'all 0.1s'}}>
                    {ex}
                  </button>
                ))}
              </div>
            </div>
          </div>
          <div style={{flex:1,display:'flex',flexDirection:'column',overflow:'hidden',padding:16,gap:16}}>
            {loading && loadingView}
            {!loading && results && <ResultsPanel sources={results} val={query} isCompact={isCompact} accent={accent}/>}
            {!loading && bulkResults && bulkView}
            {!loading && !results && !bulkResults && emptyState}
          </div>
        </div>
      </div>
    );
  }

  // ── Dashboard layout ──────────────────────────────────────────────────────────
  return (
    <div style={{height:'100vh',display:'flex',flexDirection:'column',overflow:'hidden'}}>
      {header}
      <div style={{flex:1,display:'flex',overflow:'hidden'}}>
        <nav style={{width:52,flexShrink:0,borderRight:'1px solid var(--border)',background:'var(--surface)',display:'flex',flexDirection:'column',alignItems:'center',paddingTop:12,gap:4}}>
          {[['🔍','Search'],['📊','Dashboard'],['📁','Reports'],['⚙️','Settings']].map(([icon,label],i)=>(
            <button key={i} title={label} style={{width:36,height:36,borderRadius:8,display:'flex',alignItems:'center',justifyContent:'center',fontSize:16,background:i===0?`${accent}18`:'transparent',color:i===0?accent:'var(--text-muted)',transition:'all 0.15s'}}>
              {icon}
            </button>
          ))}
        </nav>
        <div style={{flex:1,display:'flex',flexDirection:'column',overflow:'hidden'}}>
          <div style={{padding:'12px 16px',borderBottom:'1px solid var(--border)',background:'var(--surface)',display:'flex',alignItems:'center',gap:12}}>
            {searchBar}
          </div>
          <div style={{flex:1,overflow:'auto',padding:16,display:'flex',flexDirection:'column',gap:16}}>
            {loading && loadingView}
            {!loading && results && <ResultsPanel sources={results} val={query} isCompact={isCompact} accent={accent}/>}
            {!loading && bulkResults && bulkView}
            {!loading && !results && !bulkResults && emptyState}
          </div>
        </div>
      </div>
    </div>
  );
}
