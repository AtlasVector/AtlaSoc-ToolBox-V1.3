import React from 'react';

// ─── Status helpers ──────────────────────────────────────────────────────────
export const STATUS_COLOR = {malicious:'var(--danger)',suspicious:'var(--amber)',clean:'var(--safe)',info:'var(--accent)',unknown:'var(--text-muted)'};
export const STATUS_LABEL = {malicious:'Malicious',suspicious:'Suspicious',clean:'Clean',info:'Info',unknown:'Unknown'};
export const IOC_LABELS = {'ip':'IPv4','ip6':'IPv6','domain':'Domain','url':'URL','email':'Email','hash-md5':'MD5 Hash','hash-sha1':'SHA-1 Hash','hash-sha256':'SHA-256 Hash','cve':'CVE','filename':'File Name','unknown':'Unknown'};

// ─── Error boundary ──────────────────────────────────────────────────────────
export class ErrorBoundary extends React.Component {
  constructor(props) { super(props); this.state = { error: null }; }
  static getDerivedStateFromError(error) { return { error }; }
  render() {
    if (this.state.error) return this.props.fallback(this.state.error);
    return this.props.children;
  }
}

// ─── UI Components ───────────────────────────────────────────────────────────
export const Badge = ({label, color, small}) => (
  <span style={{display:'inline-flex',alignItems:'center',gap:4,padding:small?'2px 7px':'3px 9px',borderRadius:100,fontSize:small?11:12,fontWeight:600,background:`${color}18`,color,border:`1px solid ${color}28`,letterSpacing:'0.02em',textTransform:'uppercase'}}>
    {label}
  </span>
);

export const Dot = ({status}) => (
  <span style={{width:7,height:7,borderRadius:'50%',background:STATUS_COLOR[status]||'var(--text-muted)',display:'inline-block',boxShadow:`0 0 6px ${STATUS_COLOR[status]||'transparent'}`}}/>
);

export const DetectionBar = ({detected, total}) => {
  const pct = total > 0 ? (detected/total)*100 : 0;
  const color = detected===0?'var(--safe)':detected<=5?'var(--amber)':'var(--danger)';
  return (
    <div>
      <div style={{display:'flex',justifyContent:'space-between',marginBottom:6}}>
        <span style={{fontFamily:'var(--mono)',fontSize:13,color}}>{detected}<span style={{color:'var(--text-muted)',fontWeight:400}}>/{total} engines</span></span>
        <span style={{fontSize:12,color:'var(--text-muted)'}}>{pct.toFixed(1)}% detection rate</span>
      </div>
      <div style={{height:6,background:'var(--surface3)',borderRadius:3,overflow:'hidden'}}>
        <div style={{width:`${pct}%`,height:'100%',background:color,borderRadius:3,transition:'width 0.8s ease'}}/>
      </div>
    </div>
  );
};

export const ScoreRing = ({score, label, max=100, color}) => {
  const c = color || (score>60?'var(--danger)':score>30?'var(--amber)':'var(--safe)');
  const pct = Math.min(100, score/max*100);
  const r = 28, circ = 2*Math.PI*r;
  return (
    <div style={{display:'flex',flexDirection:'column',alignItems:'center',gap:4}}>
      <svg width={72} height={72} viewBox="0 0 72 72" style={{transform:'rotate(-90deg)'}}>
        <circle cx={36} cy={36} r={r} fill="none" stroke="var(--surface3)" strokeWidth={5}/>
        <circle cx={36} cy={36} r={r} fill="none" stroke={c} strokeWidth={5} strokeDasharray={circ} strokeDashoffset={circ*(1-pct/100)} strokeLinecap="round" style={{transition:'stroke-dashoffset 0.8s ease'}}/>
        <text x={36} y={36} textAnchor="middle" dominantBaseline="middle" style={{fill:'var(--text)',fontSize:15,fontFamily:'var(--mono)',fontWeight:700,transform:'rotate(90deg) translate(-72px,0)'}}>{score}</text>
      </svg>
      <span style={{fontSize:11,color:'var(--text-muted)',textAlign:'center',textTransform:'uppercase',letterSpacing:'0.05em'}}>{label}</span>
    </div>
  );
};

export const InfoRow = ({label, value, mono, color}) => (
  <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',gap:12,padding:'7px 0',borderBottom:'1px solid var(--border)'}}>
    <span style={{color:'var(--text-muted)',fontSize:12,flexShrink:0,minWidth:120}}>{label}</span>
    <span style={{fontFamily:mono?'var(--mono)':undefined,fontSize:mono?12:13,color:color||'var(--text)',textAlign:'right',wordBreak:'break-all'}}>{value}</span>
  </div>
);

export const Tag = ({text, danger, warn}) => (
  <span style={{display:'inline-block',padding:'2px 8px',borderRadius:4,fontSize:11,fontWeight:500,background:danger?'rgba(239,68,68,0.12)':warn?'rgba(245,158,11,0.12)':'var(--surface3)',color:danger?'var(--danger)':warn?'var(--amber)':'var(--text-dim)',border:`1px solid ${danger?'rgba(239,68,68,0.2)':warn?'rgba(245,158,11,0.2)':'var(--border2)'}`,textTransform:'uppercase',letterSpacing:'0.04em'}}>
    {text}
  </span>
);

// ─── Shared source-panel error state ──────────────────────────────────────────
export function renderError(d) {
  return (
    <div style={{padding:'20px 0',textAlign:'center'}}>
      <div style={{fontSize:28,marginBottom:8}}>⚠</div>
      <div style={{color:'var(--amber)',fontWeight:600,marginBottom:4}}>{d.source} unavailable</div>
      <div style={{fontSize:12,color:'var(--text-muted)'}}>{d.error}</div>
    </div>
  );
}

// ─── Logo Mark ───────────────────────────────────────────────────────────────
export const LogoMark = ({size = 22}) => (
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 96" width={size} height={Math.round(size * 1.2)} style={{flexShrink:0,color:'var(--accent)'}}>
    <defs>
      <clipPath id="av-lmc">
        <path d="M 40 2 L 78 17 L 78 50 C 78 72 58 89 40 95 C 22 89 2 72 2 50 L 2 17 Z" />
      </clipPath>
    </defs>
    <path d="M 40 2 L 78 17 L 78 50 C 78 72 58 89 40 95 C 22 89 2 72 2 50 L 2 17 Z" fill="#0b1628" />
    <g clipPath="url(#av-lmc)">
      <rect x="0" y="74" width="80" height="22" fill="#060f1c" />
      <polygon points="2,74 14,58 26,74" fill="#081a2a" />
      <polygon points="54,74 66,58 78,74" fill="#071628" />
      <polygon points="18,76 40,44 62,76" fill="#0e2a40" />
      <polyline points="18,76 40,44 62,76" fill="none" stroke="currentColor" strokeWidth="1.3" strokeOpacity="0.85" strokeLinejoin="round" />
      <polygon points="36.5,52 40,44 43.5,52" fill="currentColor" opacity="0.45" />
      <circle cx="40" cy="44" r="14" fill="none" stroke="currentColor" strokeWidth="1" strokeDasharray="7.5 4.5" strokeDashoffset="4" opacity="0.75" />
      <circle cx="40" cy="44" r="5.5" fill="none" stroke="currentColor" strokeWidth="1" opacity="0.9" />
      <circle cx="40" cy="44" r="2" fill="currentColor" />
      <line x1="40" y1="24" x2="40" y2="36" stroke="currentColor" strokeWidth="1.1" strokeLinecap="round" opacity="0.9" />
      <line x1="40" y1="52" x2="40" y2="64" stroke="currentColor" strokeWidth="1.1" strokeLinecap="round" opacity="0.9" />
      <line x1="20" y1="44" x2="31" y2="44" stroke="currentColor" strokeWidth="1.1" strokeLinecap="round" opacity="0.9" />
      <line x1="49" y1="44" x2="60" y2="44" stroke="currentColor" strokeWidth="1.1" strokeLinecap="round" opacity="0.9" />
      <path d="M 10,20 H 18 V 28 H 26" fill="none" stroke="currentColor" strokeWidth="0.75" strokeOpacity="0.4" strokeLinecap="round" strokeLinejoin="round" />
      <rect x="8" y="18" width="4" height="4" rx="1" fill="none" stroke="currentColor" strokeWidth="0.7" strokeOpacity="0.5" />
      <circle cx="26" cy="28" r="1.5" fill="currentColor" opacity="0.5" />
      <path d="M 70,20 H 62 V 28 H 54" fill="none" stroke="currentColor" strokeWidth="0.75" strokeOpacity="0.4" strokeLinecap="round" strokeLinejoin="round" />
      <rect x="68" y="18" width="4" height="4" rx="1" fill="none" stroke="currentColor" strokeWidth="0.7" strokeOpacity="0.5" />
      <circle cx="54" cy="28" r="1.5" fill="currentColor" opacity="0.5" />
    </g>
    <path d="M 40 2 L 78 17 L 78 50 C 78 72 58 89 40 95 C 22 89 2 72 2 50 L 2 17 Z" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinejoin="round" />
  </svg>
);

export const BrandName = ({accent}) => (
  <React.Fragment>Atla<span style={{color:accent}}>Soc</span>
  </React.Fragment>
);
