const rateLimitMap = new Map();
let rlCleanupCounter = 0;
function isRateLimited(ip, maxPerMinute = 30) {
  const now = Date.now();
  // Amortized cleanup every 1000 requests — keeps map bounded, O(1) per-request average
  if (++rlCleanupCounter >= 1000) {
    rlCleanupCounter = 0;
    for (const [key, entry] of rateLimitMap) {
      if (now - entry.start > 60_000) rateLimitMap.delete(key);
    }
  }
  const entry = rateLimitMap.get(ip) || { count: 0, start: now };
  if (now - entry.start > 60_000) {
    rateLimitMap.set(ip, { count: 1, start: now });
    return false;
  }
  entry.count++;
  rateLimitMap.set(ip, entry);
  return entry.count > maxPerMinute;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
const SECURITY_HEADERS = {
  'Content-Type': 'application/json',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
};

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...SECURITY_HEADERS, ...extra } });
}

// ─── KV cache ────────────────────────────────────────────────────────────────
const CACHE_TTL = 3600;

async function kvGet(kv, key) {
  try { const v = await kv.get(key); return v ? JSON.parse(v) : null; }
  catch { return null; }
}

async function kvPut(kv, key, data) {
  try { await kv.put(key, JSON.stringify(data), { expirationTtl: CACHE_TTL }); }
  catch {}
}
function err(msg, status = 400) {
  return json({ error: msg }, status);
}

// Returns an AbortSignal that times out after `ms` milliseconds.
function timeout(ms) {
  return AbortSignal.timeout ? AbortSignal.timeout(ms) : (() => {
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), ms);
    return ctrl.signal;
  })();
}

// Valid indicator types accepted by each route handler.
const VALID_TYPES = new Set([
  'ip', 'ip6', 'domain', 'url',
  'hash-md5', 'hash-sha1', 'hash-sha256',
  'email', 'filename',
]);

// ─── Source handlers ──────────────────────────────────────────────────────────

async function handleVirusTotal(ioc, type, env) {
  if (!env.VT_API_KEY) return { error: 'VirusTotal not configured' };
  const typeMap = {
    ip: 'ip_addresses', ip6: 'ip_addresses', domain: 'domains', url: 'urls',
    'hash-md5': 'files', 'hash-sha1': 'files', 'hash-sha256': 'files',
    filename: 'files', email: 'domains',
  };
  let endpoint;
  if (type === 'url') {
    const encoded = btoa(ioc).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
    endpoint = `https://www.virustotal.com/api/v3/urls/${encoded}`;
  } else {
    const vtType = typeMap[type] || 'files';
    const id = type === 'email' ? ioc.split('@')[1] : ioc;
    endpoint = `https://www.virustotal.com/api/v3/${vtType}/${encodeURIComponent(id)}`;
  }
  const res = await fetch(endpoint, {
    headers: { 'x-apikey': env.VT_API_KEY },
    signal: timeout(8000),
  });
  if (!res.ok) {
    // Don't leak quota/auth error messages from the upstream API to the client.
    return { error: `VirusTotal returned ${res.status}` };
  }
  const data = await res.json();
  const stats = data?.data?.attributes?.last_analysis_stats || {};
  const meta  = data?.data?.attributes || {};
  return {
    source: 'VirusTotal',
    detected: stats.malicious || 0,
    total: Object.values(stats).reduce((a,b)=>a+b,0) || 0,
    suspicious: stats.suspicious || 0,
    harmless: stats.harmless || 0,
    lastAnalysis: meta.last_analysis_date ? new Date(meta.last_analysis_date*1000).toISOString().split('T')[0] : null,
    reputation: meta.reputation ?? null,
    categories: meta.categories ? Object.values(meta.categories) : [],
    tags: meta.tags || [],
    fileType: meta.type_description || null,
    fileSize: meta.size ? `${Math.round(meta.size/1024)} KB` : null,
    firstSeen: meta.first_submission_date ? new Date(meta.first_submission_date*1000).toISOString().split('T')[0] : null,
    permalink: `https://www.virustotal.com/gui/${typeMap[type]||'files'}/${ioc}`,
  };
}

async function handleAbuseIPDB(ip, env) {
  if (!env.ABUSEIPDB_KEY) return { error: 'AbuseIPDB not configured' };
  const res = await fetch(
    `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`,
    { headers: { Key: env.ABUSEIPDB_KEY, Accept: 'application/json' }, signal: timeout(8000) }
  );
  if (!res.ok) return { error: `AbuseIPDB returned ${res.status}` };
  const { data } = await res.json();
  return {
    source: 'AbuseIPDB',
    abuseScore: data.abuseConfidenceScore,
    country: data.countryCode,
    isp: data.isp,
    domain: data.domain,
    usageType: data.usageType,
    totalReports: data.totalReports,
    numDistinctUsers: data.numDistinctUsers,
    lastReported: data.lastReportedAt ? data.lastReportedAt.split('T')[0] : null,
    isWhitelisted: data.isWhitelisted,
    tor: data.isTor,
    ipVersion: data.ipVersion,
  };
}

async function handleShodan(ip, env) {
  if (!env.SHODAN_KEY) return { error: 'Shodan not configured' };
  // Shodan host endpoint only accepts the key as a query parameter (no header support).
  const res = await fetch(
    `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${env.SHODAN_KEY}`,
    { signal: timeout(8000) }
  );
  if (res.status === 404) return { source: 'Shodan', found: false };
  if (!res.ok) return { error: `Shodan returned ${res.status}` };
  const data = await res.json();
  return {
    source: 'Shodan', found: true,
    ports: data.ports || [],
    hostnames: data.hostnames || [],
    os: data.os || null,
    org: data.org || null,
    asn: data.asn || null,
    country: data.country_name || null,
    city: data.city || null,
    vulns: data.vulns ? Object.keys(data.vulns) : [],
    tags: data.tags || [],
    lastSeen: data.last_update ? data.last_update.split('T')[0] : null,
    services: (data.data||[]).slice(0,10).map(s=>({ port:s.port, transport:s.transport, product:s.product||null, version:s.version||null })),
  };
}

async function handleOTX(ioc, type, env) {
  const key = env.OTX_KEY || '';
  const otxTypeMap = { ip:'IPv4', ip6:'IPv6', domain:'domain', url:'url', 'hash-md5':'file', 'hash-sha1':'file', 'hash-sha256':'file', email:'email', filename:'file' };
  const otxType = otxTypeMap[type] || 'domain';
  const res = await fetch(
    `https://otx.alienvault.com/api/v1/indicators/${otxType}/${encodeURIComponent(ioc)}/general`,
    { headers: key ? { 'X-OTX-API-KEY': key } : {}, signal: timeout(8000) }
  );
  if (!res.ok) return { error: `OTX returned ${res.status}` };
  const data = await res.json();
  return {
    source: 'AlienVault OTX',
    pulses: data?.pulse_info?.count || 0,
    threatScore: data?.reputation || 0,
    malwareFamilies: data?.pulse_info?.pulses?.flatMap(p=>p.malware_families||[]).slice(0,5) || [],
    categories: data?.pulse_info?.pulses?.flatMap(p=>p.tags||[]).slice(0,8) || [],
    adversaries: data?.pulse_info?.pulses?.flatMap(p=>p.adversary?[p.adversary]:[]).slice(0,3) || [],
    relatedIndicators: data?.pulse_info?.related_indicator_count || 0,
    firstSeen: data?.pulse_info?.pulses?.[0]?.created?.split('T')[0] || null,
    lastSeen: data?.pulse_info?.pulses?.sort((a,b)=>new Date(b.modified)-new Date(a.modified))[0]?.modified?.split('T')[0] || null,
  };
}

async function handleURLScan(ioc, type, env) {
  const key = env.URLSCAN_KEY || '';
  const q = type === 'domain' ? `domain:${ioc}` : `page.url:${ioc}`;
  const searchRes = await fetch(
    `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(q)}&size=1`,
    { headers: key ? { 'API-Key': key } : {}, signal: timeout(8000) }
  );
  if (!searchRes.ok) return { error: `URLScan returned ${searchRes.status}` };
  const searchData = await searchRes.json();
  const hit = searchData?.results?.[0];
  if (!hit) return { source: 'URLScan.io', found: false };
  return {
    source: 'URLScan.io', found: true,
    verdicts: hit.verdicts || {},
    ip: hit.page?.ip || null,
    country: hit.page?.country || null,
    server: hit.page?.server || null,
    title: hit.page?.title || null,
    screenshot: hit.screenshot || null,
    reportUrl: `https://urlscan.io/result/${hit._id}/`,
    technologies: hit.page?.technologies?.map(t=>t.name) || [],
  };
}

async function handleWHOIS(ioc, type) {
  const domain = type === 'email' ? ioc.split('@')[1] : ioc;
  const isIP = type === 'ip' || type === 'ip6';

  const endpoints = isIP ? [
    `https://rdap.org/ip/${encodeURIComponent(ioc)}`,
    `https://rdap.arin.net/registry/ip/${encodeURIComponent(ioc)}`,
    `https://rdap.db.ripe.net/ip/${encodeURIComponent(ioc)}`,
    `https://rdap.apnic.net/ip/${encodeURIComponent(ioc)}`,
  ] : [
    `https://rdap.org/domain/${encodeURIComponent(domain)}`,
    `https://rdap.verisign.com/com/v1/domain/${encodeURIComponent(domain)}`,
  ];

  let data = null;
  for (const endpoint of endpoints) {
    try {
      const res = await fetch(endpoint, {
        headers: { Accept: 'application/json' },
        cf: { connectTimeoutMs: 4000 },
        signal: timeout(6000),
      });
      if (res.ok) { data = await res.json(); break; }
    } catch { continue; }
  }
  if (!data) return { error: 'RDAP lookup failed — all endpoints unreachable' };
  const getDate = (events, action) => events?.find(e=>e.eventAction===action)?.eventDate?.split('T')[0] || null;
  const registrar = data.entities?.find(e=>e.roles?.includes('registrar'));
  return {
    source: 'WHOIS / RDAP',
    handle: data.handle || null,
    name: data.name || data.ldhName || null,
    status: Array.isArray(data.status) ? data.status : [data.status].filter(Boolean),
    country: data.country || null,
    registrar: registrar?.vcardArray?.[1]?.find(v=>v[0]==='fn')?.[3] || null,
    created: getDate(data.events, 'registration'),
    updated: getDate(data.events, 'last changed'),
    expires: getDate(data.events, 'expiration'),
    nameservers: data.nameservers?.map(ns=>ns.ldhName?.toLowerCase()) || [],
    cidr: data.cidr0_cidrs?.[0] ? `${data.cidr0_cidrs[0].v4prefix||data.cidr0_cidrs[0].v6prefix}/${data.cidr0_cidrs[0].length}` : null,
    asn: data.handle?.startsWith('AS') ? data.handle : null,
  };
}

async function handleMalwareBazaar(hash) {
  const res = await fetch('https://mb-api.abuse.ch/api/v1/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `query=get_info&hash=${encodeURIComponent(hash)}`,
    signal: timeout(8000),
  });
  if (!res.ok) return { error: `MalwareBazaar returned ${res.status}` };
  const data = await res.json();
  if (data.query_status !== 'ok') return { source: 'MalwareBazaar', found: false };
  const s = data.data?.[0];
  return {
    source: 'MalwareBazaar', found: true,
    fileName: s?.file_name, fileType: s?.file_type,
    fileSize: s?.file_size ? `${Math.round(s.file_size/1024)} KB` : null,
    malwareFamily: s?.signature, tags: s?.tags || [],
    firstSeen: s?.first_seen?.split(' ')[0] || null,
    deliveryMethod: s?.delivery_method || null,
    reporter: s?.reporter || null,
  };
}

// ─── Main handler ─────────────────────────────────────────────────────────────
export async function onRequest({ request, env, waitUntil }) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204 });
  if (request.method !== 'GET') return err('Method not allowed', 405);

  // Rate limit
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (isRateLimited(ip, 30)) return err('Rate limit exceeded', 429);

  const url    = new URL(request.url);
  const route  = url.pathname.replace(/^\/api\//, '');

  if (route === 'health') return json({ status: 'ok' });

  const ioc    = url.searchParams.get('ioc');
  const type   = url.searchParams.get('type');

  if (!ioc || !type) return err('Missing params: ioc, type');
  if (ioc.length > 2048) return err('Indicator too long');
  if (!VALID_TYPES.has(type)) return err(`Invalid type: must be one of ${[...VALID_TYPES].join(', ')}`);
  if (!/^[a-zA-Z0-9._:/@%+=?&\-[\]]+$/.test(ioc)) return err('Invalid indicator');

  const kv = env.ATLASOC_CACHE;

  try {
    const cacheKey = `${route}:${type}:${ioc.toLowerCase()}`;

    if (kv) {
      const hit = await kvGet(kv, cacheKey);
      if (hit) return json(hit, 200, { 'X-Cache': 'HIT' });
    }

    let result;
    switch (route) {
      case 'vt':      result = await handleVirusTotal(ioc, type, env); break;
      case 'abuse':   result = await handleAbuseIPDB(ioc, env); break;
      case 'shodan':  result = await handleShodan(ioc, env); break;
      case 'otx':     result = await handleOTX(ioc, type, env); break;
      case 'urlscan': result = await handleURLScan(ioc, type, env); break;
      case 'whois':   result = await handleWHOIS(ioc, type); break;
      case 'bazaar':  result = await handleMalwareBazaar(ioc); break;
      default:        return err('Not found', 404);
    }

    // Don't cache error responses — upstream may be transiently down
    if (kv && !result?.error) waitUntil(kvPut(kv, cacheKey, result));

    return json(result, 200, { 'X-Cache': kv ? 'MISS' : 'BYPASS' });
  } catch (e) {
    console.error(e);
    return err('Internal error', 500);
  }
}