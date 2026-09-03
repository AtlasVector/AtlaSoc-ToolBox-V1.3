// KV-backed rate limiter — global across all Worker isolates.
// Reuses ATLASOC_CACHE binding (keys prefixed "rl:" to avoid collision with response cache).
// Approximate: concurrent requests in the same window can race, but close enough for abuse prevention.
//
// Two counters share one 60s window: a per-IP cap (catches a single abusive client) and a
// coarse global cap across all IPs (catches abuse spread over rotating/many IPs, which the
// per-IP cap alone can't see).
//
// KV availability drives the fallback in opposite directions on purpose:
//   - No binding at all (`kv` is undefined) means local dev without KV configured — allow,
//     same as before.
//   - Binding present but a call throws (a real production KV outage) fails CLOSED — block —
//     because "fail open" here means unlimited free use of paid upstream APIs for as long as
//     KV stays down. A logged, temporary 429 is the safer failure mode.
async function checkCounter(kv, key, max) {
  const now = Date.now();
  const raw = await kv.get(key);
  if (raw) {
    const entry = JSON.parse(raw);
    if (now - entry.start < 60_000) {
      if (entry.count >= max) return true;
      await kv.put(key, JSON.stringify({ count: entry.count + 1, start: entry.start }), { expirationTtl: 60 });
      return false;
    }
  }
  await kv.put(key, JSON.stringify({ count: 1, start: now }), { expirationTtl: 60 });
  return false;
}

export async function isRateLimited(kv, ip, maxPerMinute = 30, maxGlobalPerMinute = 300) {
  if (!kv) return false;
  try {
    const [ipLimited, globalLimited] = await Promise.all([
      checkCounter(kv, `rl:${ip}`, maxPerMinute),
      checkCounter(kv, 'rl:global', maxGlobalPerMinute),
    ]);
    return ipLimited || globalLimited;
  } catch (e) {
    console.error('Rate limiter KV error — failing closed:', e.message);
    return true;
  }
}

// ─── Per-source rate limits / cache TTL / circuit breaker defaults ─────────────
const SOURCE_LIMITS = {
  vt:      { perMinute: 4, perDay: 500, cacheHitTtl: 24*3600, cacheMissTtl: 2*3600, maliciousThreshold: 3 },
  abuse:   { perMinute: 30, perDay: 1000, cacheHitTtl: 8*3600, cacheMissTtl: 1*3600, scoreThresholds: { malicious: 75, suspicious: 25 } },
  shodan:  { perMinute: 1, perDay: null, cacheHitTtl: 36*3600, cacheMissTtl: 4*3600 },
  greynoise: { perMinute: 2, perDay: 50, cacheHitTtl: 8*3600, cacheMissTtl: 1*3600 },
  otx:     { perMinute: 10, perDay: null, cacheHitTtl: 24*3600, cacheMissTtl: 4*3600 },
  urlscan: { perMinute: 1, perDay: 100, cacheHitTtl: 24*3600, cacheMissTtl: 4*3600 },
  whois:   { perMinute: 10, perDay: null, cacheHitTtl: 48*3600, cacheMissTtl: 4*3600 },
  bazaar:  { perMinute: 10, perDay: null, cacheHitTtl: 24*3600, cacheMissTtl: 4*3600 },
  cve:     { perMinute: 10, perDay: null, cacheHitTtl: 12*3600, cacheMissTtl: 2*3600 },
  dns:     { perMinute: 30, perDay: null, cacheHitTtl: 12*3600, cacheMissTtl: 2*3600 },
};

function sourceConfig(source) {
  return SOURCE_LIMITS[source] || { perMinute: 10, perDay: null, cacheHitTtl: 3600, cacheMissTtl: 1800 };
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
const DEFAULT_CACHE_TTL = 3600;

async function kvGet(kv, key) {
  try { const v = await kv.get(key); return v ? JSON.parse(v) : null; }
  catch { return null; }
}

async function kvPut(kv, key, data, ttlSeconds) {
  try {
    await kv.put(key, JSON.stringify(data), { expirationTtl: ttlSeconds || DEFAULT_CACHE_TTL });
    return true;
  } catch (e) {
    const msg = String(e?.message || '');
    if (msg.includes('429') || msg.includes('limit') || msg.includes('quota')) {
      console.warn(`KV write skipped for ${key}: quota/limit reached`);
      return false;
    }
    console.error(`KV write failed for ${key}:`, msg);
    return false;
  }
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
  'email', 'filename', 'cve',
]);

// ─── Shared resilience layer ──────────────────────────────────────────────────
const MAX_RETRIES = 3;
const BASE_RETRY_DELAY = 500;

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// A request that timed out (AbortSignal.timeout / AbortController) already spent
// its full `timeout(ms)` budget once; retrying it burns that same budget again
// per attempt (up to MAX_RETRIES times) while the caller waits, for a source
// that just proved itself slow. That's the dominant cause of multi-second
// stalls on a single sluggish source, so timeouts fail fast instead of retrying.
function isTimeoutError(e) {
  return e?.name === 'AbortError' || e?.name === 'TimeoutError';
}

export async function withRetry(fn, env) {
  let attempt = 0;
  while (true) {
    try {
      return await fn();
    } catch (e) {
      attempt++;
      if (attempt >= MAX_RETRIES) throw e;
      if (isTimeoutError(e)) throw e;
      const status = e?.status || e?.response?.status;
      if (status >= 400 && status < 500 && status !== 429) throw e;
      const delay = BASE_RETRY_DELAY * Math.pow(2, attempt - 1) + Math.floor(Math.random() * 250);
      await sleep(delay);
    }
  }
}

async function cbGet(kv, source) {
  const raw = await kv.get(`cb:${source}`);
  return raw ? JSON.parse(raw) : { state: 'closed', until: 0, failures: 0 };
}

async function cbPut(kv, source, state) {
  try {
    await kv.put(`cb:${source}`, JSON.stringify(state), { expirationTtl: 120 });
    return true;
  } catch (e) {
    console.error(`CB write failed for ${source}:`, e.message);
    return false;
  }
}

async function otxBackoffState(kv) {
  if (!kv) return null;
  try {
    const raw = await kv.get('backoff:otx');
    if (!raw) return null;
    const state = JSON.parse(raw);
    if (state.until > Date.now()) return state;
    return null;
  } catch {
    return null;
  }
}

async function setOtxBackoff(kv, failures) {
  if (!kv) return;
  const backoffMs = Math.min(30000, 1000 * Math.pow(2, failures));
  await kv.put('backoff:otx', JSON.stringify({ until: Date.now() + backoffMs, failures }), { expirationTtl: 60 });
}

async function resetOtxBackoff(kv) {
  if (!kv) return;
  try { await kv.delete('backoff:otx'); } catch {}
}

async function withCircuitBreaker(kv, source, fn) {
  if (!kv) return fn();
  const state = await cbGet(kv, source);
  const now = Date.now();
  if (state.state === 'open' && now < state.until) {
    const err = new Error(`SourceUnavailable ${source}`);
    err.code = 'SourceUnavailable';
    err.source = source;
    throw err;
  }
  try {
    const result = await fn();
    const closed = await cbPut(kv, source, { state: 'closed', until: 0, failures: 0 });
    if (!closed) return result;
    return result;
  } catch (e) {
    const next = { ...state, failures: (state.failures || 0) + 1 };
    if (next.failures >= 5) {
      next.state = 'open';
      next.until = Date.now() + 60_000;
    }
    await cbPut(kv, source, next);
    throw e;
  }
}

async function perSourceRateLimit(kv, source) {
  if (!kv) return false;
  const cfg = sourceConfig(source);
  if (!cfg.perMinute) return false;
  const minuteKey = `rl:src:${source}`;
  const now = Date.now();
  const raw = await kv.get(minuteKey);
  if (raw) {
    const entry = JSON.parse(raw);
    if (now - entry.start < 60_000) {
      if (entry.count >= cfg.perMinute) return true;
      const next = entry.count + 1;
      if (next >= cfg.perMinute) {
        await kvPut(kv, minuteKey, JSON.stringify({ count: next, start: entry.start }), 60);
      }
      return false;
    }
  }
  await kvPut(kv, minuteKey, JSON.stringify({ count: 1, start: now }), 60);
  return false;
}

async function withCache(kv, source, type, ioc, fn, fetchedAt = Date.now()) {
  if (!kv) return { _cached: false, _stale: false, value: await fn() };
  const cfg = sourceConfig(source);
  const digest = `${type}:${String(ioc).toLowerCase()}`;
  const cacheKey = `intel:${source}:${digest}`;
  const hit = await kvGet(kv, cacheKey);
  if (hit) {
    const stale = Date.now() - new Date(hit.fetchedAt || 0).getTime() > (cfg.cacheHitTtl || DEFAULT_CACHE_TTL) * 1000;
    return { _cached: true, _stale: !!hit.stale || stale, value: hit };
  }
  const value = await fn();
  if (value && value.error) return { _cached: false, _stale: false, value };
  const ttl = cfg.cacheMissTtl || DEFAULT_CACHE_TTL;
  const payload = { ...value, fetchedAt: new Date(fetchedAt).toISOString(), stale: false };
  await kvPut(kv, cacheKey, payload, ttl);
  return { _cached: false, _stale: false, value: payload };
}

async function callWithResilience(kv, source, type, ioc, fn) {
  if (await perSourceRateLimit(kv, source)) {
    const limitedErr = new Error(`RateLimited ${source}`);
    limitedErr.code = 'RateLimited';
    limitedErr.source = source;
    throw limitedErr;
  }
  const result = await withCircuitBreaker(kv, source, () => withRetry(() => fn(), {}));
  const { _cached, _stale, value } = await withCache(kv, source, type, ioc, () => Promise.resolve(result));
  return { ...value, _cached, _stale };
}

// ─── Source handlers ──────────────────────────────────────────────────────────

async function handleVirusTotal(ioc, type, env) {
  if (!env.VT_API_KEY) return { error: 'VirusTotal not configured' };
  const typeMap = {
    ip: 'ip_addresses', ip6: 'ip_addresses', domain: 'domains', url: 'urls',
    'hash-md5': 'files', 'hash-sha1': 'files', 'hash-sha256': 'files',
    filename: 'files', email: 'domains',
  };
  // VirusTotal GUI URL format (different from API endpoints)
  const guiMap = {
    ip: 'ip-address', ip6: 'ip-address', domain: 'domain', url: 'url',
    'hash-md5': 'file', 'hash-sha1': 'file', 'hash-sha256': 'file',
    filename: 'file', email: 'domain',
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
  const engineResults = meta.last_analysis_results || {};
  const detectedEngines = Object.entries(engineResults)
    .filter(([, v]) => v.category === 'malicious' || v.category === 'suspicious')
    .slice(0, 10)
    .map(([name, v]) => ({ name, result: v.result, category: v.category }));
  const totalDetections = (stats.malicious || 0) + (stats.suspicious || 0);
  const status = totalDetections === 0 ? 'clean' : totalDetections <= 3 ? 'suspicious' : 'malicious';
  return {
    source: 'VirusTotal',
    status,
    detected: stats.malicious || 0,
    total: Object.values(stats).reduce((a,b)=>a+b,0) || 0,
    suspicious: stats.suspicious || 0,
    harmless: stats.harmless || 0,
    undetected: stats.undetected || 0,
    lastAnalysis: meta.last_analysis_date ? new Date(meta.last_analysis_date*1000).toISOString().split('T')[0] : null,
    reputation: meta.reputation ?? null,
    categories: meta.categories ? Object.values(meta.categories) : [],
    tags: meta.tags || [],
    fileType: meta.type_description || null,
    fileSize: meta.size ? `${Math.round(meta.size/1024)} KB` : null,
    firstSeen: meta.first_submission_date ? new Date(meta.first_submission_date*1000).toISOString().split('T')[0] : null,
    permalink: `https://www.virustotal.com/gui/${guiMap[type]||'file'}/${type === 'url' ? encoded : ioc}`,
    // IP/domain enrichment
    country: meta.country || null,
    asn: meta.asn || null,
    network: meta.network || null,
    asOwner: meta.as_owner || null,
    continent: meta.continent || null,
    registrar: meta.registrar || null,
    creationDate: meta.creation_date ? new Date(meta.creation_date*1000).toISOString().split('T')[0] : null,
    engines: detectedEngines,
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
    countryName: data.countryName || null,
    isp: data.isp,
    domain: data.domain,
    usageType: data.usageType,
    totalReports: data.totalReports,
    numDistinctUsers: data.numDistinctUsers,
    lastReported: data.lastReportedAt ? data.lastReportedAt.split('T')[0] : null,
    isWhitelisted: data.isWhitelisted,
    tor: data.isTor,
    ipVersion: data.ipVersion,
    permalink: `https://www.abuseipdb.com/check/${ip}`,
    recentReports: (data.reports || []).slice(0, 5).map(r => ({
      date: r.reportedAt ? r.reportedAt.split('T')[0] : null,
      categories: r.categories || [],
      comment: r.comment ? r.comment.slice(0, 120) : null,
    })),
  };
}

async function handleShodan(ip, env) {
  if (!env.SHODAN_KEY) return { error: 'Shodan not configured' };
  const key = env.SHODAN_KEY;
  const res = await fetch(
    `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(key)}`,
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
    permalink: `https://www.shodan.io/host/${ip}`,
  };
}

async function handleGreyNoise(ip, env) {
  if (!env.GREYNOISE_KEY) return { error: 'GreyNoise not configured' };
  const res = await fetch(
    `https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`,
    { headers: { key: env.GREYNOISE_KEY, Accept: 'application/json' }, signal: timeout(8000) }
  );
  if (res.status === 404) return { source: 'GreyNoise', found: false };
  if (!res.ok) return { error: `GreyNoise returned ${res.status}` };
  const data = await res.json();
  return {
    source: 'GreyNoise',
    found: true,
    noise: !!data.noise,
    riot: !!data.riot,
    classification: data.classification || 'unknown',
    name: data.name || null,
    lastSeen: data.last_seen || null,
    message: data.message || null,
    permalink: data.link || `https://viz.greynoise.io/ip/${ip}`,
  };
}

async function handleOTX(ioc, type, env) {
  if (!env.OTX_KEY) return { error: 'OTX not configured' };
  const key = env.OTX_KEY;
  const otxTypeMap = { ip:'IPv4', ip6:'IPv6', domain:'domain', url:'url', 'hash-md5':'file', 'hash-sha1':'file', 'hash-sha256':'file', email:'email', filename:'file' };
  const otxType = otxTypeMap[type] || 'domain';
  if (env.ATLASOC_CACHE) {
    const backoff = await otxBackoffState(env.ATLASOC_CACHE);
    if (backoff) {
      const err = new Error(`RateLimited OTX`);
      err.code = 'RateLimited';
      err.source = 'otx';
      throw err;
    }
  }
  let ok = false;
  try {
    const res = await fetch(
      `https://otx.alienvault.com/api/v1/indicators/${otxType}/${encodeURIComponent(ioc)}/general`,
      { headers: { 'X-OTX-API-KEY': key }, signal: timeout(8000) }
    );
    if (!res.ok) return { error: `OTX returned ${res.status}` };
    const data = await res.json();
    if (env.ATLASOC_CACHE) await resetOtxBackoff(env.ATLASOC_CACHE);
    ok = true;
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
      permalink: data?.pulse_info?.pulses?.[0] ? `https://otx.alienvault.com/pulse/${data.pulse_info.pulses[0].id}/` : `https://otx.alienvault.com/indicators/${otxType}/${encodeURIComponent(ioc)}/`,
    };
  } catch (e) {
    if (!ok && env.ATLASOC_CACHE) {
      const raw = await kvGet(env.ATLASOC_CACHE, 'backoff:otx');
      const failures = raw ? (JSON.parse(raw).failures || 1) + 1 : 1;
      await setOtxBackoff(env.ATLASOC_CACHE, failures);
    }
    throw e;
  }
}

// URLScan's public search endpoint doesn't reliably scope results to the
// query term (anonymous/no-key requests especially) — it can hand back a
// top hit for a completely unrelated domain. Only trust a hit whose own
// domain is the queried domain or one of its subdomains/parent domains.
export function urlscanDomainMatches(queried, resultDomain) {
  if (!queried || !resultDomain) return false;
  const a = String(queried).toLowerCase().replace(/\.$/, '');
  const b = String(resultDomain).toLowerCase().replace(/\.$/, '');
  return a === b || a.endsWith(`.${b}`) || b.endsWith(`.${a}`);
}

export async function handleURLScan(ioc, type, env) {
  const key = env.URLSCAN_KEY || '';
  // For URLScan, search by domain extracted from URL, or direct URL
  let q;
  if (type === 'url') {
    // Extract domain from URL for better search results
    try {
      q = new URL(ioc).hostname;
    } catch {
      q = ioc;
    }
  } else {
    q = ioc;
  }
  const searchRes = await fetch(
    `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(q)}&size=1`,
    { headers: key ? { 'API-Key': key } : {}, signal: timeout(8000) }
  );
  if (!searchRes.ok) return { error: `URLScan returned ${searchRes.status}` };
  const searchData = await searchRes.json();
  const hit = searchData?.results?.[0];
  if (!hit || !urlscanDomainMatches(q, hit.page?.domain || hit.task?.domain)) return { source: 'URLScan.io', found: false };
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
    `https://rdap.db.ripe.net/registry/ip/${encodeURIComponent(ioc)}`,
    `https://rdap.apnic.net/ip/${encodeURIComponent(ioc)}`,
  ] : [
    `https://rdap.org/domain/${encodeURIComponent(domain)}`,
    `https://rdap.verisign.com/com/v1/domain/${encodeURIComponent(domain)}`,
  ];

  let lastStatus = null;
  let data = null;
  for (const endpoint of endpoints) {
    try {
      const res = await fetch(endpoint, {
        headers: { Accept: 'application/json' },
        cf: { connectTimeoutMs: 4000 },
        signal: timeout(6000),
      });
      lastStatus = res.status;
      if (res.ok) { data = await res.json(); break; }
    } catch { lastStatus = 'timeout'; }
  }
  if (!data) return { error: `RDAP lookup failed — all endpoints unreachable (last status: ${lastStatus || 'none'})` };
  const getDate = (events, action) => events?.find(e=>e.eventAction===action)?.eventDate?.split('T')[0] || null;
  const registrar = data.entities?.find(e=>e.roles?.includes('registrar'));
  const nameservers = data.nameservers?.map(ns=>ns.ldhName?.toLowerCase()) || [];
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
    nameservers,
    found: nameservers.length > 0 || !!data.ldhName || !!data.handle,
    cidr: data.cidr0_cidrs?.[0] ? `${data.cidr0_cidrs[0].v4prefix||data.cidr0_cidrs[0].v6prefix}/${data.cidr0_cidrs[0].length}` : null,
    asn: data.handle?.startsWith('AS') ? data.handle : null,
    permalink: isIP ? `https://rdap.org/ip/${encodeURIComponent(ioc)}` : `https://rdap.org/domain/${encodeURIComponent(domain)}`,
  };
}

async function handleMalwareBazaar(hash, env) {
  const res = await fetch('https://mb-api.abuse.ch/api/v1/', {
    method: 'POST',
    headers: {
      'Auth-Key': env.MALWAREBAZAAR_KEY || '',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: `query=get_info&hash=${encodeURIComponent(hash)}`,
    signal: timeout(8000),
  });
  if (res.status === 401 || res.status === 403) return { error: 'MalwareBazaar not configured' };
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
    permalink: `https://bazaar.abuse.ch/sample/${hash}/`,
  };
}

async function handleCVE(cveId, env) {
  const id = cveId.toUpperCase();

  // Primary: NVD (NIST) — authoritative, free, optional API key for higher rate limit
  const nvdHeaders = env.NVD_API_KEY ? { 'apiKey': env.NVD_API_KEY } : {};
  try {
    const nvdRes = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(id)}`,
      { headers: nvdHeaders, signal: timeout(10000) }
    );
    if (nvdRes.ok) {
      const nvdData = await nvdRes.json();
      const vuln = nvdData?.vulnerabilities?.[0]?.cve;
      if (vuln) {
        const desc = vuln.descriptions?.find(d => d.lang === 'en')?.value || null;
        const cvssV31 = vuln.metrics?.cvssMetricV31?.[0];
        const cvssV30 = vuln.metrics?.cvssMetricV30?.[0];
        const cvssV2  = vuln.metrics?.cvssMetricV2?.[0];
        const cvss = cvssV31 || cvssV30 || cvssV2;
        const cvssData = cvss?.cvssData || {};
        const weaknesses = vuln.weaknesses?.flatMap(w =>
          w.description?.map(d => d.value).filter(v => v && v !== 'NVD-CWE-Other' && v !== 'NVD-CWE-noinfo')
        ).filter(Boolean) || [];
        const refs = (vuln.references || []).slice(0, 10).map(r => ({
          url: r.url,
          source: r.source || null,
          tags: r.tags || [],
        }));
        const cpes = (vuln.configurations || [])
          .flatMap(c => c.nodes || [])
          .flatMap(n => n.cpeMatch || [])
          .filter(c => c.vulnerable)
          .slice(0, 15)
          .map(c => c.criteria);

        return {
          source: 'NVD / NIST',
          id: vuln.id,
          description: desc,
          published: vuln.published?.split('T')[0] || null,
          lastModified: vuln.lastModified?.split('T')[0] || null,
          vulnStatus: vuln.vulnStatus || null,
          cvssScore: cvssData.baseScore ?? null,
          cvssVersion: cvssData.version || (cvssV31 ? '3.1' : cvssV30 ? '3.0' : cvssV2 ? '2.0' : null),
          severity: cvssData.baseSeverity || null,
          vectorString: cvssData.vectorString || null,
          attackVector: cvssData.attackVector || cvssData.accessVector || null,
          attackComplexity: cvssData.attackComplexity || cvssData.accessComplexity || null,
          privilegesRequired: cvssData.privilegesRequired || null,
          userInteraction: cvssData.userInteraction || null,
          scope: cvssData.scope || null,
          confidentialityImpact: cvssData.confidentialityImpact || null,
          integrityImpact: cvssData.integrityImpact || null,
          availabilityImpact: cvssData.availabilityImpact || null,
          exploitabilityScore: cvss?.exploitabilityScore ?? null,
          impactScore: cvss?.impactScore ?? null,
          weaknesses,
          references: refs,
          affectedProducts: cpes,
          cisaExploited: vuln.cisaExploitAdd ? true : false,
          cisaActionDue: vuln.cisaActionDue || null,
          permalink: `https://nvd.nist.gov/vuln/detail/${vuln.id}`,
        };
      }
    }
  } catch { /* fall through to CIRCL */ }

  // Fallback: CIRCL CVE Search (free, no key, good coverage)
  try {
    const circlRes = await fetch(
      `https://cve.circl.lu/api/cve/${encodeURIComponent(id)}`,
      { signal: timeout(8000) }
    );
    if (circlRes.ok) {
      const d = await circlRes.json();
      if (d && d.id) {
        const cvss3 = d.cvss3 || null;
        const cvss2 = d.cvss || null;
          return {
          source: 'CIRCL CVE Search',
          id: d.id,
          description: d.summary || null,
          published: d.Published?.split('T')[0] || null,
          lastModified: d.Modified?.split('T')[0] || null,
          vulnStatus: null,
          cvssScore: cvss3 ?? cvss2 ?? null,
          cvssVersion: cvss3 ? '3.x' : cvss2 ? '2.0' : null,
          severity: cvss3 >= 9 ? 'CRITICAL' : cvss3 >= 7 ? 'HIGH' : cvss3 >= 4 ? 'MEDIUM' : cvss3 ? 'LOW' : null,
          vectorString: d.cvss3_vector || d.cvss_time || null,
          attackVector: null, attackComplexity: null, privilegesRequired: null,
          userInteraction: null, scope: null,
          confidentialityImpact: null, integrityImpact: null, availabilityImpact: null,
          exploitabilityScore: null, impactScore: null,
          weaknesses: d.cwe ? [d.cwe] : [],
          references: (d.references || []).slice(0, 10).map(url => ({ url, source: null, tags: [] })),
          affectedProducts: (d.vulnerable_product || []).slice(0, 15),
          cisaExploited: false, cisaActionDue: null,
          permalink: `https://cve.circl.lu/cve/${d.id}`,
        };
      }
    }
  } catch { /* both failed */ }

  return { error: `CVE ${id} not found in NVD or CIRCL` };
}

// ─── DNS-over-HTTPS (Cloudflare, free, no key) ─────────────────────────
const DNS_TYPE_MAP = { 'A':1, 'NS':2, 'CNAME':5, 'SOA':6, 'MX':15, 'TXT':16, 'AAAA':28 };
const DNS_TYPE_NAME = Object.fromEntries(Object.entries(DNS_TYPE_MAP).map(([n,v])=>[v,n]));

async function handleDNS(domain) {
  const types = ['A','AAAA','CNAME','MX','TXT','NS'];
  const results = {};
  await Promise.all(types.map(async (type) => {
    try {
      const res = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`,
        { headers: { 'Accept': 'application/dns-json' }, signal: timeout(5000) }
      );
      if (res.ok) {
        const d = await res.json();
        if (d.Answer && d.Answer.length > 0) {
          results[type] = d.Answer.map(a => ({
            name: a.name,
            type: DNS_TYPE_NAME[a.type] || String(a.type),
            TTL: a.TTL,
            data: a.data
          }));
        }
      }
    } catch { /* ignore per-type failures */ }
  }));
  return {
    source: 'DNS Lookup',
    domain,
    records: results,
    queriedTypes: types,
    found: Object.keys(results).length > 0,
  };
}

// ─── Main handler ─────────────────────────────────────────────────────
export async function onRequest({ request, env, waitUntil }) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204 });
  if (request.method !== 'GET') return err('Method not allowed', 405);

  // Rate limit
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (await isRateLimited(env.ATLASOC_CACHE, ip, 30)) return err('Rate limit exceeded', 429);

  const url    = new URL(request.url);
  const route  = url.pathname.replace(/^\/api\//, '');

  if (route === 'health') return json({ status: 'ok' });

  const ioc    = url.searchParams.get('ioc');
  const type   = url.searchParams.get('type');

  if (!ioc || !type) return err('Missing params: ioc, type');
  if (ioc.length > 2048) return err('Indicator too long');
  if (!VALID_TYPES.has(type)) return err(`Invalid type: must be one of ${[...VALID_TYPES].join(', ')}`);
  if (!/^[a-zA-Z0-9._:\/@%+=?&-]+$/.test(ioc)) return err('Invalid indicator');

  const kv = env.ATLASOC_CACHE;

  try {
    const source = route;
    const cfg = sourceConfig(source);
    const iocLower = String(ioc).toLowerCase();

    let wrapped;
    try {
      wrapped = await callWithResilience(kv, source, type, iocLower, async () => {
        switch (route) {
          case 'vt':      return normalizeVT(await handleVirusTotal(ioc, type, env), type);
          case 'abuse':   if (type !== 'ip' && type !== 'ip6') throw new Error('InvalidIoc'); return normalizeAbuseIPDB(await handleAbuseIPDB(ioc, env));
          case 'shodan':  return normalizeShodan(await handleShodan(ioc, env));
          case 'greynoise': if (type !== 'ip' && type !== 'ip6') throw new Error('InvalidIoc'); return normalizeGreyNoise(await handleGreyNoise(ioc, env));
          case 'otx':     return normalizeOTX(await handleOTX(ioc, type, env));
          case 'urlscan': return normalizeURLScan(await handleURLScan(ioc, type, env));
          case 'whois':   return normalizeWHOIS(await handleWHOIS(ioc, type));
          case 'bazaar':  return normalizeMalwareBazaar(await handleMalwareBazaar(ioc, env));
          case 'cve':     return normalizeCVE(await handleCVE(ioc, env));
          case 'dns':     return normalizeDNS(await handleDNS(ioc));
          default:        return { error: 'Not found', code: 404 };
        }
      });
    } catch (resilienceError) {
      wrapped = { error: resilienceError.message, code: resilienceError.code || 'SourceUnavailable', source };
      if (kv) {
        const cacheKey = `intel:${source}:${type}:${iocLower}`;
        const staleHit = await kvGet(kv, cacheKey);
        if (staleHit) {
          wrapped = { ...staleHit, stale: true, _cached: true, _stale: true, _error: resilienceError.message, condition: 'endpoint_error', conditionMessage: resilienceError.message };
        }
      }
    }

    const conditionMeta = normalizeCondition(wrapped);
    const response = {
      indicator: ioc,
      type,
      source,
      stale: wrapped._stale || false,
      cached: wrapped._cached || false,
      status: sourceStatus(wrapped),
      error: wrapped._error || wrapped.error || null,
      condition: conditionMeta.condition,
      conditionMessage: conditionMeta.message,
      data: wrapped,
    };

    if (kv && !response.error) waitUntil(kvPut(kv, `intel:${source}:${type}:${iocLower}`, omitMeta(response), sourceConfig(source).cacheMissTtl || DEFAULT_CACHE_TTL));
    return json(response, 200, { 'X-Cache': wrapped._cached ? 'HIT' : kv ? 'MISS' : 'BYPASS' });
  } catch (e) {
    console.error(e);
    return err('Internal error', 500);
  }
}

function omitMeta(obj) {
  const { _cached, _stale, _error, ...rest } = obj;
  return rest;
}

function sourceStatus(item) {
  if (!item) return 'unknown';
  if (item.condition === 'endpoint_error' || item.error) return 'error';
  if (item._stale) return 'stale';
  if (item.condition === 'not_configured') return 'error';
  if (item.condition === 'no_results') return 'clean';
  if (item.verdict === 'malicious') return 'malicious';
  if (item.verdict === 'suspicious') return 'suspicious';
  if (item.status === 'clean' || item.verdict === 'benign') return 'clean';
  return 'unknown';
}

function normalizeCondition(raw) {
  const explicit = raw && raw.condition;
  if (explicit) return { condition: explicit, message: raw.conditionMessage || raw.error || null };
  const msg = (raw && raw._error) ? raw._error : (raw && raw.error) ? raw.error : null;
  if (/not configured/i.test(String(msg))) return { condition: 'not_configured', message: msg };
  if (msg) return { condition: 'endpoint_error', message: msg };
  if (raw.source === 'VirusTotal') return { condition: (raw.detected || raw.total) ? 'ok' : 'no_results', message: 'No data returned for this indicator' };
  if (raw.source === 'Shodan') return { condition: raw.found ? 'ok' : 'no_results', message: 'No data returned for this indicator' };
  if (raw.source === 'GreyNoise') return { condition: raw.found ? 'ok' : 'no_results', message: 'No data returned for this indicator' };
  if (raw.source === 'AlienVault OTX') return { condition: (raw.pulses || 0) > 0 ? 'ok' : 'no_results', message: 'No data returned for this indicator' };
  if (raw.source === 'URLScan.io') return { condition: raw.found ? 'ok' : 'no_results', message: 'No data returned for this indicator' };
  if (raw.source === 'MalwareBazaar') return { condition: raw.found ? 'ok' : 'no_results', message: 'No data returned for this indicator' };
  if (raw.source === 'DNS Lookup') return { condition: raw.found ? 'ok' : 'no_results', message: 'No data returned for this indicator' };
  return { condition: 'ok', message: null };
}

function normalizeVT(raw, type) {
  if (raw?.error) return { ...raw, _error: raw.error };
  const verdict = raw.status === 'malicious' ? 'malicious' : raw.status === 'suspicious' ? 'suspicious' : 'benign';
  const detected = raw.detected || 0;
  const total = raw.total || 0;
  return {
    source: 'VirusTotal',
    sourceKey: 'vt',
    iocType: type,
    verdict,
    score: total ? Math.round((detected / total) * 100) : null,
    status: raw.status,
    detected,
    total,
    suspicious: raw.suspicious || 0,
    harmless: raw.harmless || 0,
    undetected: raw.undetected || 0,
    lastAnalysis: raw.lastAnalysis,
    reputation: raw.reputation,
    categories: raw.categories || [],
    tags: raw.tags || [],
    fileType: raw.fileType,
    fileSize: raw.fileSize,
    firstSeen: raw.firstSeen,
    geo: { country: raw.country || null, asn: raw.asn || null, org: raw.asOwner || null },
    permalink: raw.permalink,
    engines: raw.engines || [],
    raw,
  };
}

function normalizeAbuseIPDB(raw) {
  if (raw?.error) return { ...raw, _error: raw.error };
  const score = raw.abuseScore ?? null;
  const verdict = score == null ? 'unknown' : score >= 75 ? 'malicious' : score >= 25 ? 'suspicious' : 'benign';
  return {
    source: 'AbuseIPDB',
    sourceKey: 'abuse',
    iocType: 'ip',
    verdict,
    score,
    status: verdict,
    abuseScore: score,
    country: raw.country,
    countryName: raw.countryName,
    isp: raw.isp,
    domain: raw.domain,
    usageType: raw.usageType,
    totalReports: raw.totalReports,
    numDistinctUsers: raw.numDistinctUsers,
    lastReported: raw.lastReported,
    isWhitelisted: raw.isWhitelisted,
    tor: raw.tor,
    ipVersion: raw.ipVersion,
    recentReports: raw.recentReports || [],
    geo: { country: raw.country || null, asn: null, org: raw.isp || null },
    permalink: raw.permalink,
    raw,
  };
}

function normalizeShodan(raw) {
  if (raw?.error) return { ...raw, _error: raw.error };
  const hasVulns = (raw.vulns || []).length > 0;
  const verdict = hasVulns ? 'suspicious' : 'unknown';
  return {
    source: 'Shodan',
    sourceKey: 'shodan',
    iocType: 'ip',
    verdict,
    score: null,
    status: verdict,
    found: raw.found,
    ports: raw.ports || [],
    hostnames: raw.hostnames || [],
    os: raw.os,
    org: raw.org,
    asn: raw.asn,
    country: raw.country,
    city: raw.city,
    vulns: raw.vulns || [],
    tags: raw.tags || [],
    lastSeen: raw.lastSeen,
    services: raw.services || [],
    geo: { country: raw.country || null, asn: raw.asn || null, org: raw.org || null },
    permalink: raw.permalink,
    raw,
  };
}

function normalizeGreyNoise(raw) {
  if (raw?.error) return { ...raw, _error: raw.error };
  const classification = raw.classification || 'unknown';
  const verdict = classification === 'malicious' ? 'malicious' : classification === 'benign' ? 'benign' : 'unknown';
  return {
    source: 'GreyNoise',
    sourceKey: 'greynoise',
    iocType: 'ip',
    verdict,
    score: null,
    status: verdict,
    found: raw.found,
    noise: raw.noise,
    riot: raw.riot,
    classification,
    name: raw.name,
    lastSeen: raw.lastSeen,
    message: raw.message,
    geo: null,
    permalink: raw.permalink,
    raw,
  };
}

function normalizeOTX(raw) {
  if (raw?.error) return { ...raw, _error: raw.error };
  const pulses = raw.pulses || 0;
  const verdict = pulses > 0 ? 'malicious' : 'benign';
  const score = pulses ? Math.min(100, Math.round(pulses * 17)) : 0;
  return {
    source: 'AlienVault OTX',
    sourceKey: 'otx',
    iocType: null,
    verdict,
    score,
    status: verdict,
    pulses,
    threatScore: raw.threatScore,
    malwareFamilies: raw.malwareFamilies || [],
    categories: raw.categories || [],
    adversaries: raw.adversaries || [],
    relatedIndicators: raw.relatedIndicators,
    firstSeen: raw.firstSeen,
    lastSeen: raw.lastSeen,
    tags: [...(raw.categories || []), ...(raw.malwareFamilies || [])],
    geo: null,
    permalink: raw.permalink,
    raw,
  };
}

function normalizeURLScan(raw) {
  if (raw?.error) return { ...raw, _error: raw.error };
  const verdicts = raw.verdicts || {};
  const overall = verdicts.overall || {};
  const verdict = overall?.malicious ? 'malicious' : overall?.suspicious ? 'suspicious' : 'unknown';
  return {
    source: 'URLScan.io',
    sourceKey: 'urlscan',
    iocType: 'url',
    verdict,
    score: null,
    status: verdict,
    found: raw.found,
    verdicts,
    ip: raw.ip,
    country: raw.country,
    server: raw.server,
    title: raw.title,
    screenshot: raw.screenshot,
    technologies: raw.technologies || [],
    tags: [...(raw.technologies || [])],
    geo: { country: raw.country || null, asn: null, org: raw.server || null },
    permalink: raw.reportUrl,
    raw,
  };
}

function normalizeWHOIS(raw) {
  if (raw?.error) return { ...raw, _error: raw.error };
  return {
    source: 'WHOIS / RDAP',
    sourceKey: 'whois',
    iocType: null,
    verdict: 'unknown',
    score: null,
    status: 'unknown',
    ...raw,
    raw,
  };
}

function normalizeMalwareBazaar(raw) {
  if (raw?.error) return { ...raw, _error: raw.error };
  const verdict = raw.found ? 'malicious' : 'benign';
  return {
    source: 'MalwareBazaar',
    sourceKey: 'bazaar',
    iocType: null,
    verdict,
    score: raw.found ? 90 : 0,
    status: verdict,
    ...raw,
    raw,
  };
}

function normalizeCVE(raw) {
  if (raw?.error) return { ...raw, _error: raw.error };
  const score = raw.cvssScore ?? null;
  const severity = (raw.severity || '').toLowerCase();
  const verdict = !score ? 'unknown' : severity === 'critical' || score >= 9 ? 'malicious' : severity === 'high' || score >= 7 ? 'suspicious' : 'benign';
  return {
    source: raw.source,
    sourceKey: 'cve',
    iocType: 'cve',
    verdict,
    score,
    status: verdict,
    ...raw,
    raw,
  };
}

function normalizeDNS(raw) {
  if (raw?.error) return { ...raw, _error: raw.error };
  return {
    source: 'DNS Lookup',
    sourceKey: 'dns',
    iocType: 'domain',
    verdict: 'unknown',
    score: null,
    status: raw.found ? 'clean' : 'unknown',
    ...raw,
    raw,
  };
}