import { detectType } from './detect.js';

// ─── API config ──────────────────────────────────────────────────────────────
// Calls go to /api/* on the same domain — no secrets, no keys in the browser.
// Keys live only in Cloudflare Pages environment variables (server-side).
export const API_BASE = '/api';

export const ENDPOINT_MAP = {
  vt:      ['ip','ip6','domain','url','hash-md5','hash-sha1','hash-sha256','email','filename'],
  abuse:   ['ip','ip6'],
  shodan:  ['ip','ip6'],
  greynoise: ['ip','ip6'],
  otx:     ['ip','ip6','domain','url','hash-md5','hash-sha1','hash-sha256','email'],
  urlscan: ['domain','url'],
  whois:   ['ip','ip6','domain','email'],
  bazaar:  ['hash-md5','hash-sha1','hash-sha256','filename'],
  cve:     ['cve'],
  dns:     ['domain'],
};

export const SOURCE_META = {
  vt:      { name: 'VirusTotal',      url: 'virustotal.com' },
  abuse:   { name: 'AbuseIPDB',       url: 'abuseipdb.com' },
  shodan:  { name: 'Shodan',          url: 'shodan.io' },
  greynoise: { name: 'GreyNoise',     url: 'greynoise.io' },
  otx:     { name: 'AlienVault OTX',  url: 'otx.alienvault.com' },
  urlscan: { name: 'URLScan.io',      url: 'urlscan.io' },
  whois:   { name: 'WHOIS / RDAP',    url: 'rdap.org' },
  bazaar:  { name: 'MalwareBazaar',   url: 'bazaar.abuse.ch' },
  cve:     { name: 'NVD / NIST',      url: 'nvd.nist.gov' },
  dns:     { name: 'DNS Lookup',      url: 'cloudflare-dns.com' },
};
export const SOURCE_EMOJI = {
  'VirusTotal': '📡',
  'AbuseIPDB': '🔬',
  'Shodan': '👽',
  'GreyNoise': '🌫️',
  'AlienVault OTX': '🛰️',
  'URLScan.io': '🔍',
  'WHOIS / RDAP': '📋',
  'MalwareBazaar': '🦠',
  'NVD / NIST': '🛡️',
  'DNS Lookup': '🌐',
};

async function fetchSource(endpoint, ioc, type) {
  try {
    const res = await fetch(
      `${API_BASE}/${endpoint}?ioc=${encodeURIComponent(ioc)}&type=${encodeURIComponent(type)}`
    );
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const json = await res.json();
    if (!json) return null;
    const payload = json.data || json;
    return {
      ...payload,
      source: SOURCE_META[endpoint]?.name || payload.source,
      _status: json.status,
      _stale: json.stale,
      _cached: json.cached,
      _error: json.error,
      error: json.error,
      condition: json.condition,
      conditionMessage: json.conditionMessage,
    };
  } catch {
    return null;
  }
}

export async function getLiveResults(val, type, onResult) {
  const t = type || detectType(val) || 'unknown';
  const applicableEndpoints = Object.entries(ENDPOINT_MAP)
    .filter(([, types]) => types.includes(t))
    .map(([ep]) => ep);

  const results = [];
  await Promise.all(
    applicableEndpoints.map(async (ep, i) => {
      const result = await fetchSource(ep, val, t) || {
        source: SOURCE_META[ep]?.name || ep,
        condition: 'endpoint_error',
        conditionMessage: 'Request failed',
        error: 'Request failed',
      };
      results[i] = result;
      onResult?.(results.filter(Boolean));
      return result;
    })
  );

  const live = results.filter(Boolean);
  return live.length ? live : [{ condition: 'endpoint_error', message: 'No live sources responded', source: SOURCE_META[applicableEndpoints[0]]?.name || 'Lookup' }];
}
