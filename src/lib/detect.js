// ─── IOC type detection ────────────────────────────────────────────────────
export function detectType(val) {
  val = val.trim();
  if (!val) return null;
  if (/^CVE-\d{4}-\d+$/i.test(val)) return 'cve';
  if (/^[a-f0-9]{32}$/i.test(val)) return 'hash-md5';
  if (/^[a-f0-9]{40}$/i.test(val)) return 'hash-sha1';
  if (/^[a-f0-9]{64}$/i.test(val)) return 'hash-sha256';
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val)) return 'email';
  if (/^https?:\/\//i.test(val)) return 'url';
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(val)) return 'ip';
  if (/^[0-9a-f:]+$/i.test(val) && val.includes(':')) return 'ip6';
  if (/\.(exe|dll|bat|ps1|sh|py|js|vbs|jar|zip|rar|pdf|doc|xls)$/i.test(val)) return 'filename';
  if (/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/i.test(val)) return 'domain';
  return 'unknown';
}
