// Pure helpers for the small pills shown next to each source tab.
// Kept separate from ResultsPanel.jsx so the decision logic is unit-testable.

export function freshnessBadge(s) {
  if (s._stale) return 'STALE';
  if (s._cached) return 'CACHED';
  return null;
}

export function statusBadge(s, emptyState) {
  if (emptyState) return 'INFO';
  if (s.error) return 'ERR';
  // A stale/cached response isn't "live" — don't claim freshness the
  // freshness badge is already contradicting.
  if (s._stale || s._cached) return null;
  return 'LIVE';
}
