import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { format, formatDistanceToNow, parseISO, subHours } from 'date-fns';
import { api } from '../services/api';
import { SignIn } from '../types';

// ── Helpers ──────────────────────────────────────────────────────────────────
const OK = (s?: { errorCode: number }) => s?.errorCode === 0;

const RISK_COLOR: Record<string, string> = {
  high:   '#EF4444',
  medium: '#EAB308',
  low:    '#3B82F6',
  none:   '#34C97D',
  hidden: '#EAB308',
};

function riskColor(level?: string) {
  return RISK_COLOR[level ?? 'none'] ?? '#8ba3cc';
}

// ── Per-user analysis ─────────────────────────────────────────────────────────
interface UserPattern {
  upn: string;
  displayName: string;
  total: number;
  failed: number;
  risky: number;
  countries: string[];
  ips: string[];
  apps: string[];
  events: SignIn[];
}

function analyzeUser(events: SignIn[]): UserPattern {
  const countries = [...new Set(events.map(e => e.location?.countryOrRegion).filter(Boolean))] as string[];
  const ips       = [...new Set(events.map(e => e.ipAddress).filter(Boolean))] as string[];
  const apps      = [...new Set(events.map(e => e.appDisplayName).filter(Boolean))] as string[];
  return {
    upn:         events[0]?.userPrincipalName ?? '',
    displayName: events[0]?.userDisplayName ?? '',
    total:       events.length,
    failed:      events.filter(e => !OK(e.status)).length,
    risky:       events.filter(e => e.riskLevelAggregated && e.riskLevelAggregated !== 'none').length,
    countries, ips, apps,
    events,
  };
}

// ── Timeline event row ────────────────────────────────────────────────────────
function TimelineRow({ s, baseline }: { s: SignIn; baseline: UserPattern | null }) {
  const ok = OK(s.status);
  const country = s.location?.countryOrRegion;
  const isNewCountry = baseline && country && !baseline.countries.includes(country);
  const isNewIp      = baseline && s.ipAddress && !baseline.ips.includes(s.ipAddress);
  const hasRisk      = s.riskLevelAggregated && s.riskLevelAggregated !== 'none';
  const anomalies    = [
    isNewCountry && `New country: ${country}`,
    isNewIp      && `New IP: ${s.ipAddress}`,
    hasRisk      && `Risk: ${s.riskLevelAggregated}`,
    !ok          && `Failed (${s.status?.errorCode ?? '?'})`,
  ].filter(Boolean) as string[];

  const highlight = anomalies.length > 0;

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: '100px 1fr auto',
      gap: 12,
      padding: '10px 0',
      borderBottom: '1px solid var(--navy-border)',
      alignItems: 'flex-start',
      background: highlight ? 'rgba(239,68,68,0.03)' : undefined,
    }}>
      {/* Time */}
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)', paddingTop: 2 }}>
        <div>{format(parseISO(s.createdDateTime), 'MM/dd HH:mm')}</div>
        <div style={{ fontSize: 10 }}>{formatDistanceToNow(parseISO(s.createdDateTime), { addSuffix: true })}</div>
      </div>

      {/* Body */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', marginBottom: anomalies.length ? 4 : 0 }}>
          <span style={{
            fontSize: 10, fontWeight: 700, padding: '1px 6px', borderRadius: 6,
            background: ok ? 'rgba(52,201,125,0.12)' : 'rgba(239,68,68,0.12)',
            color: ok ? '#34C97D' : '#EF4444',
          }}>{ok ? 'OK' : 'FAIL'}</span>
          <span style={{ fontSize: 12, fontWeight: 600 }}>{s.appDisplayName || 'Unknown app'}</span>
          <span className="text-muted" style={{ fontSize: 11 }}>
            {[s.location?.city, country].filter(Boolean).join(', ') || '—'}
            {s.ipAddress ? ` · ${s.ipAddress}` : ''}
          </span>
          {s.deviceDetail?.operatingSystem && (
            <span className="role-tag" style={{ fontSize: 10 }}>{s.deviceDetail.operatingSystem}</span>
          )}
        </div>
        {anomalies.length > 0 && (
          <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
            {anomalies.map(a => (
              <span key={a} style={{
                fontSize: 10, padding: '1px 7px', borderRadius: 8, fontWeight: 600,
                background: 'rgba(239,68,68,0.12)', color: '#EF4444',
                border: '1px solid rgba(239,68,68,0.25)',
              }}>{a}</span>
            ))}
          </div>
        )}
      </div>

      {/* Risk badge */}
      <div>
        {hasRisk && (
          <span style={{
            fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 8,
            background: `${riskColor(s.riskLevelAggregated)}20`,
            color: riskColor(s.riskLevelAggregated),
            border: `1px solid ${riskColor(s.riskLevelAggregated)}40`,
            textTransform: 'uppercase',
          }}>{s.riskLevelAggregated}</span>
        )}
      </div>
    </div>
  );
}

// ── User card (left panel) ────────────────────────────────────────────────────
function UserCard({ pattern, selected, onClick }: { pattern: UserPattern; selected: boolean; onClick: () => void }) {
  const failRate = pattern.total ? Math.round((pattern.failed / pattern.total) * 100) : 0;
  const threat   = pattern.risky > 0 || pattern.failed > 2;
  return (
    <div onClick={onClick} style={{
      padding: '12px 14px',
      borderRadius: 10,
      border: selected
        ? '1px solid rgba(232,120,74,0.5)'
        : `1px solid ${threat ? 'rgba(239,68,68,0.25)' : 'var(--navy-border)'}`,
      background: selected ? 'rgba(232,120,74,0.08)' : 'var(--navy-card)',
      cursor: 'pointer',
      marginBottom: 6,
      transition: 'background 0.15s',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 4 }}>
        <div>
          <div style={{ fontWeight: 700, fontSize: 13 }}>{pattern.displayName}</div>
          <div className="text-muted mono" style={{ fontSize: 10 }}>{pattern.upn}</div>
        </div>
        <div style={{ textAlign: 'right', flexShrink: 0 }}>
          <div style={{ fontWeight: 700, fontSize: 13, color: threat ? '#EF4444' : 'var(--text-primary)' }}>{pattern.total}</div>
          <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>events</div>
        </div>
      </div>
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        {pattern.failed > 0 && (
          <span style={{ fontSize: 10, padding: '1px 6px', borderRadius: 6, background: 'rgba(239,68,68,0.12)', color: '#EF4444', fontWeight: 600 }}>
            {pattern.failed} failed ({failRate}%)
          </span>
        )}
        {pattern.risky > 0 && (
          <span style={{ fontSize: 10, padding: '1px 6px', borderRadius: 6, background: 'rgba(234,179,8,0.12)', color: '#EAB308', fontWeight: 600 }}>
            {pattern.risky} risky
          </span>
        )}
        {pattern.countries.length > 1 && (
          <span className="role-tag" style={{ fontSize: 10 }}>{pattern.countries.length} countries</span>
        )}
      </div>
    </div>
  );
}

// ── Main ──────────────────────────────────────────────────────────────────────
export default function SignInsPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const [allSignIns, setAllSignIns] = useState<SignIn[]>([]);
  const [loading, setLoading]       = useState(true);
  const [error, setError]           = useState<{ message: string; hint?: string } | null>(null);
  const [hours, setHours]           = useState(48);
  const [search, setSearch]         = useState('');
  const [onlyFailed, setOnlyFailed] = useState(false);
  const [onlyRisky, setOnlyRisky]   = useState(false);
  const [selectedUpn, setSelectedUpn] = useState<string | null>(null);
  const timelineRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    api.getSignIns(hours)
      .then(data => {
        const list = data as SignIn[];
        setAllSignIns(list);
        // Auto-select user from query param or most-events user
        const urlUpn = searchParams.get('upn');
        if (urlUpn) {
          setSelectedUpn(urlUpn);
        } else if (!selectedUpn) {
          const byUser = groupByUser(list);
          const topUser = byUser.sort((a, b) => b.total - a.total)[0];
          if (topUser) setSelectedUpn(topUser.upn);
        }
      })
      .catch(err => setError({ message: err.message || 'Failed to load sign-in logs', hint: err.hint }))
      .finally(() => setLoading(false));
  }, [hours]);

  function groupByUser(events: SignIn[]): UserPattern[] {
    const map = new Map<string, SignIn[]>();
    for (const e of events) {
      const upn = e.userPrincipalName || 'unknown';
      if (!map.has(upn)) map.set(upn, []);
      map.get(upn)!.push(e);
    }
    return Array.from(map.values()).map(analyzeUser);
  }

  const allPatterns = useMemo(() => {
    const base = groupByUser(allSignIns).sort((a, b) => {
      const aScore = a.risky * 3 + a.failed * 2 + (a.countries.length > 1 ? 1 : 0);
      const bScore = b.risky * 3 + b.failed * 2 + (b.countries.length > 1 ? 1 : 0);
      return bScore - aScore;
    });
    if (!search) return base;
    const q = search.toLowerCase();
    return base.filter(p =>
      p.upn.toLowerCase().includes(q) ||
      p.displayName.toLowerCase().includes(q) ||
      p.countries.some(c => c.toLowerCase().includes(q)) ||
      p.apps.some(a => a.toLowerCase().includes(q))
    );
  }, [allSignIns, search]);

  const selectedPattern = allPatterns.find(p => p.upn === selectedUpn) ?? allPatterns[0] ?? null;

  // Build baseline: events from first half of window vs second half
  const baseline = useMemo((): UserPattern | null => {
    if (!selectedPattern) return null;
    const midpoint = subHours(new Date(), hours / 2);
    const older = selectedPattern.events.filter(e => parseISO(e.createdDateTime) < midpoint);
    if (!older.length) return null;
    return analyzeUser(older);
  }, [selectedPattern, hours]);

  const timelineEvents = useMemo(() => {
    if (!selectedPattern) return [];
    return selectedPattern.events
      .filter(e => {
        if (onlyFailed && OK(e.status)) return false;
        if (onlyRisky && (!e.riskLevelAggregated || e.riskLevelAggregated === 'none')) return false;
        return true;
      })
      .sort((a, b) => new Date(b.createdDateTime).getTime() - new Date(a.createdDateTime).getTime());
  }, [selectedPattern, onlyFailed, onlyRisky]);

  // Stats across all sign-ins
  const globalStats = useMemo(() => ({
    total:   allSignIns.length,
    failed:  allSignIns.filter(e => !OK(e.status)).length,
    risky:   allSignIns.filter(e => e.riskLevelAggregated && e.riskLevelAggregated !== 'none').length,
    users:   allPatterns.length,
  }), [allSignIns, allPatterns]);

  return (
    <div>
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="page-header">
        <div>
          <div className="page-title">Sign-in Investigation</div>
          <div className="page-subtitle">
            Per-user timeline · behavior baseline · anomaly detection
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <select className="filter-select" value={hours} onChange={e => setHours(Number(e.target.value))}>
            <option value={6}>Last 6h</option>
            <option value={24}>Last 24h</option>
            <option value={48}>Last 48h</option>
            <option value={72}>Last 72h</option>
            <option value={168}>Last 7 days</option>
          </select>
        </div>
      </div>

      {/* ── Global stat row ────────────────────────────────────────────── */}
      <div className="stats-grid" style={{ marginBottom: 20 }}>
        <div className="stat-card neutral"><div className="stat-value">{globalStats.total}</div><div className="stat-label">Total events</div></div>
        <div className="stat-card medium"><div className="stat-value">{globalStats.users}</div><div className="stat-label">Active users</div></div>
        <div className={`stat-card ${globalStats.failed > 0 ? 'amber' : 'clean'}`}><div className="stat-value">{globalStats.failed}</div><div className="stat-label">Failed sign-ins</div></div>
        <div className={`stat-card ${globalStats.risky > 0 ? 'critical' : 'clean'}`}><div className="stat-value">{globalStats.risky}</div><div className="stat-label">Risky sign-ins</div></div>
      </div>

      {/* ── License error ──────────────────────────────────────────────── */}
      {error && (
        <div className="card" style={{ borderLeft: '3px solid #EAB308', marginBottom: 16 }}>
          <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
            <span style={{ fontSize: 22 }}>⚠️</span>
            <div>
              <div style={{ fontWeight: 700, marginBottom: 4, color: '#EAB308' }}>{error.message}</div>
              {error.hint && <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>{error.hint}</div>}
              <div style={{ marginTop: 10, fontSize: 12, color: 'var(--text-muted)' }}>
                Requires Entra ID P1+, <code>AuditLog.Read.All</code> with admin consent.
              </div>
            </div>
          </div>
        </div>
      )}

      {loading ? (
        <div className="loading-state"><div className="loading-spinner" /><div className="loading-text">Loading sign-in data…</div></div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: 16, alignItems: 'flex-start' }}>

          {/* ── Left: user list ──────────────────────────────────────── */}
          <div>
            <div style={{ marginBottom: 8 }}>
              <input
                className="filter-input"
                placeholder="Filter users…"
                value={search}
                onChange={e => setSearch(e.target.value)}
                style={{ width: '100%', boxSizing: 'border-box' }}
              />
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8, paddingLeft: 2 }}>
              {allPatterns.length} users · sorted by risk signal
            </div>
            <div style={{ maxHeight: 'calc(100vh - 320px)', overflowY: 'auto' }}>
              {allPatterns.length === 0 && (
                <div className="text-muted" style={{ padding: '24px 0', textAlign: 'center', fontSize: 12 }}>
                  No sign-in data found for this window.
                </div>
              )}
              {allPatterns.map(p => (
                <UserCard
                  key={p.upn}
                  pattern={p}
                  selected={p.upn === (selectedPattern?.upn ?? '')}
                  onClick={() => setSelectedUpn(p.upn)}
                />
              ))}
            </div>
          </div>

          {/* ── Right: investigation panel ───────────────────────────── */}
          {selectedPattern ? (
            <div className="card" style={{ padding: 20 }}>
              {/* User header */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16, flexWrap: 'wrap', gap: 10 }}>
                <div>
                  <div style={{ fontWeight: 700, fontSize: 18, marginBottom: 2 }}>{selectedPattern.displayName}</div>
                  <div className="text-muted mono" style={{ fontSize: 12 }}>{selectedPattern.upn}</div>
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button className="btn btn-ghost btn-sm" onClick={() => navigate(`/users?userId=`) }>
                    View in Users →
                  </button>
                  <button className="btn btn-ghost btn-sm" onClick={() => navigate(`/alerts?q=${encodeURIComponent(selectedPattern.upn)}`)}>
                    View Alerts →
                  </button>
                </div>
              </div>

              {/* Pattern summary grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, marginBottom: 16 }}>
                {[
                  { label: 'Total events',   value: selectedPattern.total,    color: 'var(--text-primary)' },
                  { label: 'Failed',          value: selectedPattern.failed,   color: selectedPattern.failed > 0 ? '#EF4444' : '#34C97D' },
                  { label: 'Risky',           value: selectedPattern.risky,    color: selectedPattern.risky > 0 ? '#EAB308' : '#34C97D' },
                  { label: 'Countries seen',  value: selectedPattern.countries.length, color: selectedPattern.countries.length > 2 ? '#F97316' : 'var(--text-primary)' },
                ].map(s => (
                  <div key={s.label} style={{ background: 'var(--navy-bg)', borderRadius: 8, padding: '10px 12px', textAlign: 'center' }}>
                    <div style={{ fontSize: 22, fontWeight: 700, color: s.color }}>{s.value}</div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>{s.label}</div>
                  </div>
                ))}
              </div>

              {/* Baseline comparison */}
              {baseline && (
                <div style={{
                  background: 'var(--navy-bg)', borderRadius: 10, padding: '12px 16px', marginBottom: 16,
                  border: '1px solid var(--navy-border)',
                }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>
                    Baseline comparison (first half of window vs recent)
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10, fontSize: 12 }}>
                    {[
                      {
                        label: 'Countries',
                        before: baseline.countries,
                        after:  selectedPattern.countries,
                        newItems: selectedPattern.countries.filter(c => !baseline.countries.includes(c)),
                      },
                      {
                        label: 'IPs',
                        before: baseline.ips,
                        after:  selectedPattern.ips,
                        newItems: selectedPattern.ips.filter(ip => !baseline.ips.includes(ip)),
                      },
                      {
                        label: 'Apps',
                        before: baseline.apps,
                        after:  selectedPattern.apps,
                        newItems: selectedPattern.apps.filter(a => !baseline.apps.includes(a)),
                      },
                    ].map(col => (
                      <div key={col.label}>
                        <div style={{ fontWeight: 600, marginBottom: 4 }}>{col.label}</div>
                        <div style={{ color: 'var(--text-muted)', fontSize: 11 }}>
                          {col.before.length} baseline → {col.after.length} total
                        </div>
                        {col.newItems.length > 0 && (
                          <div style={{ marginTop: 4 }}>
                            {col.newItems.slice(0, 3).map(item => (
                              <span key={item} style={{
                                display: 'inline-block', margin: '2px 2px 0 0',
                                fontSize: 10, padding: '1px 6px', borderRadius: 6,
                                background: 'rgba(239,68,68,0.12)', color: '#EF4444', fontWeight: 600,
                              }}>+ {item}</span>
                            ))}
                            {col.newItems.length > 3 && (
                              <span style={{ fontSize: 10, color: 'var(--text-muted)' }}> +{col.newItems.length - 3} more</span>
                            )}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Countries + Apps chips */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
                {[
                  { label: 'Countries', items: selectedPattern.countries },
                  { label: 'Applications', items: selectedPattern.apps.slice(0, 6) },
                ].map(col => (
                  <div key={col.label}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{col.label}</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {col.items.map(item => (
                        <span key={item} className="role-tag" style={{ fontSize: 11 }}>{item}</span>
                      ))}
                      {col.items.length === 0 && <span className="text-muted" style={{ fontSize: 11 }}>—</span>}
                    </div>
                  </div>
                ))}
              </div>

              {/* Timeline filters */}
              <div style={{ display: 'flex', gap: 12, marginBottom: 12, alignItems: 'center' }}>
                <div style={{ fontWeight: 600, fontSize: 13 }}>Timeline</div>
                <label style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer' }}>
                  <input type="checkbox" checked={onlyFailed} onChange={e => setOnlyFailed(e.target.checked)} style={{ accentColor: '#EF4444' }} />
                  Failed only
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer' }}>
                  <input type="checkbox" checked={onlyRisky} onChange={e => setOnlyRisky(e.target.checked)} style={{ accentColor: '#EAB308' }} />
                  Risky only
                </label>
                <span className="text-muted" style={{ fontSize: 11, marginLeft: 'auto' }}>{timelineEvents.length} events</span>
              </div>

              {/* Timeline */}
              <div ref={timelineRef} style={{ maxHeight: 420, overflowY: 'auto' }}>
                {timelineEvents.length === 0 ? (
                  <div className="text-muted" style={{ padding: '24px 0', textAlign: 'center', fontSize: 12 }}>No events match the current filters.</div>
                ) : (
                  timelineEvents.map((e, i) => (
                    <TimelineRow key={e.id ?? i} s={e} baseline={baseline} />
                  ))
                )}
              </div>
            </div>
          ) : (
            <div className="card">
              <div className="empty-state">
                <div className="empty-icon">🔍</div>
                <div className="empty-text">Select a user to investigate</div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
