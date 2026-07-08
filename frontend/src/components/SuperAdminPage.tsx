import React, { useEffect, useState, useCallback } from 'react';

interface TenantRow {
  tenantId: string;
  tenantName: string;
  primaryEmail: string;
  connectedAt: string | null;
  lastSeenAt: string | null;
  lastScanAt: string | null;
  lastAlertAt: string | null;
  graphPermissions: boolean | null;
  signInLogsOk: boolean | null;
  webhookActive: boolean;
  privilegedUsers: number | null;
  telegramOk: boolean | null;
  telegramConfigured: boolean;
  plan: string;
  trialEndsAt: string | null;
  adminEmails: string[];
  alertCount: number;
}

function fmt(iso: string | null) {
  if (!iso) return '—';
  const d = new Date(iso);
  const now = Date.now();
  const diff = now - d.getTime();
  if (diff < 60000)    return 'just now';
  if (diff < 3600000)  return Math.floor(diff / 60000) + 'm ago';
  if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
  return d.toLocaleDateString('en-GB') + ' ' + d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
}

function Dot({ ok, label }: { ok: boolean | null; label?: string }) {
  const color = ok === true ? '#22c55e' : ok === false ? '#ef4444' : '#6b7280';
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 12 }}>
      <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, display: 'inline-block', flexShrink: 0 }} />
      {label}
    </span>
  );
}

function PlanBadge({ plan }: { plan: string }) {
  const colors: Record<string, string> = {
    active: '#22c55e', trial: '#f59e0b', expired: '#ef4444', cancelled: '#6b7280'
  };
  return (
    <span style={{ background: colors[plan] || '#6b7280', color: '#fff', borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 700, textTransform: 'uppercase' }}>
      {plan}
    </span>
  );
}

// ── Supervisor Panel ───────────────────────────────────────────────────────────

interface SupervisorRun {
  ran_at: string;
  issues_found: number;
  auto_fixed: number;
  claude_resolved: number;
  escalated: boolean;
}

interface SupervisorData {
  ok?: boolean;
  error?: string;
  running?: boolean;
  lastCheck?: number;
  recentRuns?: SupervisorRun[];
  summary?: {
    stuckMissions: number;
    openCriticals: number;
    lastEscalated: boolean;
    totalRuns: number;
  };
}

function SupervisorPanel() {
  const [data, setData]       = useState<SupervisorData | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    fetch('/api/superadmin/supervisor', { credentials: 'include' })
      .then(r => r.json())
      .then(d => { setData(d); setLoading(false); })
      .catch(() => { setData({ ok: false, error: 'Failed to reach supervisor' }); setLoading(false); });
  }, []);

  useEffect(() => { load(); }, [load]);

  const pill = () => {
    if (!data || loading)          return { label: '…',        bg: '#374151', color: '#9ca3af' };
    if (data.error || data.ok === false) return { label: '⚠ Offline', bg: '#450a0a', color: '#fca5a5' };
    if (data.summary?.lastEscalated)     return { label: '🔴 Escalated', bg: '#450a0a', color: '#fca5a5' };
    if ((data.summary?.openCriticals ?? 0) > 0) return { label: '🟡 Issues', bg: '#422006', color: '#fcd34d' };
    return { label: '🟢 All Clear', bg: '#052e16', color: '#86efac' };
  };

  const p = pill();
  const runs = data?.recentRuns ?? [];
  const s    = data?.summary;

  return (
    <div className="card" style={{ marginBottom: 20, padding: '16px 20px' }}>
      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: 18 }}>🤖</span>
          <span style={{ fontWeight: 700, fontSize: 14 }}>Supervisor Agent</span>
          <span style={{ background: p.bg, color: p.color, borderRadius: 20, padding: '2px 12px', fontSize: 12, fontWeight: 700 }}>
            {p.label}
          </span>
          {data?.running && (
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>● running now</span>
          )}
        </div>
        <button className="btn btn-ghost btn-sm" onClick={load}>↻</button>
      </div>

      {loading ? (
        <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>Loading…</div>
      ) : data?.error ? (
        <div style={{ color: '#fca5a5', fontSize: 12 }}>{data.error}</div>
      ) : (
        <>
          {/* Summary stats */}
          <div style={{ display: 'flex', gap: 24, marginBottom: 14, flexWrap: 'wrap' }}>
            {[
              { label: 'Total runs',     value: s?.totalRuns      ?? '—' },
              { label: 'Open criticals', value: s?.openCriticals  ?? 0,  alert: (s?.openCriticals ?? 0) > 0 },
              { label: 'Stuck missions', value: s?.stuckMissions  ?? 0,  alert: (s?.stuckMissions ?? 0) > 0 },
              { label: 'Last check',     value: data?.lastCheck ? fmt(new Date(data.lastCheck).toISOString()) : '—' },
            ].map(({ label, value, alert }) => (
              <div key={label}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 2 }}>{label}</div>
                <div style={{ fontWeight: 700, fontSize: 15, color: alert ? '#fcd34d' : 'var(--text-primary)' }}>{String(value)}</div>
              </div>
            ))}
          </div>

          {/* Recent runs table */}
          {runs.length > 0 && (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                <thead>
                  <tr style={{ color: 'var(--text-muted)', fontSize: 11, textTransform: 'uppercase', letterSpacing: '.05em' }}>
                    {['Time', 'Issues', 'Auto-fixed', 'Claude', 'Escalated'].map(h => (
                      <th key={h} style={{ textAlign: 'left', padding: '4px 10px', fontWeight: 600 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {runs.slice(0, 5).map((r, i) => (
                    <tr key={i} style={{ borderTop: '1px solid var(--navy-border)' }}>
                      <td style={{ padding: '6px 10px', color: 'var(--text-muted)' }}>{fmt(r.ran_at)}</td>
                      <td style={{ padding: '6px 10px', color: r.issues_found > 0 ? '#fcd34d' : 'var(--text-secondary)' }}>{r.issues_found}</td>
                      <td style={{ padding: '6px 10px' }}>{r.auto_fixed}</td>
                      <td style={{ padding: '6px 10px' }}>{r.claude_resolved}</td>
                      <td style={{ padding: '6px 10px' }}>
                        {r.escalated
                          ? <span style={{ color: '#fca5a5', fontWeight: 700 }}>🔴 Yes</span>
                          : <span style={{ color: '#86efac' }}>—</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────────

export default function SuperAdminPage() {
  const [tenants, setTenants] = useState<TenantRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState('');
  const [asOf, setAsOf]       = useState('');
  const [search, setSearch]   = useState('');

  const load = () => {
    setLoading(true);
    setError('');
    fetch('/api/superadmin/tenants', { credentials: 'include' })
      .then(r => {
        if (r.status === 403) throw new Error('Access denied — this page is restricted.');
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(d => { setTenants(d.tenants || []); setAsOf(d.asOf || ''); setLoading(false); })
      .catch(err => { setError(err.message); setLoading(false); });
  };

  useEffect(() => { load(); }, []);

  const filtered = tenants.filter(t =>
    !search ||
    t.tenantName.toLowerCase().includes(search.toLowerCase()) ||
    t.tenantId.toLowerCase().includes(search.toLowerCase()) ||
    t.primaryEmail.toLowerCase().includes(search.toLowerCase())
  );

  const stats = {
    total:   tenants.length,
    active:  tenants.filter(t => t.plan === 'active').length,
    trial:   tenants.filter(t => t.plan === 'trial').length,
    expired: tenants.filter(t => t.plan === 'expired' || t.plan === 'cancelled').length,
    alerts:  tenants.reduce((s, t) => s + t.alertCount, 0),
    users:   tenants.reduce((s, t) => s + (t.privilegedUsers || 0), 0)
  };

  return (
    <div>
      {/* Header */}
      <div className="page-header">
        <div>
          <div className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span>🛡️</span> Super Admin — All Tenants
          </div>
          <div className="page-subtitle">
            Restricted view · {tenants.length} tenants connected
            {asOf && <span style={{ marginLeft: 12, color: 'var(--text-muted)', fontSize: 11 }}>as of {fmt(asOf)}</span>}
          </div>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={load}>↻ Refresh</button>
      </div>

      {/* Supervisor Panel */}
      <SupervisorPanel />

      {/* Stats */}
      <div className="stats-grid" style={{ marginBottom: 20 }}>
        <div className="stat-card neutral"><div className="stat-value">{stats.total}</div><div className="stat-label">Total Tenants</div></div>
        <div className="stat-card ok"><div className="stat-value">{stats.active}</div><div className="stat-label">Active</div></div>
        <div className="stat-card amber"><div className="stat-value">{stats.trial}</div><div className="stat-label">Trial</div></div>
        <div className="stat-card critical"><div className="stat-value">{stats.expired}</div><div className="stat-label">Expired</div></div>
        <div className="stat-card medium"><div className="stat-value">{stats.alerts}</div><div className="stat-label">Total Alerts</div></div>
        <div className="stat-card neutral"><div className="stat-value">{stats.users}</div><div className="stat-label">Monitored Users</div></div>
      </div>

      {/* Search */}
      <div className="filter-bar" style={{ marginBottom: 16 }}>
        <input
          className="filter-input"
          placeholder="Search by tenant name, ID or email…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{ maxWidth: 380 }}
        />
        <span style={{ fontSize: 12, color: 'var(--text-muted)', marginLeft: 8 }}>
          {filtered.length} / {tenants.length} shown
        </span>
      </div>

      {/* Table */}
      <div className="card" style={{ overflowX: 'auto' }}>
        {loading ? (
          <div className="loading-state"><div className="loading-spinner" /><div className="loading-text">Loading tenants…</div></div>
        ) : error ? (
          <div className="empty-state">
            <div className="empty-icon">🔒</div>
            <div className="empty-text">{error}</div>
          </div>
        ) : !filtered.length ? (
          <div className="empty-state"><div className="empty-icon">🏢</div><div className="empty-text">No tenants found</div></div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--navy-border)', color: 'var(--text-muted)', fontSize: 11, textTransform: 'uppercase', letterSpacing: '.06em' }}>
                <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Tenant</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Connected by</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Plan</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Alerts</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Users</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Health</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Last seen</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Last scan</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Connected at</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((t, i) => (
                <tr
                  key={t.tenantId}
                  style={{
                    borderBottom: '1px solid var(--navy-border)',
                    background: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.015)',
                    transition: 'background .15s'
                  }}
                  onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,0.04)')}
                  onMouseLeave={e => (e.currentTarget.style.background = i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.015)')}
                >
                  {/* Tenant name + ID */}
                  <td style={{ padding: '10px 12px' }}>
                    <div style={{ fontWeight: 600 }}>{t.tenantName}</div>
                    <div className="mono" style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>{t.tenantId}</div>
                    {t.adminEmails.length > 0 && (
                      <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
                        Admin: {t.adminEmails.slice(0, 2).join(', ')}{t.adminEmails.length > 2 ? ` +${t.adminEmails.length - 2}` : ''}
                      </div>
                    )}
                  </td>

                  {/* Who connected */}
                  <td style={{ padding: '10px 12px', color: 'var(--text-secondary)' }}>
                    {t.primaryEmail || <span style={{ color: 'var(--text-muted)' }}>—</span>}
                  </td>

                  {/* Plan */}
                  <td style={{ padding: '10px 12px' }}>
                    <PlanBadge plan={t.plan} />
                    {t.plan === 'trial' && t.trialEndsAt && (
                      <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>
                        ends {new Date(t.trialEndsAt).toLocaleDateString('en-GB')}
                      </div>
                    )}
                  </td>

                  {/* Alert count */}
                  <td style={{ padding: '10px 12px' }}>
                    <span style={{ fontWeight: t.alertCount > 0 ? 700 : 400, color: t.alertCount > 0 ? 'var(--critical)' : 'var(--text-muted)' }}>
                      {t.alertCount}
                    </span>
                    {t.lastAlertAt && (
                      <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>last: {fmt(t.lastAlertAt)}</div>
                    )}
                  </td>

                  {/* Privileged users */}
                  <td style={{ padding: '10px 12px', color: 'var(--text-secondary)' }}>
                    {t.privilegedUsers ?? '—'}
                  </td>

                  {/* Health indicators */}
                  <td style={{ padding: '10px 12px' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                      <Dot ok={t.graphPermissions}  label="Graph" />
                      <Dot ok={t.signInLogsOk}      label="Sign-ins" />
                      <Dot ok={t.telegramConfigured ? t.telegramOk : null} label={t.telegramConfigured ? 'Telegram' : undefined} />
                    </div>
                  </td>

                  {/* Last seen */}
                  <td style={{ padding: '10px 12px', color: 'var(--text-muted)', fontSize: 12 }}>
                    {fmt(t.lastSeenAt)}
                  </td>

                  {/* Last scan */}
                  <td style={{ padding: '10px 12px', color: 'var(--text-muted)', fontSize: 12 }}>
                    {fmt(t.lastScanAt)}
                  </td>

                  {/* Connected at */}
                  <td style={{ padding: '10px 12px', color: 'var(--text-muted)', fontSize: 12 }}>
                    {t.connectedAt ? new Date(t.connectedAt).toLocaleDateString('en-GB') : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
