import React, { useEffect, useState } from 'react';

// MSP Dashboard — shows ALL tenants at a glance
// Each tenant card shows: risk level, open alerts, last activity

interface TenantSummary {
  tenantId: string;
  tenantName: string;
  userEmail: string;
  connectedAt: string;
  alertStats: { open: number; critical: number; high: number; total: number };
  riskScore: number;
  lastAlertAt: string | null;
  privilegedUsers: number;
  trialStatus: string;
  daysLeft: number | null;
}

export default function MspDashboard() {
  const [tenants, setTenants] = useState<TenantSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [sortBy, setSortBy]   = useState<'risk' | 'alerts' | 'name'>('risk');

  useEffect(() => {
    fetch('/api/msp/tenants', { credentials: 'include' })
      .then(r => r.json())
      .then(d => setTenants(Array.isArray(d) ? d : []))
      .catch(() => setTenants([]))
      .finally(() => setLoading(false));
  }, []);

  const sorted = [...tenants].sort((a, b) => {
    if (sortBy === 'risk')   return b.riskScore - a.riskScore;
    if (sortBy === 'alerts') return b.alertStats.open - a.alertStats.open;
    return a.tenantName.localeCompare(b.tenantName);
  });

  const totalCritical = tenants.reduce((s, t) => s + t.alertStats.critical, 0);
  const totalOpen     = tenants.reduce((s, t) => s + t.alertStats.open, 0);
  const needsAction   = tenants.filter(t => t.alertStats.critical > 0 || t.alertStats.high > 0);

  const riskColor = (score: number) =>
    score >= 75 ? '#ff3b3b' : score >= 50 ? '#ff6b35' : score >= 25 ? '#f5a623' : '#2ecc71';

  if (loading) return <div className="loading-state"><div className="loading-spinner" /><div className="loading-text">Loading tenants...</div></div>;

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">MSP Dashboard</div>
          <div className="page-subtitle">{tenants.length} tenants · All security status at a glance</div>
        </div>
        <select className="filter-select" value={sortBy} onChange={e => setSortBy(e.target.value as any)}>
          <option value="risk">Sort: Highest Risk</option>
          <option value="alerts">Sort: Most Alerts</option>
          <option value="name">Sort: Name</option>
        </select>
      </div>

      {/* Summary bar */}
      <div className="stats-grid" style={{ marginBottom: 24 }}>
        <div className="stat-card neutral"><div className="stat-value">{tenants.length}</div><div className="stat-label">Tenants</div></div>
        <div className="stat-card critical"><div className="stat-value">{totalCritical}</div><div className="stat-label">Critical Alerts</div></div>
        <div className="stat-card high"><div className="stat-value">{totalOpen}</div><div className="stat-label">Open Alerts</div></div>
        <div className="stat-card amber"><div className="stat-value">{needsAction.length}</div><div className="stat-label">Need Action</div></div>
        <div className="stat-card clean"><div className="stat-value">{tenants.length - needsAction.length}</div><div className="stat-label">All Clear</div></div>
      </div>

      {/* Tenant cards */}
      {sorted.length === 0 ? (
        <div className="card">
          <div className="empty-state">
            <div className="empty-icon">🏢</div>
            <div className="empty-text">No tenants connected yet</div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 6 }}>
              Share the login URL with your clients to connect their tenants
            </div>
          </div>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 16 }}>
          {sorted.map(t => {
            const color = riskColor(t.riskScore);
            const needsAction = t.alertStats.critical > 0 || t.alertStats.high > 0;
            return (
              <div key={t.tenantId} className="card" style={{
                borderTop: `3px solid ${color}`,
                cursor: 'pointer',
                transition: 'transform 0.15s, border-color 0.15s',
                position: 'relative',
                overflow: 'hidden'
              }}
                onMouseEnter={e => (e.currentTarget.style.transform = 'translateY(-2px)')}
                onMouseLeave={e => (e.currentTarget.style.transform = '')}
              >
                {needsAction && (
                  <div style={{ position: 'absolute', top: 12, right: 12, width: 8, height: 8, borderRadius: '50%', background: '#ff3b3b', boxShadow: '0 0 8px #ff3b3b', animation: 'livePulse 2s infinite' }} />
                )}

                {/* Tenant name + email */}
                <div style={{ marginBottom: 12 }}>
                  <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 2 }}>
                    {t.tenantName === t.tenantId ? t.userEmail?.split('@')[1] || t.tenantId : t.tenantName}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{t.userEmail}</div>
                </div>

                {/* Risk score */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
                  <div style={{ flex: 1, height: 6, background: 'var(--navy-700)', borderRadius: 3, overflow: 'hidden' }}>
                    <div style={{ height: '100%', width: t.riskScore + '%', background: color, borderRadius: 3 }} />
                  </div>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700, color, flexShrink: 0 }}>
                    {t.riskScore}/100
                  </span>
                </div>

                {/* Alert counts */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 6, marginBottom: 12 }}>
                  {[
                    { label: 'Critical', value: t.alertStats.critical, color: '#ff3b3b' },
                    { label: 'High',     value: t.alertStats.high || 0, color: '#ff6b35' },
                    { label: 'Open',     value: t.alertStats.open,     color: 'var(--text-primary)' },
                    { label: 'Total',    value: t.alertStats.total,    color: 'var(--text-muted)' }
                  ].map(s => (
                    <div key={s.label} style={{ textAlign: 'center', padding: '6px 4px', background: 'var(--navy-800)', borderRadius: 4 }}>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 16, fontWeight: 700, color: s.color }}>{s.value}</div>
                      <div style={{ fontSize: 9, color: 'var(--text-muted)', textTransform: 'uppercase' }}>{s.label}</div>
                    </div>
                  ))}
                </div>

                {/* Meta */}
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-muted)' }}>
                  <span>👤 {t.privilegedUsers || '—'} admins</span>
                  <span>
                    {t.trialStatus === 'trial'
                      ? <span style={{ color: '#f5a623' }}>⏳ {t.daysLeft}d trial</span>
                      : t.trialStatus === 'active'
                      ? <span style={{ color: '#2ecc71' }}>✓ Active</span>
                      : <span style={{ color: '#ff3b3b' }}>⚠️ Expired</span>}
                  </span>
                  <span>{t.lastAlertAt ? new Date(t.lastAlertAt).toLocaleDateString() : 'No alerts'}</span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
