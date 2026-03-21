import React, { useEffect, useMemo, useState } from 'react';
import { api } from '../services/api';

export default function AuditCenterPage() {
  const [data, setData] = useState<any>({ entries: [], stats: {} });
  const [action, setAction] = useState('');
  const [actor, setActor] = useState('');
  const [since, setSince] = useState('');
  const [loading, setLoading] = useState(true);

  const load = () => {
    setLoading(true);
    api.getAudit({ limit: 200, action: action || undefined, actor: actor || undefined, since: since || undefined })
      .then(setData)
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, [action, actor, since]);

  const actors = useMemo(() => Array.from(new Set<string>(((data.entries || []) as any[]).map((e: any) => String(e.actor || '')))).filter(Boolean).slice(0, 20), [data.entries]);

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Audit Center</div>
          <div className="page-subtitle">Searchable evidence stream for responses, playbook decisions, policy changes, and workflow updates</div>
        </div>
        <a className="btn btn-primary" href={api.exportAuditUrl({ action: action || undefined, actor: actor || undefined, since: since || undefined })}>↓ Export filtered CSV</a>
      </div>

      <div className="stats-grid" style={{ marginBottom: 20 }}>
        <div className="stat-card neutral"><div className="stat-value">{data.stats?.total || 0}</div><div className="stat-label">Events</div></div>
        <div className="stat-card medium"><div className="stat-value">{data.stats?.last7Days || 0}</div><div className="stat-label">Last 7 days</div></div>
        <div className="stat-card amber"><div className="stat-value">{data.stats?.settingsChanges || 0}</div><div className="stat-label">Settings changes</div></div>
        <div className="stat-card critical"><div className="stat-value">{data.stats?.sessionsRevoked || 0}</div><div className="stat-label">Session revokes</div></div>
      </div>

      <div className="filter-bar">
        <input className="filter-input" placeholder="Filter by action e.g. workflow.updated" value={action} onChange={e => setAction(e.target.value)} />
        <select className="filter-select" value={actor} onChange={e => setActor(e.target.value)}>
          <option value="">All actors</option>
          {actors.map((a: string) => <option key={a} value={a}>{a}</option>)}
        </select>
        <input className="filter-input" type="date" value={since} onChange={e => setSince(e.target.value)} />
        <button className="btn btn-ghost btn-sm" onClick={load}>↻ Refresh</button>
      </div>

      <div className="card">
        <div className="card-header"><div className="card-title">Evidence stream</div></div>
        {loading ? <div className="loading-state"><div className="loading-spinner" /><div className="loading-text">Loading evidence...</div></div> : (
          <div style={{ display: 'grid', gap: 10 }}>
            {(data.entries || []).map((e: any, idx: number) => (
              <div key={idx} className="timeline-item" style={{ marginBottom: 0 }}>
                <div className="timeline-dot" />
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'center' }}>
                    <div style={{ fontWeight: 700, fontSize: 13 }}>{e.action}</div>
                    <div className="mono text-muted" style={{ fontSize: 11 }}>{new Date(e.timestamp).toLocaleString()}</div>
                  </div>
                  <div className="text-muted" style={{ fontSize: 12, marginTop: 3 }}>Actor: {e.actor}</div>
                  <pre style={{ marginTop: 8, whiteSpace: 'pre-wrap', fontSize: 11, color: 'var(--text-secondary)', background: 'rgba(255,255,255,0.03)', border: '1px solid var(--navy-border)', borderRadius: 10, padding: 10 }}>{JSON.stringify(e, null, 2)}</pre>
                </div>
              </div>
            ))}
            {!data.entries?.length && <div className="empty-state"><div className="empty-icon">🧾</div><div className="empty-text">No audit events matched this filter</div></div>}
          </div>
        )}
      </div>
    </div>
  );
}
