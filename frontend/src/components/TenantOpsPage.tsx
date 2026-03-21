import React, { useEffect, useMemo, useState } from 'react';
import { api } from '../services/api';

export default function TenantOpsPage() {
  const [health, setHealth] = useState<any>(null);
  const [ops, setOps] = useState<any>(null);
  const [roles, setRoles] = useState<any>(null);
  const [policy, setPolicy] = useState<any>(null);
  const [orchestration, setOrchestration] = useState<any>(null);
  const [orchestrationPolicies, setOrchestrationPolicies] = useState<any>(null);
  const [selection, setSelection] = useState<string[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [lastRun, setLastRun] = useState<any>(null);

  const load = () => Promise.all([api.getTenantHealth(), api.getOpsDashboard(), api.getRolesMatrix(), api.getPolicyPack(), api.getOrchestration(), api.getOrchestrationPolicies()])
    .then(([h, o, r, p, m, op]) => {
      setHealth(h);
      setOps(o);
      setRoles(r);
      setPolicy(p);
      setOrchestration(m);
      setOrchestrationPolicies(op);
      setSelection((current) => current.filter(id => (m?.tenants || []).some((t: any) => t.tenantId === id)));
    });

  useEffect(() => { load(); }, []);

  const changePolicy = async (pack: string) => {
    setBusy('policy');
    try { await api.setPolicyPack(pack); await load(); } finally { setBusy(null); }
  };

  const runFleetAction = async (action: string) => {
    setBusy(action);
    try {
      const result = await api.orchestrateTenants({ tenantIds: selection, action });
      setLastRun(result);
      await load();
    } finally {
      setBusy(null);
    }
  };

  const tenants = orchestration?.tenants || [];
  const selectedCount = selection.length || tenants.length;
  const selectionSummary = useMemo(() => tenants.filter((t: any) => !selection.length || selection.includes(t.tenantId)), [selection, tenants]);

  const toggle = (tenantId: string) => {
    setSelection(prev => prev.includes(tenantId) ? prev.filter(id => id !== tenantId) : [...prev, tenantId]);
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Tenant Ops Dashboard</div>
          <div className="page-subtitle">Phase 10 orchestration across policy, permissions, notification backlog, and fleet operations</div>
        </div>
      </div>

      <div className="stats-grid" style={{ marginBottom: 20 }}>
        <div className="stat-card neutral"><div className="stat-value">{health?.score ?? '—'}</div><div className="stat-label">Tenant health</div></div>
        <div className="stat-card amber"><div className="stat-value">{ops?.queuePressure?.pendingApproval ?? '—'}</div><div className="stat-label">Pending approvals</div></div>
        <div className="stat-card critical"><div className="stat-value">{ops?.queuePressure?.overdue ?? '—'}</div><div className="stat-label">Overdue cases</div></div>
        <div className="stat-card medium"><div className="stat-value">{ops?.notificationCenter?.unread ?? 0}</div><div className="stat-label">Unread notifications</div></div>
      </div>

      <div className="grid-two-responsive">
        <div className="card">
          <div className="card-header"><div className="card-title">Health controls</div><span className="role-tag">Grade {health?.grade || '—'}</span></div>
          <div style={{ display: 'grid', gap: 10 }}>
            {(health?.controls || []).map((c: any) => (
              <div key={c.id}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 4 }}><span>{c.id}</span><strong>{c.score}</strong></div>
                <div style={{ height: 8, background: 'rgba(255,255,255,0.06)', borderRadius: 999 }}><div style={{ width: `${c.score}%`, height: '100%', borderRadius: 999, background: c.score > 84 ? 'var(--green-clean)' : c.score > 70 ? 'var(--amber-400)' : 'var(--red-critical)' }} /></div>
              </div>
            ))}
          </div>
          <div className="callout-panel" style={{ marginTop: 16 }}>
            <div className="card-title" style={{ marginBottom: 6 }}>Policy pack</div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {['conservative', 'balanced', 'strict'].map(pack => (
                <button key={pack} className={`btn btn-sm ${policy?.policyPack === pack ? 'btn-primary' : ''}`} onClick={() => changePolicy(pack)} disabled={busy === 'policy'}>{pack}</button>
              ))}
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header"><div className="card-title">Role matrix</div><span className="role-tag">Current {roles?.current?.role || '—'}</span></div>
          <div style={{ display: 'grid', gap: 10 }}>
            {roles && Object.entries(roles.matrix || {}).map(([role, perms]: any) => (
              <div key={role} style={{ paddingBottom: 10, borderBottom: '1px solid var(--navy-border)' }}>
                <div style={{ fontWeight: 700, fontSize: 12, marginBottom: 6 }}>{role}</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>{perms.map((p: string) => <span key={p} className="role-tag">{p}</span>)}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="card" style={{ marginTop: 20 }}>
        <div className="card-header"><div className="card-title">Workflow vs response trend</div></div>
        <div style={{ display: 'grid', gap: 8 }}>
          {(ops?.trend || []).map((t: any) => (
            <div key={t.day} style={{ display: 'grid', gridTemplateColumns: '120px 1fr 1fr', gap: 12, alignItems: 'center' }}>
              <div className="mono text-muted" style={{ fontSize: 11 }}>{t.day}</div>
              <div style={{ fontSize: 12 }}>Workflow updates: <strong>{t.workflow}</strong></div>
              <div style={{ fontSize: 12 }}>Response actions: <strong>{t.response}</strong></div>
            </div>
          ))}
        </div>
      </div>



      <div className="card" style={{ marginTop: 20 }}>
        <div className="card-header"><div className="card-title">Orchestration guardrails</div><span className="role-tag">Phase 11</span></div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          <span className="role-tag">Cross-tenant sweep: {orchestrationPolicies?.allowCrossTenantSweep ? 'on' : 'off'}</span>
          <span className="role-tag">Bulk notify: {orchestrationPolicies?.allowBulkNotify ? 'on' : 'off'}</span>
          <span className="role-tag">Disable approval: {orchestrationPolicies?.requireApprovalForDisable ? 'required' : 'not required'}</span>
          <span className="role-tag">Max tenants/run: {orchestrationPolicies?.maxTenantsPerRun ?? '—'}</span>
        </div>
      </div>

      <div className="card" style={{ marginTop: 20 }}>
        <div className="card-header"><div className="card-title">Multi-tenant orchestration</div><span className="role-tag">Phase 11</span></div>
        <div className="stats-grid" style={{ marginBottom: 16 }}>
          <div className="stat-card neutral"><div className="stat-value">{orchestration?.summary?.totalOpenAlerts ?? 0}</div><div className="stat-label">Fleet open alerts</div></div>
          <div className="stat-card critical"><div className="stat-value">{orchestration?.summary?.totalOverdueCases ?? 0}</div><div className="stat-label">Fleet overdue</div></div>
          <div className="stat-card amber"><div className="stat-value">{orchestration?.summary?.totalPendingApprovals ?? 0}</div><div className="stat-label">Fleet pending approvals</div></div>
          <div className="stat-card medium"><div className="stat-value">{orchestration?.summary?.totalNotificationBacklog ?? 0}</div><div className="stat-label">Notification backlog</div></div>
        </div>

        <div className="filter-bar" style={{ marginBottom: 14 }}>
          <button className="btn btn-primary btn-sm" disabled={!!busy} onClick={() => runFleetAction('sweep')}>{busy === 'sweep' ? 'Running…' : `Run automation sweep (${selectedCount})`}</button>
          <button className="btn btn-sm btn-ghost" disabled={!!busy} onClick={() => runFleetAction('notify-review')}>{busy === 'notify-review' ? 'Queuing…' : `Queue review notice (${selectedCount})`}</button>
          <button className="btn btn-sm btn-ghost" onClick={() => setSelection([])}>Select all</button>
        </div>

        <div style={{ display: 'grid', gap: 10 }}>
          {tenants.map((tenant: any) => (
            <label key={tenant.tenantId} style={{ display: 'grid', gridTemplateColumns: '28px 1.4fr repeat(7, 1fr)', gap: 12, paddingBottom: 10, borderBottom: '1px solid var(--navy-border)', alignItems: 'center', cursor: 'pointer' }}>
              <input type="checkbox" checked={!selection.length || selection.includes(tenant.tenantId)} onChange={() => toggle(tenant.tenantId)} />
              <div>
                <div style={{ fontWeight: 700, fontSize: 13 }}>{tenant.tenantName}</div>
                <div className="text-muted" style={{ fontSize: 11 }}>{tenant.tenantId}</div>
              </div>
              <div style={{ fontSize: 12 }}>Pack<br /><strong>{tenant.policyPack}</strong></div>
              <div style={{ fontSize: 12 }}>Open<br /><strong>{tenant.openAlerts}</strong></div>
              <div style={{ fontSize: 12 }}>Critical<br /><strong>{tenant.criticalOpen}</strong></div>
              <div style={{ fontSize: 12 }}>Overdue<br /><strong>{tenant.overdueCases}</strong></div>
              <div style={{ fontSize: 12 }}>Pending<br /><strong>{tenant.pendingApproval}</strong></div>
              <div style={{ fontSize: 12 }}>Notify<br /><strong>{tenant.notificationBacklog}</strong></div>
              <div style={{ fontSize: 12 }}>Health<br /><strong>{tenant.healthScore}</strong></div>
            </label>
          ))}
        </div>

        {lastRun && (
          <div className="callout-panel" style={{ marginTop: 16 }}>
            <div className="card-title" style={{ marginBottom: 6 }}>Last orchestration run</div>
            <div style={{ fontSize: 12, marginBottom: 8 }}>{lastRun.action} · {new Date(lastRun.executedAt).toLocaleString()}</div>
            <div style={{ display: 'grid', gap: 6 }}>
              {(lastRun.results || []).map((r: any) => (
                <div key={r.tenantId} style={{ fontSize: 12 }}>• <strong>{r.tenantId}</strong> — {r.status}</div>
              ))}
            </div>
          </div>
        )}

        <div className="callout-panel" style={{ marginTop: 16 }}>
          <div className="card-title" style={{ marginBottom: 6 }}>Selection summary</div>
          <div style={{ fontSize: 12 }}>Selected open alerts: <strong>{selectionSummary.reduce((a: number, t: any) => a + t.openAlerts, 0)}</strong></div>
          <div style={{ fontSize: 12 }}>Selected overdue cases: <strong>{selectionSummary.reduce((a: number, t: any) => a + t.overdueCases, 0)}</strong></div>
          <div style={{ fontSize: 12 }}>Selected notification backlog: <strong>{selectionSummary.reduce((a: number, t: any) => a + t.notificationBacklog, 0)}</strong></div>
        </div>
      </div>
    </div>
  );
}
