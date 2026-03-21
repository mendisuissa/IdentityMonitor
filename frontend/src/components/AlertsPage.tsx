import React, { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { formatDistanceToNow, format } from 'date-fns';
import { generateAlertPDF } from '../services/pdfReport';
import { api } from '../services/api';
import { Alert, AlertWorkflow, AccessProfile } from '../types';

function inferConfidence(alert: Alert): 'high' | 'medium' | 'low' {
  if (alert.severity === 'critical') return 'high';
  if (alert.severity === 'high') return 'high';
  if (alert.riskScore && alert.riskScore >= 80) return 'high';
  if (alert.severity === 'medium') return 'medium';
  return 'low';
}
const confidenceColor = (c: string) => ({ high: '#ff6b35', medium: '#f5a623', low: '#4a90d9' }[c] || '#8ba3cc');

export default function AlertsPage() {
  const [searchParams] = useSearchParams();
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState(searchParams.get('status') || '');
  const [severityFilter, setSeverityFilter] = useState(searchParams.get('severity') || '');
  const [search, setSearch] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [acting, setActing] = useState<string | null>(null);
  const [access, setAccess] = useState<AccessProfile | null>(null);
  const [commentDrafts, setCommentDrafts] = useState<Record<string, string>>({});

  const fetchAlerts = () => {
    setLoading(true);
    Promise.all([
      api.getAlerts({ status: statusFilter || undefined, severity: severityFilter || undefined }),
      api.getAccess().catch(() => null)
    ])
      .then(([a, acc]) => { setAlerts(a); if (acc) setAccess(acc); })
      .catch(() => {})
      .finally(() => setLoading(false));
  };
  useEffect(() => { fetchAlerts(); }, [statusFilter, severityFilter]);

  const updateWorkflow = async (alertId: string, patch: Partial<AlertWorkflow>) => {
    const updated = await api.patchWorkflow(alertId, patch as any);
    setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, workflow: { ...(a.workflow || {}), ...updated } } : a));
  };

  const handleResolve = async (alert: Alert) => {
    setActing(alert.id);
    try {
      await api.resolveAlert(alert.id, alert.workflow?.owner || 'admin');
      await fetchAlerts();
    } finally { setActing(null); }
  };
  const handleDismiss = async (alert: Alert) => {
    setActing(alert.id);
    try { await api.dismissAlert(alert.id); await fetchAlerts(); } finally { setActing(null); }
  };
  const handleRevoke = async (alert: Alert) => {
    if (!window.confirm(`Revoke all sessions for ${alert.userDisplayName}?`)) return;
    setActing(alert.id);
    try { const result = await api.revokeUserSessions(alert.userId); window.alert(result.message); } catch (err: any) { window.alert('Failed: ' + err.message); } finally { setActing(null); }
  };
  const handleAddComment = async (alertId: string) => {
    const message = commentDrafts[alertId]?.trim();
    if (!message) return;
    const updated = await api.addComment(alertId, message);
    setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, workflow: { ...(a.workflow || {}), ...updated } } : a));
    setCommentDrafts(prev => ({ ...prev, [alertId]: '' }));
  };

  const filtered = alerts.filter(a => !search || [a.userDisplayName, a.userPrincipalName, a.anomalyLabel, a.ipAddress, a.country, a.appName].filter(Boolean).join(' ').toLowerCase().includes(search.toLowerCase()));
  const overview = useMemo(() => {
    const open = filtered.filter(a => a.status === 'open');
    return {
      open: open.length,
      assigned: open.filter(a => a.workflow?.owner).length,
      withNotes: open.filter(a => (a.workflow?.comments || []).length > 0 || a.workflow?.note).length,
      highConfidence: open.filter(a => (a.workflow?.confidence || inferConfidence(a)) === 'high').length,
    };
  }, [filtered]);

  const canRespond = access?.permissions.includes('alerts.respond');
  const canApprove = access?.permissions.includes('alerts.approve');

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Active Threats</div>
          <div className="page-subtitle">Investigation, approval workflow, collaboration thread, and guided response for privileged identity incidents</div>
        </div>
        <div className="role-tag">Role {access?.role || '—'}</div>
      </div>
      <div className="stats-grid" style={{ marginBottom: 20 }}>
        <div className="stat-card critical"><div className="stat-value">{overview.open}</div><div className="stat-label">Open threats</div></div>
        <div className="stat-card amber"><div className="stat-value">{overview.assigned}</div><div className="stat-label">Assigned</div></div>
        <div className="stat-card medium"><div className="stat-value">{overview.highConfidence}</div><div className="stat-label">High confidence</div></div>
        <div className="stat-card neutral"><div className="stat-value">{overview.withNotes}</div><div className="stat-label">Documented</div></div>
      </div>
      <div className="callout-panel" style={{ marginBottom: 12 }}>
        <div className="card-title" style={{ marginBottom: 4 }}>Queue visibility</div>
        <div className="text-muted" style={{ fontSize: 12 }}>If the navbar badge looks higher than the visible list, the difference is usually caused by search text, severity filters, or alerts waiting in another workflow state.</div>
      </div>

      <div className="filter-bar">
        <select className="filter-select" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}><option value="">All Statuses</option><option value="open">Open</option><option value="resolved">Resolved</option><option value="dismissed">Dismissed</option></select>
        <select className="filter-select" value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}><option value="">All Severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
        <input className="filter-input" placeholder="Search threat, user, app, IP, location..." value={search} onChange={e => setSearch(e.target.value)} />
        <button className="btn btn-ghost btn-sm" onClick={fetchAlerts}>↻ Refresh</button>
      </div>
      {loading ? <div className="loading-state"><div className="loading-spinner" /><div className="loading-text">Loading threats...</div></div> : filtered.length === 0 ? (
        <div className="card"><div className="empty-state"><div className="empty-icon">✓</div><div className="empty-text">No threats matched the current view</div></div></div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {filtered.map(alert => {
            const wf = alert.workflow || {};
            const confidence = wf.confidence || inferConfidence(alert);
            return <div key={alert.id} className="card" style={{ padding: 0, overflow: expanded === alert.id ? 'visible' : 'hidden', borderLeft: `3px solid ${({ critical: '#ff3b3b', high: '#ff6b35', medium: '#f5a623', low: '#4a90d9' } as any)[alert.severity]}` }}>
              <div style={{ padding: '14px 20px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap' }} onClick={() => setExpanded(expanded === alert.id ? null : alert.id)}>
                <span className={`severity-badge ${alert.severity}`}>{alert.severity}</span>
                <div style={{ minWidth: 180 }}><div style={{ fontWeight: 700, fontSize: 13 }}>{alert.userDisplayName}</div><div className="text-muted" style={{ fontSize: 11 }}>{alert.userPrincipalName}</div></div>
                <div style={{ flex: 1, minWidth: 180 }}><div style={{ fontWeight: 700, fontSize: 13 }}>{alert.anomalyLabel}</div><div className="text-muted" style={{ fontSize: 11 }}>{alert.detail}</div></div>
                <div style={{ minWidth: 160, textAlign: 'right' }}>
                  <div className="mono text-muted" style={{ fontSize: 11 }}>{formatDistanceToNow(new Date(alert.detectedAt), { addSuffix: true })}</div>
                  <div style={{ fontSize: 10, color: confidenceColor(confidence), textTransform: 'uppercase', fontFamily: 'var(--font-mono)', marginTop: 4 }}>{confidence} confidence</div>
                  <div className="role-tag" style={{ marginTop: 6 }}>{wf.caseStatus || 'open'} · {wf.approvalStatus || 'pending'}</div>
                </div>
              </div>
              {expanded === alert.id && <div style={{ borderTop: '1px solid var(--navy-border)', padding: '16px 20px', background: 'rgba(0,0,0,0.16)' }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1.15fr 1fr 1.1fr', gap: 16 }}>
                  <div>
                    <div className="card-title" style={{ marginBottom: 8 }}>Incident timeline</div>
                    <TimelineItem title="Risky sign-in observed" subtitle={format(new Date(alert.signInTime), 'PPpp')} detail={`${[alert.city, alert.country].filter(Boolean).join(', ') || 'Unknown'} · ${alert.ipAddress || 'No IP'}`} />
                    <TimelineItem title="Privileged context confirmed" subtitle={(alert.roles || []).join(', ')} detail={`App: ${alert.appName || 'Unknown'} · Device: ${alert.deviceOs || 'Unknown'}`} />
                    {wf.slaBreachedAt && <TimelineItem title="SLA breached" subtitle={format(new Date(wf.slaBreachedAt), 'PPpp')} detail={`Escalation level ${wf.escalationLevel || 1}`} />}
                    <div className="card-title" style={{ margin: '14px 0 8px' }}>Comments</div>
                    <div style={{ display: 'grid', gap: 8, maxHeight: 200, overflow: 'auto' }}>
                      {(wf.comments || []).map(c => <div key={c.id} style={{ border: '1px solid var(--navy-border)', borderRadius: 10, padding: 10 }}><div style={{ fontSize: 11, fontWeight: 700 }}>{c.actor}</div><div style={{ fontSize: 12, marginTop: 4 }}>{c.message}</div><div className="text-muted" style={{ fontSize: 10, marginTop: 4 }}>{new Date(c.createdAt).toLocaleString()}</div></div>)}
                      {!wf.comments?.length && <div className="text-muted" style={{ fontSize: 12 }}>No collaboration thread yet.</div>}
                    </div>
                    {canRespond && <div style={{ display: 'flex', gap: 8, marginTop: 10 }}><input className="filter-input" placeholder="Add analyst note or approval comment" value={commentDrafts[alert.id] || ''} onChange={e => setCommentDrafts(prev => ({ ...prev, [alert.id]: e.target.value }))} /><button className="btn btn-primary btn-sm" onClick={() => handleAddComment(alert.id)}>Add</button></div>}
                  </div>
                  <div>
                    <div className="card-title" style={{ marginBottom: 8 }}>Case management</div>
                    <DetailRow label="Owner" value={wf.owner || 'Unassigned'} />
                    <DetailRow label="Due" value={wf.dueAt ? new Date(wf.dueAt).toLocaleString() : '—'} />
                    <DetailRow label="Requested action" value={wf.requestedAction || 'monitor'} />
                    <DetailRow label="Approval" value={wf.approvalStatus || 'pending'} />
                    {canRespond && <>
                      <label className="card-title" style={{ marginBottom: 6, display: 'block', marginTop: 10 }}>Assign owner</label>
                      <input className="filter-input" value={wf.owner || ''} onChange={e => updateWorkflow(alert.id, { owner: e.target.value })} />
                      <label className="card-title" style={{ marginBottom: 6, display: 'block', marginTop: 10 }}>Confidence</label>
                      <select className="filter-select" value={confidence} onChange={e => updateWorkflow(alert.id, { confidence: e.target.value as any })}><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
                      <label className="card-title" style={{ marginBottom: 6, display: 'block', marginTop: 10 }}>Case status</label>
                      <select className="filter-select" value={wf.caseStatus || 'open'} onChange={e => updateWorkflow(alert.id, { caseStatus: e.target.value as any })}><option value="open">Open</option><option value="triage">Triage</option><option value="ready_to_execute">Ready to execute</option><option value="closed">Closed</option></select>
                      <label className="card-title" style={{ marginBottom: 6, display: 'block', marginTop: 10 }}>SLA due</label>
                      <input className="filter-input" type="datetime-local" value={wf.dueAt ? wf.dueAt.slice(0,16) : ''} onChange={e => updateWorkflow(alert.id, { dueAt: new Date(e.target.value).toISOString() })} />
                    </>}
                  </div>
                  <div>
                    <div className="card-title" style={{ marginBottom: 8 }}>Advanced approval workflow</div>
                    <div className="callout-panel">
                      <div className="card-title" style={{ marginBottom: 6 }}>Recommended next action</div>
                      <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{alert.severity === 'critical' ? 'Escalate immediately. Capture owner, approve revoke or disable, and document business justification.' : 'Validate context first, then choose between monitor, revoke, or disable based on confidence and role criticality.'}</div>
                    </div>
                    {canApprove && <div style={{ display: 'grid', gap: 8, marginTop: 12 }}>
                      <button className="btn btn-primary btn-sm" onClick={() => api.decidePlaybook(alert.id, 'approved', 'revoke').then(fetchAlerts)}>Approve revoke</button>
                      <button className="btn btn-sm" onClick={() => api.decidePlaybook(alert.id, 'approved', 'disable').then(fetchAlerts)}>Approve disable</button>
                      <button className="btn btn-ghost btn-sm" onClick={() => api.decidePlaybook(alert.id, 'rejected', 'monitor').then(fetchAlerts)}>Reject / monitor only</button>
                    </div>}
                    <div style={{ marginTop: 12 }}>
                      <label className="card-title" style={{ marginBottom: 6, display: 'block' }}>Suppression reason</label>
                      <input className="filter-input" value={wf.suppressReason || ''} onChange={e => updateWorkflow(alert.id, { suppressReason: e.target.value })} />
                    </div>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 8, paddingTop: 12, paddingBottom: 16, borderTop: '1px solid var(--navy-border)', flexWrap: 'wrap', marginTop: 16 }}>
                  {alert.status === 'open' && canRespond && <>
                    <button className="btn btn-danger btn-sm" onClick={() => handleRevoke(alert)} disabled={acting === alert.id}>⊘ Revoke Sessions</button>
                    <button className="btn btn-primary btn-sm" onClick={() => handleResolve(alert)} disabled={acting === alert.id}>✓ Mark Resolved</button>
                    <button className="btn btn-ghost btn-sm" onClick={() => handleDismiss(alert)} disabled={acting === alert.id}>Dismiss</button>
                  </>}
                  <button className="btn btn-ghost btn-sm" style={{ marginLeft: 'auto' }} onClick={() => generateAlertPDF(alert as any)}>↓ Export PDF</button>
                </div>
              </div>}
            </div>;
          })}
        </div>
      )}
    </div>
  );
}

function TimelineItem({ title, subtitle, detail }: { title: string; subtitle: string; detail: string }) {
  return <div className="timeline-item"><div className="timeline-dot" /><div><div style={{ fontWeight: 700, fontSize: 12 }}>{title}</div><div className="text-muted" style={{ fontSize: 11 }}>{subtitle}</div><div style={{ fontSize: 11, marginTop: 2 }}>{detail}</div></div></div>;
}
function DetailRow({ label, value }: { label: string; value: string }) {
  return <div style={{ display: 'flex', gap: 8, marginBottom: 6, fontSize: 12 }}><span style={{ color: 'var(--text-muted)', minWidth: 100 }}>{label}</span><span>{value}</span></div>;
}
