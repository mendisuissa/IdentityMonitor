import React, { useEffect, useMemo, useState } from 'react';
import { api } from '../services/api';

export default function CaseBoardPage() {
  const [cases, setCases] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [owner, setOwner] = useState('');
  const [status, setStatus] = useState('');
  const [approval, setApproval] = useState('');
  const [selectedId, setSelectedId] = useState<string>('');
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [comment, setComment] = useState('');
  const [bulkOwner, setBulkOwner] = useState('');
  const [busy, setBusy] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    api.getCases({ owner: owner || undefined, caseStatus: status || undefined, approvalStatus: approval || undefined })
      .then((data) => {
        setCases(data);
        if (!selectedId && data[0]?.alertId) setSelectedId(data[0].alertId);
        if (selectedId && !data.find((c: any) => c.alertId === selectedId) && data[0]?.alertId) setSelectedId(data[0].alertId);
        setSelectedIds((prev) => prev.filter(id => data.some((c: any) => c.alertId === id)));
      })
      .finally(() => setLoading(false));
  };
  useEffect(() => { load(); }, [owner, status, approval]);

  const queues = useMemo(() => ({
    overdue: cases.filter(c => c.isOverdue),
    unassigned: cases.filter(c => !c.owner),
    pending: cases.filter(c => c.approvalStatus === 'pending'),
    ready: cases.filter(c => c.caseStatus === 'ready_to_execute')
  }), [cases]);

  const selected = cases.find(c => c.alertId === selectedId) || cases[0];

  const act = async (action: () => Promise<any>, key: string) => {
    setBusy(key);
    try { await action(); await load(); } finally { setBusy(null); }
  };

  const toggleBulk = (id: string) => {
    setSelectedIds(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);
  };

  const bulkAct = async (action: string) => {
    if (!selectedIds.length) return;
    await act(() => api.bulkCases({ alertIds: selectedIds, action, owner: bulkOwner, comment }), `bulk-${action}`);
    if (action === 'comment') setComment('');
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Case Board</div>
          <div className="page-subtitle">Operational queue with SLA automation, mentions, deeper approvals, bulk actions, and guided response flow</div>
        </div>
      </div>
      <div className="stats-grid" style={{ marginBottom: 20 }}>
        <div className="stat-card critical"><div className="stat-value">{queues.overdue.length}</div><div className="stat-label">Overdue</div></div>
        <div className="stat-card amber"><div className="stat-value">{queues.unassigned.length}</div><div className="stat-label">Unassigned</div></div>
        <div className="stat-card medium"><div className="stat-value">{queues.pending.length}</div><div className="stat-label">Pending approval</div></div>
        <div className="stat-card neutral"><div className="stat-value">{queues.ready.length}</div><div className="stat-label">Ready to execute</div></div>
      </div>
      <div className="filter-bar">
        <input className="filter-input" placeholder="Owner email" value={owner} onChange={e => setOwner(e.target.value)} />
        <select className="filter-select" value={status} onChange={e => setStatus(e.target.value)}>
          <option value="">All case statuses</option><option value="open">Open</option><option value="triage">Triage</option><option value="ready_to_execute">Ready to execute</option><option value="closed">Closed</option>
        </select>
        <select className="filter-select" value={approval} onChange={e => setApproval(e.target.value)}>
          <option value="">All approvals</option><option value="pending">Pending</option><option value="approved">Approved</option><option value="rejected">Rejected</option>
        </select>
        <button className="btn btn-ghost btn-sm" onClick={load}>↻ Refresh</button>
        <button className="btn btn-sm btn-primary" onClick={() => act(() => api.runAutomationSweep(), 'sweep')} disabled={busy === 'sweep'}>{busy === 'sweep' ? 'Running…' : 'Run automation sweep'}</button>
      </div>

      <div className="callout-panel" style={{ marginBottom: 18 }}>
        <div className="card-title" style={{ marginBottom: 8 }}>Bulk actions</div>
        <div className="filter-bar">
          <input className="filter-input" placeholder="Assign owner for selected cases" value={bulkOwner} onChange={e => setBulkOwner(e.target.value)} />
          <input className="filter-input" placeholder="Bulk comment / mention" value={comment} onChange={e => setComment(e.target.value)} />
          <button className="btn btn-sm btn-ghost" disabled={!selectedIds.length || !bulkOwner} onClick={() => bulkAct('assign')}>Assign ({selectedIds.length})</button>
          <button className="btn btn-sm btn-ghost" disabled={!selectedIds.length || !comment.trim()} onClick={() => bulkAct('comment')}>Comment</button>
          <button className="btn btn-sm btn-ghost" disabled={!selectedIds.length} onClick={() => bulkAct('approve')}>Approve</button>
          <button className="btn btn-sm btn-ghost" disabled={!selectedIds.length} onClick={() => bulkAct('resolve')}>Resolve</button>
          <button className="btn btn-sm btn-ghost" disabled={!selectedIds.length} onClick={() => bulkAct('dismiss')}>Dismiss</button>
        </div>
      </div>

      <div className="grid-two-responsive case-board-grid">
        <div style={{ display: 'grid', gap: 16 }}>
          {(loading ? [] : cases).map((c, idx) => (
            <button key={idx} className="card case-card-btn" onClick={() => setSelectedId(c.alertId)} style={{ textAlign: 'left', border: selected?.alertId === c.alertId ? '1px solid var(--navy-border-light)' : undefined }}>
              <div className="case-card-top">
                <label className="checkbox-inline" onClick={e => e.stopPropagation()}>
                  <input type="checkbox" checked={selectedIds.includes(c.alertId)} onChange={() => toggleBulk(c.alertId)} />
                </label>
                <div className="card-header" style={{ marginBottom: 8, flex: 1 }}>
                  <div className="card-title">{c.title}</div>
                  <span className={`severity-badge ${c.severity}`}>{c.severity}</span>
                </div>
              </div>
              <div className="detail-stack">
                <div className="text-muted" style={{ fontSize: 12 }}>{c.userDisplayName} · {c.userPrincipalName}</div>
                <div style={{ fontSize: 12 }}>Owner: <strong>{c.owner || 'Unassigned'}</strong></div>
                <div style={{ fontSize: 12 }}>Case status: <strong>{c.caseStatus}</strong></div>
                <div style={{ fontSize: 12 }}>Approval: <strong>{c.approvalStatus}</strong></div>
                <div style={{ fontSize: 12 }}>Due: <strong>{c.dueAt ? new Date(c.dueAt).toLocaleString() : '—'}</strong></div>
              </div>
            </button>
          ))}
          {!loading && !cases.length && <div className="card"><div className="empty-state"><div className="empty-icon">📦</div><div className="empty-text">No cases matched the current queue filters</div></div></div>}
        </div>

        <div className="card case-detail-sticky">
          {!selected ? (
            <div className="empty-state"><div className="empty-icon">🧭</div><div className="empty-text">Select a case to view automation, mentions, and approvals</div></div>
          ) : (
            <>
              <div className="card-header">
                <div className="card-title">{selected.title}</div>
                <span className="role-tag">{selected.tenantId}</span>
              </div>
              <div className="detail-stack" style={{ marginBottom: 12 }}>
                <div style={{ fontSize: 12 }}>Requested action: <strong>{selected.requestedAction}</strong></div>
                <div style={{ fontSize: 12 }}>Escalation level: <strong>{selected.escalationLevel || 0}</strong></div>
                <div style={{ fontSize: 12 }}>Confidence: <strong>{(selected.confidence || 'medium').toUpperCase()}</strong></div>
                <div style={{ fontSize: 12 }}>Active approver lane: <strong>{selected.activeApprovalStep?.role || 'Completed'}</strong></div>
              </div>

              <div className="callout-panel" style={{ marginBottom: 12 }}>
                <div className="card-title" style={{ marginBottom: 8 }}>Approval chain</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                  {(selected.approvalSteps || []).map((step: any) => (
                    <span key={step.step} className="role-tag">Step {step.step} · {step.role} · {step.status}</span>
                  ))}
                </div>
              </div>

              <div className="callout-panel" style={{ marginBottom: 12 }}>
                <div className="card-title" style={{ marginBottom: 8 }}>Mentions</div>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  {(selected.mentions || []).length ? selected.mentions.map((m: string) => <span key={m} className="role-tag">@{m}</span>) : <span className="text-muted">No mentions yet</span>}
                </div>
              </div>

              <div className="callout-panel" style={{ marginBottom: 12 }}>
                <div className="card-title" style={{ marginBottom: 8 }}>Runbook</div>
                <div style={{ display: 'grid', gap: 8, marginBottom: 10 }}>
                  {(selected.runbookSteps || []).length ? selected.runbookSteps.map((step: string, idx: number) => (
                    <div key={idx} style={{ fontSize: 12 }}>• Step {idx + 1}: {step}</div>
                  )) : <span className="text-muted">No runbook steps configured</span>}
                </div>
              </div>

              <div className="callout-panel" style={{ marginBottom: 12 }}>
                <div className="card-title" style={{ marginBottom: 8 }}>Comments</div>
                <div style={{ display: 'grid', gap: 8, maxHeight: 220, overflow: 'auto', marginBottom: 8 }}>
                  {(selected.comments || []).length ? selected.comments.map((item: any) => (
                    <div key={item.id} style={{ paddingBottom: 8, borderBottom: '1px solid var(--navy-border)' }}>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{item.actor} · {new Date(item.createdAt).toLocaleString()}</div>
                      <div style={{ fontSize: 13 }}>{item.message}</div>
                    </div>
                  )) : <span className="text-muted">No comments yet</span>}
                </div>
                <textarea className="filter-input" rows={4} placeholder="Add comment. Example: @soclead@company.com please review before auto-disable." value={comment} onChange={e => setComment(e.target.value)} style={{ width: '100%', resize: 'vertical', minHeight: 96 }} />
                <div style={{ display: 'flex', gap: 8, marginTop: 8, flexWrap: 'wrap' }}>
                  <button className="btn btn-sm btn-primary" disabled={!comment.trim() || busy === 'comment'} onClick={() => act(async () => { await api.addComment(selected.alertId, comment.trim()); setComment(''); }, 'comment')}>Add comment</button>
                  <button className="btn btn-sm" disabled={busy === 'approve'} onClick={() => act(() => api.decidePlaybook(selected.alertId, 'approved', selected.requestedAction || 'monitor', 'Approved via Phase 11 case board'), 'approve')}>Approve step</button>
                  <button className="btn btn-sm btn-ghost" disabled={busy === 'reject'} onClick={() => act(() => api.decidePlaybook(selected.alertId, 'rejected', 'monitor', 'Rejected for more investigation'), 'reject')}>Reject step</button>
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
