import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { formatDistanceToNow } from 'date-fns';
import { api } from '../services/api';
import { PrivilegedUser, RiskPosture } from '../types';

// ── Constants ──────────────────────────────────────────────────────────────
const RISK_ORDER = ['critical', 'high', 'medium', 'low', 'clean'];

const CRITICAL_ROLES = [
  'Global Administrator',
  'Privileged Role Administrator',
  'Security Administrator',
  'Exchange Administrator',
  'SharePoint Administrator',
  'Conditional Access Administrator',
  'Intune Administrator',
];

function severityColor(s: string) {
  return (
    { critical: '#EF4444', high: '#F97316', medium: '#EAB308', low: '#3B82F6', clean: '#34C97D' }[s] ||
    '#8ba3cc'
  );
}

// Eligible roles come from backend as "RoleName (Eligible)"
function parseRole(raw: string): { name: string; isEligible: boolean } {
  const eligible = raw.endsWith(' (Eligible)');
  return { name: eligible ? raw.slice(0, -11) : raw, isEligible: eligible };
}

function blastRadius(roles: string[]): { label: string; color: string; detail: string } {
  const critical = roles.filter(r => CRITICAL_ROLES.includes(r));
  if (critical.length >= 2)
    return { label: 'Catastrophic', color: '#EF4444', detail: `${critical.length} critical roles — full tenant compromise possible` };
  if (critical.length === 1)
    return { label: 'Severe', color: '#F97316', detail: `${critical[0]} — broad lateral movement potential` };
  if (roles.length >= 3)
    return { label: 'Elevated', color: '#EAB308', detail: `${roles.length} privileged roles — significant scope` };
  if (roles.length >= 1)
    return { label: 'Moderate', color: '#3B82F6', detail: `${roles.length} role(s) — limited blast radius` };
  return { label: 'Minimal', color: '#34C97D', detail: 'No privileged roles detected' };
}

// ── SignInRow ─────────────────────────────────────────────────────────────
function SignInRow({ signIn }: { signIn: any }) {
  const failed = signIn.status?.errorCode !== 0 && signIn.status?.errorCode != null;
  const riskLevel = signIn.riskLevelDuringSignIn ?? signIn.riskLevel ?? 'none';
  const riskColor: Record<string, string> = { high: '#EF4444', medium: '#EAB308', low: '#3B82F6', none: 'var(--text-muted)', hidden: '#EAB308' };
  const app = signIn.appDisplayName || signIn.clientAppUsed || 'Unknown app';
  const location = [signIn.location?.city, signIn.location?.countryOrRegion].filter(Boolean).join(', ') || '—';
  const time = signIn.createdDateTime
    ? formatDistanceToNow(new Date(signIn.createdDateTime), { addSuffix: true })
    : '—';

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: '1fr auto auto',
      gap: 8,
      padding: '8px 0',
      borderBottom: '1px solid var(--navy-border)',
      fontSize: 12,
      alignItems: 'center',
    }}>
      <div>
        <div style={{ fontWeight: 600, marginBottom: 1 }}>{app}</div>
        <div className="text-muted" style={{ fontSize: 11 }}>{location} · {time}</div>
      </div>
      <span style={{
        fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 10,
        background: failed ? 'rgba(239,68,68,0.12)' : 'rgba(52,201,125,0.1)',
        color: failed ? '#EF4444' : '#34C97D',
      }}>
        {failed ? 'FAIL' : 'OK'}
      </span>
      {riskLevel !== 'none' && (
        <span style={{
          fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 10,
          background: `${riskColor[riskLevel] ?? '#8ba3cc'}20`,
          color: riskColor[riskLevel] ?? '#8ba3cc',
        }}>
          {riskLevel.toUpperCase()}
        </span>
      )}
    </div>
  );
}

// ── Inline confirm dialog ─────────────────────────────────────────────────
interface ConfirmAction {
  title: string;
  body: string;
  confirmLabel: string;
  danger?: boolean;
  onConfirm: () => void;
}

function ConfirmModal({ action, onDismiss }: { action: ConfirmAction; onDismiss: () => void }) {
  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)', zIndex: 1000,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={onDismiss}>
      <div style={{
        background: 'var(--navy-card)', border: '1px solid var(--navy-border)',
        borderRadius: 14, padding: '24px 28px', maxWidth: 400, width: '90%',
      }} onClick={e => e.stopPropagation()}>
        <div style={{ fontWeight: 700, fontSize: 16, marginBottom: 10 }}>{action.title}</div>
        <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: 20 }}>{action.body}</div>
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
          <button className="btn btn-ghost btn-sm" onClick={onDismiss}>Cancel</button>
          <button
            className={`btn btn-sm ${action.danger ? 'btn-danger' : 'btn-primary'}`}
            onClick={() => { action.onConfirm(); onDismiss(); }}
          >
            {action.confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── ResultToast ───────────────────────────────────────────────────────────
function ResultToast({ message, ok, onDismiss }: { message: string; ok: boolean; onDismiss: () => void }) {
  useEffect(() => { const t = setTimeout(onDismiss, 4000); return () => clearTimeout(t); }, [onDismiss]);
  return (
    <div style={{
      position: 'fixed', bottom: 24, right: 24, zIndex: 1100,
      background: ok ? 'rgba(52,201,125,0.12)' : 'rgba(239,68,68,0.12)',
      border: `1px solid ${ok ? '#34C97D' : '#EF4444'}55`,
      color: ok ? '#34C97D' : '#EF4444',
      borderRadius: 10, padding: '12px 20px', fontSize: 13, fontWeight: 600,
      maxWidth: 340,
    }}>
      {ok ? '✓ ' : '✗ '}{message}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────
export default function UsersPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const [users, setUsers]               = useState<PrivilegedUser[]>([]);
  const [loading, setLoading]           = useState(true);
  const [search, setSearch]             = useState('');
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null);
  const [posture, setPosture]           = useState<RiskPosture | null>(null);

  const [signIns, setSignIns]           = useState<any[]>([]);
  const [signInsLoading, setSignInsLoading] = useState(false);

  const [confirmAction, setConfirmAction] = useState<ConfirmAction | null>(null);
  const [toast, setToast]               = useState<{ message: string; ok: boolean } | null>(null);
  const [actionPending, setActionPending] = useState<string | null>(null);

  // Load users + posture
  useEffect(() => {
    Promise.all([
      api.getUsers().catch(() => [] as PrivilegedUser[]),
      api.getRiskPosture().catch(() => null),
    ]).then(([u, p]) => {
      let sorted = (u as PrivilegedUser[]).sort((a, b) =>
        RISK_ORDER.indexOf(a.riskLevel) - RISK_ORDER.indexOf(b.riskLevel)
      );
      if (sorted.length === 0 && (p as any)?.mostRiskyAdmins?.length) {
        const toRisk = (s: number) => s >= 75 ? 'critical' : s >= 50 ? 'high' : s >= 25 ? 'medium' : s > 0 ? 'low' : 'clean';
        sorted = ((p as any).mostRiskyAdmins as any[]).map(a => ({
          id: a.userId || a.id,
          displayName: a.displayName || '',
          userPrincipalName: a.userPrincipalName || a.email || '',
          roles: a.roles || [],
          riskLevel: toRisk(a.score || 0),
          alertCount: a.openAlerts ?? a.alertCount ?? 0,
          accountEnabled: true,
          lastAlert: undefined,
        } as PrivilegedUser));
      }
      setUsers(sorted);
      setPosture(p as RiskPosture | null);
      const urlId = searchParams.get('userId');
      const match = urlId ? sorted.find(u => u.id === urlId) : null;
      setSelectedUserId(match?.id ?? sorted[0]?.id ?? null);
    }).finally(() => setLoading(false));
  }, []);

  // Load sign-ins when selected user changes
  useEffect(() => {
    if (!selectedUserId) { setSignIns([]); return; }
    setSignInsLoading(true);
    api.getUserSignIns(selectedUserId)
      .then(data => setSignIns(Array.isArray(data) ? data.slice(0, 12) : []))
      .catch(() => setSignIns([]))
      .finally(() => setSignInsLoading(false));
  }, [selectedUserId]);

  const handleRevoke = (user: PrivilegedUser) => {
    setConfirmAction({
      title: `Revoke sessions for ${user.displayName}?`,
      body: 'This forces MFA re-authentication on next sign-in. The user will be immediately signed out of all active sessions.',
      confirmLabel: 'Revoke Sessions',
      danger: true,
      onConfirm: async () => {
        setActionPending(user.id + ':revoke');
        try {
          const r = await api.revokeUserSessions(user.id);
          setToast({ message: r.message || 'Sessions revoked', ok: true });
        } catch (e: any) {
          setToast({ message: e.message || 'Failed', ok: false });
        } finally { setActionPending(null); }
      },
    });
  };

  const handleDisable = (user: PrivilegedUser) => {
    const action = user.accountEnabled ? 'disable' : 're-enable';
    setConfirmAction({
      title: `${user.accountEnabled ? 'Disable' : 'Re-enable'} account for ${user.displayName}?`,
      body: user.accountEnabled
        ? 'The account will be blocked from sign-in immediately. Existing sessions may persist until token expiry.'
        : 'The account will be restored. The user can sign in immediately.',
      confirmLabel: user.accountEnabled ? 'Disable Account' : 'Re-enable Account',
      danger: user.accountEnabled,
      onConfirm: async () => {
        setActionPending(user.id + ':disable');
        try {
          const r = await (user.accountEnabled ? api.disableUser(user.id) : api.enableUser(user.id));
          setToast({ message: r.message || `Account ${action}d`, ok: true });
          setUsers(prev => prev.map(u => u.id === user.id ? { ...u, accountEnabled: !u.accountEnabled } : u));
        } catch (e: any) {
          setToast({ message: e.message || 'Failed', ok: false });
        } finally { setActionPending(null); }
      },
    });
  };

  const filtered = useMemo(() => users.filter(u =>
    !search ||
    u.displayName.toLowerCase().includes(search.toLowerCase()) ||
    u.userPrincipalName.toLowerCase().includes(search.toLowerCase()) ||
    u.roles.some(r => r.toLowerCase().includes(search.toLowerCase()))
  ), [search, users]);

  const selectedUser = filtered.find(u => u.id === selectedUserId) || filtered[0] || null;

  const stats = useMemo(() => ({
    risky:     users.filter(u => u.riskLevel !== 'clean').length,
    threats:   users.filter(u => u.alertCount > 0).length,
    multiRole: users.filter(u => u.roles.length > 1).length,
    disabled:  users.filter(u => !u.accountEnabled).length,
  }), [users]);

  const selectedPosture = posture?.mostRiskyAdmins?.find(p => p.userId === selectedUser?.id);
  const selectedBlast   = selectedUser ? blastRadius(selectedUser.roles.map(r => parseRole(r).name)) : null;

  if (loading) return (
    <div className="loading-state">
      <div className="loading-spinner" />
      <div className="loading-text">Loading privileged users…</div>
    </div>
  );

  return (
    <div>
      {confirmAction && (
        <ConfirmModal action={confirmAction} onDismiss={() => setConfirmAction(null)} />
      )}
      {toast && (
        <ResultToast message={toast.message} ok={toast.ok} onDismiss={() => setToast(null)} />
      )}

      {/* ── Header ───────────────────────────────────────────────────── */}
      <div className="page-header">
        <div>
          <div className="page-title">Exposure Center</div>
          <div className="page-subtitle">
            {users.length} privileged identities monitored for exposure, blast radius, and response readiness
          </div>
        </div>
      </div>

      {/* ── Stats ────────────────────────────────────────────────────── */}
      <div className="stats-grid" style={{ marginBottom: 20 }}>
        <div className="stat-card critical"><div className="stat-value">{stats.risky}</div><div className="stat-label">Risky identities</div></div>
        <div className="stat-card medium"><div className="stat-value">{stats.threats}</div><div className="stat-label">With open threats</div></div>
        <div className="stat-card amber"><div className="stat-value">{stats.multiRole}</div><div className="stat-label">Multi-role exposure</div></div>
        <div className="stat-card neutral"><div className="stat-value">{stats.disabled}</div><div className="stat-label">Disabled accounts</div></div>
      </div>

      {/* ── Filter ───────────────────────────────────────────────────── */}
      <div className="filter-bar">
        <input
          className="filter-input"
          placeholder="Search by name, role, or UPN…"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        <div style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>
          {filtered.length} identities
        </div>
      </div>

      {/* ── Split layout ─────────────────────────────────────────────── */}
      <div className="two-col exposure-layout">

        {/* ── Left: Watchlist table ─────────────────────────────────── */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">Privileged Identity Watchlist</div>
            <span className="role-tag">Ordered by risk</span>
          </div>
          <table className="data-table">
            <thead>
              <tr>
                <th>Risk</th>
                <th>User</th>
                <th>Roles</th>
                <th>Account</th>
                <th>Threats</th>
                <th>Score</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(user => {
                const parsedRoles = user.roles.map(parseRole);
                const isCritical = parsedRoles.some(r => CRITICAL_ROLES.includes(r.name));
                return (
                  <tr
                    key={user.id}
                    onClick={() => setSelectedUserId(user.id)}
                    className={selectedUserId === user.id ? 'selected-row' : ''}
                    style={{ cursor: 'pointer' }}
                  >
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                        <span className="risk-dot" style={{
                          background: severityColor(user.riskLevel),
                          boxShadow: user.riskLevel !== 'clean' ? `0 0 6px ${severityColor(user.riskLevel)}` : 'none',
                        }} />
                        <span style={{
                          color: severityColor(user.riskLevel),
                          fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700, textTransform: 'uppercase',
                        }}>
                          {user.riskLevel}
                        </span>
                      </div>
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                        {isCritical && (
                          <span title="Critical role" style={{ fontSize: 12 }}>👑</span>
                        )}
                        <div>
                          <div style={{ fontWeight: 600 }}>{user.displayName}</div>
                          <div className="text-muted mono" style={{ fontSize: 11 }}>{user.userPrincipalName}</div>
                        </div>
                      </div>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                        {parsedRoles.slice(0, 2).map(r => (
                          <span key={r.name + r.isEligible} className="role-tag" style={
                            CRITICAL_ROLES.includes(r.name)
                              ? { background: 'rgba(239,68,68,0.12)', color: '#EF4444', borderColor: 'rgba(239,68,68,0.3)' }
                              : r.isEligible
                              ? { background: 'rgba(155,138,251,0.1)', color: '#9B8AFB', borderColor: 'rgba(155,138,251,0.3)' }
                              : {}
                          }>
                            {r.name.replace(' Administrator', ' Admin')}
                            {r.isEligible && <span style={{ fontSize: 9, marginLeft: 3, opacity: 0.8 }}>JIT</span>}
                          </span>
                        ))}
                        {parsedRoles.length > 2 && <span className="text-muted" style={{ fontSize: 11 }}>+{parsedRoles.length - 2}</span>}
                      </div>
                    </td>
                    <td>
                      <span style={{
                        padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600,
                        background: user.accountEnabled ? 'rgba(52,201,125,0.1)' : 'rgba(239,68,68,0.1)',
                        color: user.accountEnabled ? '#34C97D' : '#EF4444',
                        border: `1px solid ${user.accountEnabled ? 'rgba(52,201,125,0.3)' : 'rgba(239,68,68,0.3)'}`,
                      }}>
                        {user.accountEnabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </td>
                    <td>
                      <span style={{
                        fontFamily: 'var(--font-mono)', fontSize: 15, fontWeight: 700,
                        color: user.alertCount > 0 ? '#EF4444' : 'var(--text-muted)',
                      }}>
                        {user.alertCount}
                      </span>
                    </td>
                    <td>
                      <span className="role-tag">{posture?.mostRiskyAdmins.find(p => p.userId === user.id)?.score ?? 0}</span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {filtered.length === 0 && (
            <div className="empty-state">
              <div className="empty-icon">👤</div>
              <div className="empty-text">No identities matched</div>
              <div className="text-muted" style={{ fontSize: 12 }}>Try a different name, role, or UPN.</div>
            </div>
          )}
        </div>

        {/* ── Right: Drill-down panel ───────────────────────────────── */}
        <div className="card sticky-panel">
          {!selectedUser ? (
            <div className="empty-state" style={{ padding: 32 }}>
              <div className="empty-icon">🧭</div>
              <div className="empty-text">Select an identity to investigate</div>
            </div>
          ) : (
            <>
              {/* Header */}
              <div style={{ marginBottom: 14 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <span style={{
                    width: 10, height: 10, borderRadius: '50%', flexShrink: 0,
                    background: severityColor(selectedUser.riskLevel),
                    boxShadow: `0 0 8px ${severityColor(selectedUser.riskLevel)}`,
                  }} />
                  <span style={{ fontWeight: 700, fontSize: 16 }}>{selectedUser.displayName}</span>
                  {selectedUser.roles.map(parseRole).some(r => CRITICAL_ROLES.includes(r.name)) && (
                    <span style={{ fontSize: 13 }}>👑</span>
                  )}
                </div>
                <div className="text-muted mono" style={{ fontSize: 11, marginBottom: 10 }}>
                  {selectedUser.userPrincipalName}
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                  {selectedUser.roles.map(parseRole).map(r => (
                    <span key={r.name + r.isEligible} className="role-tag" style={
                      CRITICAL_ROLES.includes(r.name)
                        ? { background: 'rgba(239,68,68,0.12)', color: '#EF4444', borderColor: 'rgba(239,68,68,0.3)' }
                        : r.isEligible
                        ? { background: 'rgba(155,138,251,0.1)', color: '#9B8AFB', borderColor: 'rgba(155,138,251,0.3)' }
                        : {}
                    }>
                      {r.name.replace(' Administrator', ' Admin')}
                      {r.isEligible
                        ? <span style={{ marginLeft: 4, fontSize: 9, opacity: 0.8, fontWeight: 700 }}>JIT</span>
                        : <span style={{ marginLeft: 4, fontSize: 9, opacity: 0.5 }}>PERM</span>
                      }
                    </span>
                  ))}
                  {selectedUser.roles.length === 0 && <span className="text-muted" style={{ fontSize: 11 }}>No roles</span>}
                </div>
              </div>

              {/* 3-stat mini grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8, marginBottom: 14 }}>
                {[
                  { label: 'Open threats', value: selectedUser.alertCount, color: selectedUser.alertCount > 0 ? '#EF4444' : '#34C97D' },
                  { label: 'Risk score',   value: selectedPosture?.score ?? 0, color: (selectedPosture?.score ?? 0) >= 70 ? '#EF4444' : (selectedPosture?.score ?? 0) >= 40 ? '#F97316' : '#34C97D' },
                  { label: 'Countries',    value: selectedPosture?.baseline?.knownCountries?.length ?? '—', color: 'var(--text-primary)' },
                ].map(s => (
                  <div key={s.label} style={{ background: 'var(--navy-bg)', borderRadius: 8, padding: '10px 12px', textAlign: 'center' }}>
                    <div style={{ fontSize: 20, fontWeight: 700, color: s.color }}>{s.value}</div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>{s.label}</div>
                  </div>
                ))}
              </div>

              {/* Blast radius callout */}
              {selectedBlast && (
                <div style={{
                  borderLeft: `4px solid ${selectedBlast.color}`,
                  background: `${selectedBlast.color}10`,
                  borderRadius: '0 8px 8px 0',
                  padding: '10px 14px',
                  marginBottom: 14,
                }}>
                  <div style={{ fontWeight: 700, fontSize: 13, color: selectedBlast.color, marginBottom: 3 }}>
                    Blast Radius: {selectedBlast.label}
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{selectedBlast.detail}</div>
                </div>
              )}

              {/* Baseline countries */}
              <div style={{ marginBottom: 14 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                  <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Baseline Countries
                  </div>
                  {selectedUser && (
                    <button
                      className="btn btn-ghost btn-sm"
                      style={{ fontSize: 10, padding: '2px 8px', opacity: 0.7 }}
                      title="Clear behavioral baseline — system will re-learn on next scan"
                      onClick={async () => {
                        if (!window.confirm(`Reset behavioral baseline for ${selectedUser.displayName}? The system will re-learn their normal patterns from the next scan.`)) return;
                        try {
                          await api.resetUserBaseline(selectedUser.id);
                          window.alert('Baseline cleared — will re-learn on next scan.');
                        } catch (e: any) {
                          window.alert('Failed: ' + e.message);
                        }
                      }}
                    >
                      ↺ Reset baseline
                    </button>
                  )}
                </div>
                {(selectedPosture?.baseline?.knownCountries?.length ?? 0) > 0 ? (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                    {selectedPosture!.baseline.knownCountries.map((c: string) => (
                      <span key={c} className="role-tag">{c}</span>
                    ))}
                  </div>
                ) : (
                  <div className="text-muted" style={{ fontSize: 12 }}>No baseline yet — will build on next scan</div>
                )}
              </div>

              {/* Recent sign-ins */}
              <div style={{ marginBottom: 14 }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Recent Sign-ins
                </div>
                {signInsLoading ? (
                  <div className="text-muted" style={{ fontSize: 12, padding: '8px 0' }}>Loading…</div>
                ) : signIns.length === 0 ? (
                  <div className="text-muted" style={{ fontSize: 12, padding: '8px 0' }}>No sign-in history available.</div>
                ) : (
                  <div style={{ maxHeight: 220, overflowY: 'auto' }}>
                    {signIns.map((s, i) => <SignInRow key={i} signIn={s} />)}
                  </div>
                )}
              </div>

              {/* Actions */}
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 4 }}>
                <button
                  className="btn btn-danger btn-sm"
                  onClick={() => handleRevoke(selectedUser)}
                  disabled={actionPending === selectedUser.id + ':revoke'}
                >
                  {actionPending === selectedUser.id + ':revoke' ? '⟳' : '⊘'} Revoke Sessions
                </button>
                <button
                  className="btn btn-sm"
                  style={{
                    background: selectedUser.accountEnabled ? 'rgba(239,68,68,0.1)' : 'rgba(52,201,125,0.1)',
                    color: selectedUser.accountEnabled ? '#EF4444' : '#34C97D',
                    border: `1px solid ${selectedUser.accountEnabled ? 'rgba(239,68,68,0.3)' : 'rgba(52,201,125,0.3)'}`,
                  }}
                  onClick={() => handleDisable(selectedUser)}
                  disabled={actionPending === selectedUser.id + ':disable'}
                >
                  {actionPending === selectedUser.id + ':disable'
                    ? '⟳'
                    : selectedUser.accountEnabled ? '🔒 Disable' : '🔓 Enable'}
                </button>
                <button
                  className="btn btn-ghost btn-sm"
                  onClick={() => navigate(`/alerts?userId=${selectedUser.id}`)}
                  style={{ marginLeft: 'auto' }}
                >
                  View Alerts →
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
