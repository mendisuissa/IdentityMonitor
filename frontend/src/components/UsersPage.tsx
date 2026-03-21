import React, { useEffect, useMemo, useState } from 'react';
import { api } from '../services/api';
import { PrivilegedUser, RiskPosture } from '../types';

const RISK_ORDER = ['critical', 'high', 'medium', 'low', 'clean'];

function severityColor(s: string) {
  return { critical: '#ff3b3b', high: '#ff6b35', medium: '#f5a623', low: '#4a90d9', clean: '#2ecc71' }[s] || '#8ba3cc';
}

export default function UsersPage() {
  const [users, setUsers] = useState<PrivilegedUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [disabling, setDisabling] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null);
  const [posture, setPosture] = useState<RiskPosture | null>(null);

  useEffect(() => {
    Promise.all([api.getUsers(), api.getRiskPosture().catch(() => null)]).then(([u, p]) => {
      const sorted = (u as PrivilegedUser[]).sort((a, b) =>
        RISK_ORDER.indexOf(a.riskLevel) - RISK_ORDER.indexOf(b.riskLevel)
      );
      setUsers(sorted);
      setSelectedUserId(sorted[0]?.id ?? null);
      setPosture(p as RiskPosture | null);
    }).finally(() => setLoading(false));
  }, []);

  const handleRevoke = async (user: PrivilegedUser) => {
    if (!window.confirm(`Revoke all sessions for ${user.displayName}?
This will force MFA re-authentication on their next sign-in.`)) return;
    setRevoking(user.id);
    try {
      const result = await api.revokeUserSessions(user.id);
      alert(result.message);
    } catch (err: any) {
      alert('Failed: ' + err.message);
    } finally {
      setRevoking(null);
    }
  };

  const handleDisable = async (user: PrivilegedUser) => {
    const action = user.accountEnabled ? 'disable' : 're-enable';
    if (!window.confirm(`${action === 'disable' ? 'Disable' : 'Re-enable'} account for ${user.displayName}?`)) return;
    setDisabling(user.id);
    try {
      const endpoint = user.accountEnabled ? 'disable' : 'enable';
      const res = await fetch(`/api/users/${user.id}/${endpoint}`, { method: 'POST', credentials: 'include' });
      const result = await res.json();
      alert(result.message);
      setUsers(prev => prev.map(u => u.id === user.id ? { ...u, accountEnabled: !u.accountEnabled } : u));
    } catch (err: any) {
      alert('Failed: ' + err.message);
    } finally { setDisabling(null); }
  };

  const filtered = useMemo(() => users.filter(u =>
    !search ||
    u.displayName.toLowerCase().includes(search.toLowerCase()) ||
    u.userPrincipalName.toLowerCase().includes(search.toLowerCase()) ||
    u.roles.some(role => role.toLowerCase().includes(search.toLowerCase()))
  ), [search, users]);

  const selectedUser = filtered.find(u => u.id === selectedUserId) || filtered[0] || null;
  const exposureStats = useMemo(() => ({
    risky: users.filter(u => u.riskLevel !== 'clean').length,
    openThreats: users.filter(u => u.alertCount > 0).length,
    disabled: users.filter(u => !u.accountEnabled).length,
    multiRole: users.filter(u => u.roles.length > 1).length,
  }), [users]);

  if (loading) return (
    <div className="loading-state">
      <div className="loading-spinner" />
      <div className="loading-text">Loading privileged users...</div>
    </div>
  );

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Exposure Center</div>
          <div className="page-subtitle">
            {users.length} privileged identities monitored for exposure, hygiene, blast radius, and response readiness
          </div>
        </div>
      </div>

      <div className="stats-grid" style={{ marginBottom: 20 }}>
        <div className="stat-card critical"><div className="stat-value">{exposureStats.risky}</div><div className="stat-label">Risky identities</div></div>
        <div className="stat-card medium"><div className="stat-value">{exposureStats.openThreats}</div><div className="stat-label">With open threats</div></div>
        <div className="stat-card amber"><div className="stat-value">{exposureStats.multiRole}</div><div className="stat-label">Multi-role exposure</div></div>
        <div className="stat-card neutral"><div className="stat-value">{exposureStats.disabled}</div><div className="stat-label">Disabled accounts</div></div>
      </div>

      <div className="filter-bar">
        <input
          className="filter-input"
          placeholder="Search privileged identity, role owner, or UPN..."
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        <div style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>
          {filtered.length} identities
        </div>
      </div>

      <div className="two-col exposure-layout">
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
                <th>Open Threats</th>
                <th>Risk Score</th>
                <th>Last Alert</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(user => (
                <tr key={user.id} onClick={() => setSelectedUserId(user.id)} className={selectedUserId === user.id ? 'selected-row' : ''} style={{ cursor: 'pointer' }}>
                  <td>
                    <div className="flex items-center gap-1">
                      <span className="risk-dot" style={{ background: severityColor(user.riskLevel), boxShadow: user.riskLevel !== 'clean' ? `0 0 6px ${severityColor(user.riskLevel)}` : 'none' }} />
                      <span style={{ color: severityColor(user.riskLevel), fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700, textTransform: 'uppercase' }}>
                        {user.riskLevel}
                      </span>
                    </div>
                  </td>
                  <td>
                    <div style={{ fontWeight: 600 }}>{user.displayName}</div>
                    <div className="text-muted mono" style={{ fontSize: 11 }}>{user.userPrincipalName}</div>
                  </td>
                  <td>
                    <div className="flex gap-1" style={{ flexWrap: 'wrap' }}>
                      {user.roles.slice(0, 2).map(r => (
                        <span key={r} className="role-tag">{r.replace(' Administrator', ' Admin')}</span>
                      ))}
                      {user.roles.length > 2 && <span className="text-muted" style={{ fontSize: 11 }}>+{user.roles.length - 2}</span>}
                    </div>
                  </td>
                  <td>
                    <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600, background: user.accountEnabled ? 'rgba(46,204,113,0.1)' : 'rgba(255,59,59,0.1)', color: user.accountEnabled ? '#2ecc71' : '#ff3b3b', border: `1px solid ${user.accountEnabled ? 'rgba(46,204,113,0.3)' : 'rgba(255,59,59,0.3)'}` }}>
                      {user.accountEnabled ? 'Enabled' : 'Disabled'}
                    </span>
                  </td>
                  <td><span style={{ fontFamily: 'var(--font-mono)', fontSize: 16, fontWeight: 700, color: user.alertCount > 0 ? 'var(--red-critical)' : 'var(--text-muted)' }}>{user.alertCount}</span></td>
                  <td><span className="role-tag">{posture?.mostRiskyAdmins.find(p => p.userId === user.id)?.score ?? 0}</span></td>
                  <td className="text-muted" style={{ fontSize: 12 }}>
                    {user.lastAlert ? <span className={`severity-badge ${user.lastAlert.severity}`}>{user.lastAlert.anomalyLabel}</span> : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {filtered.length === 0 && (
            <div className="empty-state">
              <div className="empty-icon">👤</div>
              <div className="empty-text">No privileged identities matched this filter</div>
              <div className="text-muted" style={{ fontSize: 12 }}>Try role name, user name, or UPN.</div>
            </div>
          )}
        </div>

        <div className="card sticky-panel">
          <div className="card-header">
            <div className="card-title">Exposure Drill-Down</div>
            <span className="role-tag">{selectedUser?.riskLevel || 'clean'}</span>
          </div>
          {!selectedUser ? (
            <div className="empty-state" style={{ padding: 32 }}>
              <div className="empty-icon">🧭</div>
              <div className="empty-text">Select an identity to investigate</div>
            </div>
          ) : (
            <>
              <div className="detail-stack">
                <DetailRow label="Identity" value={selectedUser.displayName} />
                <DetailRow label="UPN" value={selectedUser.userPrincipalName} mono />
                <DetailRow label="Roles" value={selectedUser.roles.join(', ') || 'None'} />
                <DetailRow label="Account state" value={selectedUser.accountEnabled ? 'Enabled' : 'Disabled'} />
                <DetailRow label="Open threats" value={String(selectedUser.alertCount)} mono />
                <DetailRow label="Risk score" value={String(posture?.mostRiskyAdmins.find(p => p.userId === selectedUser.id)?.score ?? 0)} mono />
                <DetailRow label="Last anomaly" value={selectedUser.lastAlert?.anomalyLabel || 'No recent alert'} />
              </div>

              <div className="callout-panel" style={{ marginTop: 14 }}>
                <div className="card-title" style={{ marginBottom: 6 }}>Exposure interpretation</div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                  {selectedUser.alertCount > 0
                    ? `${selectedUser.displayName} already has active threat history. Prioritize owner assignment, validate current access need, and be ready to revoke sessions if confidence remains high.`
                    : `${selectedUser.displayName} has no open threat queue right now. Use this view to validate role hygiene, permanent assignments, and whether every privileged role is still justified.`}
                </div>
              </div>

              <div className="action-list" style={{ marginTop: 14 }}>
                <div className="action-list-item">• Blast radius: {selectedUser.roles.length > 1 ? 'Elevated due to multiple privileged roles' : 'Moderate due to limited role spread'}</div>
                <div className="action-list-item">• Suggested next step: {selectedUser.alertCount > 0 ? 'Investigate active incidents and capture analyst notes.' : 'Review least-privilege and PIM eligibility.'}</div>
                <div className="action-list-item">• Hygiene signal: {selectedUser.accountEnabled ? 'Account is active and can be used immediately.' : 'Account is disabled, reducing active exposure.'}</div>
              </div>

              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 16 }}>
                <button className="btn btn-danger btn-sm" onClick={() => handleRevoke(selectedUser)} disabled={revoking === selectedUser.id}>
                  {revoking === selectedUser.id ? '⟳' : '⊘'} Revoke
                </button>
                <button className="btn btn-sm" style={{ background: selectedUser.accountEnabled ? 'rgba(255,59,59,0.1)' : 'rgba(46,204,113,0.1)', color: selectedUser.accountEnabled ? 'var(--red-critical)' : 'var(--green-clean)', border: `1px solid ${selectedUser.accountEnabled ? 'rgba(255,59,59,0.3)' : 'rgba(46,204,113,0.3)'}` }} onClick={() => handleDisable(selectedUser)} disabled={disabling === selectedUser.id}>
                  {disabling === selectedUser.id ? '⟳' : selectedUser.accountEnabled ? '🔒 Disable' : '🔓 Enable'}
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div style={{ display: 'flex', gap: 8, marginBottom: 4, fontSize: 12 }}>
      <span style={{ color: 'var(--text-muted)', minWidth: 90, flexShrink: 0 }}>{label}</span>
      <span style={{ fontFamily: mono ? 'var(--font-mono)' : undefined, fontSize: mono ? 11 : 12 }}>{value}</span>
    </div>
  );
}
