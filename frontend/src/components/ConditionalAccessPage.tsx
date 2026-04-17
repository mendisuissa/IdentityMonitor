import React, { useEffect, useState } from 'react';
import { apiFetch } from '../services/api';

type CaTab = 'policies' | 'quickactions' | 'locations';

interface CaPolicy {
  id: string;
  displayName: string;
  state: string;
  createdDateTime?: string;
  modifiedDateTime?: string;
  conditions?: any;
}

interface NamedLocation {
  id: string;
  displayName: string;
  '@odata.type'?: string;
  ipRanges?: Array<{ cidrAddress: string }>;
  countriesAndRegions?: string[];
  isTrusted?: boolean;
}

interface QuickActionResult {
  ok: boolean;
  message: string;
}

function StateBadge({ state }: { state: string }) {
  if (state === 'enabled') {
    return (
      <span
        className="severity-badge"
        style={{ background: 'var(--green-clean)', color: '#fff', fontSize: 11 }}
      >
        Enabled
      </span>
    );
  }
  if (state === 'enabledForReportingButNotEnforced') {
    return (
      <span
        className="severity-badge"
        style={{ background: 'var(--amber-400)', color: '#000', fontSize: 11 }}
      >
        Report only
      </span>
    );
  }
  return (
    <span
      className="severity-badge"
      style={{ background: 'var(--red-critical)', color: '#fff', fontSize: 11 }}
    >
      Disabled
    </span>
  );
}

function ConditionsSummary({ conditions }: { conditions?: any }) {
  if (!conditions) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>;
  const parts: string[] = [];
  if (conditions.users?.includeUsers?.length) parts.push(`Users: ${conditions.users.includeUsers.slice(0, 2).join(', ')}${conditions.users.includeUsers.length > 2 ? '…' : ''}`);
  if (conditions.users?.includeGroups?.length) parts.push(`${conditions.users.includeGroups.length} group(s)`);
  if (conditions.applications?.includeApplications?.length) {
    const apps = conditions.applications.includeApplications;
    parts.push(apps[0] === 'All' ? 'All apps' : `${apps.length} app(s)`);
  }
  if (conditions.locations?.includeLocations?.length) parts.push('Location filter');
  if (conditions.platforms?.includePlatforms?.length) parts.push(`Platforms: ${conditions.platforms.includePlatforms.join(', ')}`);
  return (
    <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
      {parts.length ? parts.join(' · ') : 'No conditions'}
    </span>
  );
}

export default function ConditionalAccessPage() {
  const [tab, setTab] = useState<CaTab>('policies');
  const [dismissedBanner, setDismissedBanner] = useState(false);
  const [permissionError, setPermissionError] = useState(false);

  // Policies tab
  const [policies, setPolicies] = useState<CaPolicy[]>([]);
  const [policiesLoading, setPoliciesLoading] = useState(false);
  const [policiesError, setPoliciesError] = useState('');
  const [togglingId, setTogglingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);

  // Locations tab
  const [locations, setLocations] = useState<NamedLocation[]>([]);
  const [locationsLoading, setLocationsLoading] = useState(false);
  const [locationsError, setLocationsError] = useState('');

  // Quick actions
  const [blockIp, setBlockIp] = useState({ ip: '', locationName: '' });
  const [blockIpResult, setBlockIpResult] = useState<QuickActionResult | null>(null);
  const [blockIpBusy, setBlockIpBusy] = useState(false);

  const [mfaUser, setMfaUser] = useState({ userId: '', policyName: '' });
  const [mfaResult, setMfaResult] = useState<QuickActionResult | null>(null);
  const [mfaBusy, setMfaBusy] = useState(false);

  const [blockUser, setBlockUser] = useState({ userId: '', policyName: '' });
  const [blockUserResult, setBlockUserResult] = useState<QuickActionResult | null>(null);
  const [blockUserBusy, setBlockUserBusy] = useState(false);

  const handle403 = (err: any) => {
    if (err?.status === 403 || String(err?.message).includes('403') || String(err?.message).toLowerCase().includes('permission')) {
      setPermissionError(true);
    }
  };

  const loadPolicies = async () => {
    setPoliciesLoading(true);
    setPoliciesError('');
    try {
      const data = await apiFetch<any>('/identity/ca-policies');
      setPolicies(Array.isArray(data) ? data : (data?.value || []));
    } catch (err: any) {
      handle403(err);
      setPoliciesError(err?.message || 'Failed to load policies');
    } finally {
      setPoliciesLoading(false);
    }
  };

  const loadLocations = async () => {
    setLocationsLoading(true);
    setLocationsError('');
    try {
      const data = await apiFetch<any>('/identity/named-locations');
      setLocations(Array.isArray(data) ? data : (data?.value || []));
    } catch (err: any) {
      handle403(err);
      setLocationsError(err?.message || 'Failed to load named locations');
    } finally {
      setLocationsLoading(false);
    }
  };

  useEffect(() => {
    if (tab === 'policies') loadPolicies();
    if (tab === 'locations') loadLocations();
  }, [tab]);

  const togglePolicy = async (policy: CaPolicy) => {
    const newState = policy.state === 'enabled' ? 'disabled' : 'enabled';
    setTogglingId(policy.id);
    try {
      await apiFetch(`/identity/ca-policies/${policy.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ state: newState }),
      });
      setPolicies(prev => prev.map(p => p.id === policy.id ? { ...p, state: newState } : p));
    } catch (err: any) {
      handle403(err);
    } finally {
      setTogglingId(null);
    }
  };

  const deletePolicy = async (id: string) => {
    setDeletingId(id);
    setDeleteConfirmId(null);
    try {
      await apiFetch(`/identity/ca-policies/${id}`, { method: 'DELETE' });
      setPolicies(prev => prev.filter(p => p.id !== id));
    } catch (err: any) {
      handle403(err);
    } finally {
      setDeletingId(null);
    }
  };

  const submitBlockIp = async () => {
    if (!blockIp.ip.trim()) return;
    setBlockIpBusy(true);
    setBlockIpResult(null);
    try {
      const res = await apiFetch<any>('/identity/block-ip', {
        method: 'POST',
        body: JSON.stringify({
          ipAddress: blockIp.ip.trim(),
          locationName: blockIp.locationName.trim() || 'IdentityMonitor-Blocked-IPs',
        }),
      });
      setBlockIpResult({ ok: true, message: res?.message || 'IP blocked successfully.' });
    } catch (err: any) {
      handle403(err);
      setBlockIpResult({ ok: false, message: err?.message || 'Failed to block IP.' });
    } finally {
      setBlockIpBusy(false);
    }
  };

  const submitMfa = async () => {
    if (!mfaUser.userId.trim()) return;
    setMfaBusy(true);
    setMfaResult(null);
    try {
      const res = await apiFetch<any>('/identity/require-mfa', {
        method: 'POST',
        body: JSON.stringify({
          userId: mfaUser.userId.trim(),
          policyName: mfaUser.policyName.trim() || undefined,
        }),
      });
      setMfaResult({ ok: true, message: res?.message || 'MFA policy applied successfully.' });
    } catch (err: any) {
      handle403(err);
      setMfaResult({ ok: false, message: err?.message || 'Failed to apply MFA policy.' });
    } finally {
      setMfaBusy(false);
    }
  };

  const submitBlockUser = async () => {
    if (!blockUser.userId.trim()) return;
    setBlockUserBusy(true);
    setBlockUserResult(null);
    try {
      const res = await apiFetch<any>('/identity/block-user', {
        method: 'POST',
        body: JSON.stringify({
          userId: blockUser.userId.trim(),
          policyName: blockUser.policyName.trim() || undefined,
        }),
      });
      setBlockUserResult({ ok: true, message: res?.message || 'User blocked successfully.' });
    } catch (err: any) {
      handle403(err);
      setBlockUserResult({ ok: false, message: err?.message || 'Failed to block user.' });
    } finally {
      setBlockUserBusy(false);
    }
  };

  const tabs: Array<{ id: CaTab; label: string; icon: string }> = [
    { id: 'policies', label: 'Policies', icon: '🛡️' },
    { id: 'quickactions', label: 'Quick Actions', icon: '⚡' },
    { id: 'locations', label: 'Named Locations', icon: '📍' },
  ];

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Conditional Access</div>
          <div className="page-subtitle">Manage CA policies, block IPs, enforce MFA, and view named locations</div>
        </div>
      </div>

      {/* Permission warning banner */}
      {!dismissedBanner && (
        <div
          style={{
            background: 'rgba(245,166,35,0.12)',
            border: '1px solid var(--amber-400)',
            borderRadius: 8,
            padding: '10px 16px',
            marginBottom: 16,
            display: 'flex',
            alignItems: 'flex-start',
            gap: 12,
          }}
        >
          <span style={{ fontSize: 16 }}>ℹ️</span>
          <div style={{ flex: 1, fontSize: 13, color: 'var(--text-secondary)' }}>
            Conditional Access policies require{' '}
            <strong>ConditionalAccessPolicy.ReadWrite.All</strong> permission. If you see errors, go
            to Settings → re-grant admin consent.
          </div>
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => setDismissedBanner(true)}
            style={{ flexShrink: 0 }}
          >
            ×
          </button>
        </div>
      )}

      {/* 403 permission error banner */}
      {permissionError && (
        <div
          style={{
            background: 'rgba(255,59,59,0.12)',
            border: '1px solid var(--red-critical)',
            borderRadius: 8,
            padding: '10px 16px',
            marginBottom: 16,
            fontSize: 13,
            color: 'var(--text-secondary)',
          }}
        >
          <strong>Missing permission:</strong> ConditionalAccessPolicy.ReadWrite.All — Re-grant
          admin consent to enable CA management.{' '}
          <a
            href="/api/auth/admin-consent"
            style={{ color: 'var(--amber-400)', textDecoration: 'underline' }}
          >
            Re-grant admin consent
          </a>
        </div>
      )}

      {/* Tab bar */}
      <div
        style={{
          display: 'flex',
          gap: 6,
          marginBottom: 18,
          borderBottom: '1px solid var(--navy-border)',
          overflowX: 'auto',
          paddingBottom: 2,
        }}
      >
        {tabs.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`btn btn-sm ${tab === t.id ? 'btn-primary' : 'btn-ghost'}`}
            style={{ whiteSpace: 'nowrap' }}
          >
            {t.icon} {t.label}
          </button>
        ))}
      </div>

      {/* ── Policies tab ── */}
      {tab === 'policies' && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">Conditional Access Policies</div>
            <button className="btn btn-ghost btn-sm" onClick={loadPolicies}>
              Refresh
            </button>
          </div>

          {policiesLoading && (
            <div className="loading-state">
              <div className="loading-spinner" />
            </div>
          )}

          {!policiesLoading && policiesError && (
            <div style={{ color: 'var(--red-critical)', fontSize: 13, padding: '12px 0' }}>
              {policiesError}
            </div>
          )}

          {!policiesLoading && !policiesError && policies.length === 0 && (
            <div className="empty-state">
              <div>No conditional access policies found.</div>
            </div>
          )}

          {!policiesLoading && policies.length > 0 && (
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Policy Name</th>
                    <th>State</th>
                    <th>Conditions</th>
                    <th>Created / Modified</th>
                    <th style={{ width: 160 }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {policies.map(policy => (
                    <tr key={policy.id}>
                      <td>
                        <span style={{ fontWeight: 600 }}>{policy.displayName}</span>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                          {policy.id}
                        </div>
                      </td>
                      <td>
                        <StateBadge state={policy.state} />
                      </td>
                      <td>
                        <ConditionsSummary conditions={policy.conditions} />
                      </td>
                      <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                        {policy.createdDateTime
                          ? new Date(policy.createdDateTime).toLocaleDateString()
                          : '—'}
                        {policy.modifiedDateTime && (
                          <div>
                            Mod: {new Date(policy.modifiedDateTime).toLocaleDateString()}
                          </div>
                        )}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 6 }}>
                          <button
                            className="btn btn-ghost btn-sm"
                            disabled={togglingId === policy.id}
                            onClick={() => togglePolicy(policy)}
                          >
                            {togglingId === policy.id
                              ? '…'
                              : policy.state === 'enabled'
                              ? 'Disable'
                              : 'Enable'}
                          </button>
                          {deleteConfirmId === policy.id ? (
                            <>
                              <button
                                className="btn btn-danger btn-sm"
                                disabled={deletingId === policy.id}
                                onClick={() => deletePolicy(policy.id)}
                              >
                                {deletingId === policy.id ? '…' : 'Confirm'}
                              </button>
                              <button
                                className="btn btn-ghost btn-sm"
                                onClick={() => setDeleteConfirmId(null)}
                              >
                                Cancel
                              </button>
                            </>
                          ) : (
                            <button
                              className="btn btn-danger btn-sm"
                              onClick={() => setDeleteConfirmId(policy.id)}
                            >
                              Delete
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ── Quick Actions tab ── */}
      {tab === 'quickactions' && (
        <div style={{ display: 'grid', gap: 16 }}>

          {/* Card 1: Block IP */}
          <div className="card">
            <div className="card-header">
              <div className="card-title">🚫 Block IP Address</div>
            </div>
            <div style={{ display: 'grid', gap: 10, maxWidth: 480 }}>
              <div>
                <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
                  IP Address *
                </label>
                <input
                  className="input"
                  placeholder="e.g. 1.2.3.4 or 1.2.3.0/24"
                  value={blockIp.ip}
                  onChange={e => setBlockIp(prev => ({ ...prev, ip: e.target.value }))}
                />
              </div>
              <div>
                <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
                  Named Location (optional, defaults to "IdentityMonitor-Blocked-IPs")
                </label>
                <input
                  className="input"
                  placeholder="IdentityMonitor-Blocked-IPs"
                  value={blockIp.locationName}
                  onChange={e => setBlockIp(prev => ({ ...prev, locationName: e.target.value }))}
                />
              </div>
              <div>
                <button
                  className="btn btn-primary"
                  disabled={blockIpBusy || !blockIp.ip.trim()}
                  onClick={submitBlockIp}
                >
                  {blockIpBusy ? 'Blocking…' : 'Block IP'}
                </button>
              </div>
              {blockIpResult && (
                <div
                  style={{
                    padding: '8px 12px',
                    borderRadius: 6,
                    fontSize: 13,
                    background: blockIpResult.ok ? 'rgba(46,204,113,0.12)' : 'rgba(255,59,59,0.12)',
                    border: `1px solid ${blockIpResult.ok ? 'var(--green-clean)' : 'var(--red-critical)'}`,
                    color: blockIpResult.ok ? 'var(--green-clean)' : 'var(--red-critical)',
                  }}
                >
                  {blockIpResult.message}
                </div>
              )}
            </div>
          </div>

          {/* Card 2: Require MFA */}
          <div className="card">
            <div className="card-header">
              <div className="card-title">🔐 Require MFA for User</div>
            </div>
            <div style={{ display: 'grid', gap: 10, maxWidth: 480 }}>
              <div>
                <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
                  User ID (objectId or UPN) *
                </label>
                <input
                  className="input"
                  placeholder="user@company.com or object-id"
                  value={mfaUser.userId}
                  onChange={e => setMfaUser(prev => ({ ...prev, userId: e.target.value }))}
                />
              </div>
              <div>
                <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
                  Policy Name (optional)
                </label>
                <input
                  className="input"
                  placeholder="e.g. Require-MFA-TargetedUser"
                  value={mfaUser.policyName}
                  onChange={e => setMfaUser(prev => ({ ...prev, policyName: e.target.value }))}
                />
              </div>
              <div>
                <button
                  className="btn btn-primary"
                  disabled={mfaBusy || !mfaUser.userId.trim()}
                  onClick={submitMfa}
                >
                  {mfaBusy ? 'Applying…' : 'Require MFA'}
                </button>
              </div>
              {mfaResult && (
                <div
                  style={{
                    padding: '8px 12px',
                    borderRadius: 6,
                    fontSize: 13,
                    background: mfaResult.ok ? 'rgba(46,204,113,0.12)' : 'rgba(255,59,59,0.12)',
                    border: `1px solid ${mfaResult.ok ? 'var(--green-clean)' : 'var(--red-critical)'}`,
                    color: mfaResult.ok ? 'var(--green-clean)' : 'var(--red-critical)',
                  }}
                >
                  {mfaResult.message}
                </div>
              )}
            </div>
          </div>

          {/* Card 3: Emergency Block User */}
          <div className="card" style={{ borderColor: 'var(--red-critical)' }}>
            <div className="card-header">
              <div className="card-title">🔒 Emergency Block User</div>
            </div>
            <div
              style={{
                padding: '8px 12px',
                marginBottom: 14,
                borderRadius: 6,
                background: 'rgba(255,59,59,0.10)',
                border: '1px solid var(--red-critical)',
                fontSize: 13,
                color: 'var(--red-critical)',
              }}
            >
              This blocks ALL sign-ins for the specified user immediately.
            </div>
            <div style={{ display: 'grid', gap: 10, maxWidth: 480 }}>
              <div>
                <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
                  User ID (objectId or UPN) *
                </label>
                <input
                  className="input"
                  placeholder="user@company.com or object-id"
                  value={blockUser.userId}
                  onChange={e => setBlockUser(prev => ({ ...prev, userId: e.target.value }))}
                />
              </div>
              <div>
                <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
                  Policy Name (optional)
                </label>
                <input
                  className="input"
                  placeholder="e.g. Emergency-Block-User"
                  value={blockUser.policyName}
                  onChange={e => setBlockUser(prev => ({ ...prev, policyName: e.target.value }))}
                />
              </div>
              <div>
                <button
                  className="btn btn-danger"
                  disabled={blockUserBusy || !blockUser.userId.trim()}
                  onClick={submitBlockUser}
                >
                  {blockUserBusy ? 'Blocking…' : 'Emergency Block'}
                </button>
              </div>
              {blockUserResult && (
                <div
                  style={{
                    padding: '8px 12px',
                    borderRadius: 6,
                    fontSize: 13,
                    background: blockUserResult.ok ? 'rgba(46,204,113,0.12)' : 'rgba(255,59,59,0.12)',
                    border: `1px solid ${blockUserResult.ok ? 'var(--green-clean)' : 'var(--red-critical)'}`,
                    color: blockUserResult.ok ? 'var(--green-clean)' : 'var(--red-critical)',
                  }}
                >
                  {blockUserResult.message}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Named Locations tab ── */}
      {tab === 'locations' && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">Named Locations</div>
            <button className="btn btn-ghost btn-sm" onClick={loadLocations}>
              Refresh
            </button>
          </div>

          {locationsLoading && (
            <div className="loading-state">
              <div className="loading-spinner" />
            </div>
          )}

          {!locationsLoading && locationsError && (
            <div style={{ color: 'var(--red-critical)', fontSize: 13, padding: '12px 0' }}>
              {locationsError}
            </div>
          )}

          {!locationsLoading && !locationsError && locations.length === 0 && (
            <div className="empty-state">
              <div>No named locations found.</div>
            </div>
          )}

          {!locationsLoading && locations.length > 0 && (
            <div style={{ display: 'grid', gap: 12 }}>
              {locations.map(loc => {
                const isIp =
                  loc['@odata.type'] === '#microsoft.graph.ipNamedLocation' ||
                  Array.isArray(loc.ipRanges);
                const isCountry =
                  loc['@odata.type'] === '#microsoft.graph.countryNamedLocation' ||
                  Array.isArray(loc.countriesAndRegions);

                return (
                  <div
                    key={loc.id}
                    style={{
                      padding: '12px 14px',
                      borderRadius: 8,
                      border: '1px solid var(--navy-border)',
                      background: 'var(--navy-800)',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                      <span style={{ fontSize: 16 }}>{isIp ? '🌐' : '🗺️'}</span>
                      <span style={{ fontWeight: 600 }}>{loc.displayName}</span>
                      {loc.isTrusted && (
                        <span
                          className="severity-badge"
                          style={{ background: 'var(--green-clean)', color: '#fff', fontSize: 10 }}
                        >
                          Trusted
                        </span>
                      )}
                    </div>

                    {isIp && loc.ipRanges && loc.ipRanges.length > 0 && (
                      <div>
                        <div
                          style={{
                            fontSize: 11,
                            color: 'var(--text-muted)',
                            textTransform: 'uppercase',
                            letterSpacing: '0.5px',
                            marginBottom: 6,
                          }}
                        >
                          IP Ranges ({loc.ipRanges.length})
                        </div>
                        <pre
                          style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: 12,
                            background: 'rgba(0,0,0,0.25)',
                            padding: '8px 10px',
                            borderRadius: 6,
                            margin: 0,
                            overflowX: 'auto',
                            color: 'var(--text-secondary)',
                          }}
                        >
                          {loc.ipRanges.map(r => r.cidrAddress).join('\n')}
                        </pre>
                      </div>
                    )}

                    {isCountry && loc.countriesAndRegions && loc.countriesAndRegions.length > 0 && (
                      <div>
                        <div
                          style={{
                            fontSize: 11,
                            color: 'var(--text-muted)',
                            textTransform: 'uppercase',
                            letterSpacing: '0.5px',
                            marginBottom: 6,
                          }}
                        >
                          Countries ({loc.countriesAndRegions.length})
                        </div>
                        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                          {loc.countriesAndRegions.map(cc => (
                            <span
                              key={cc}
                              className="role-tag"
                              style={{ fontSize: 12 }}
                            >
                              {cc}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {!isIp && !isCountry && (
                      <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                        {loc['@odata.type'] || 'Unknown location type'}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
