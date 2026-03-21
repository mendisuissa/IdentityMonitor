import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { SignIn } from '../types';
import { format } from 'date-fns';

const STATUS_SUCCESS = (s?: { errorCode: number }) => s?.errorCode === 0;

export default function SignInsPage() {
  const [signIns, setSignIns]   = useState<SignIn[]>([]);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState<{ message: string; hint?: string } | null>(null);
  const [hours, setHours]       = useState(24);
  const [search, setSearch]     = useState('');
  const [onlyFailed, setOnlyFailed] = useState(false);

  useEffect(() => {
    setLoading(true);
    setError(null);
    fetch(`/api/signins?hours=${hours}`, { credentials: 'include' })
      .then(async r => {
        const data = await r.json();
        if (!r.ok) {
          setError({ message: data.error || 'Failed to load sign-in logs', hint: data.hint });
          setSignIns([]);
        } else {
          setSignIns(data as SignIn[]);
        }
      })
      .catch(err => setError({ message: err.message }))
      .finally(() => setLoading(false));
  }, [hours]);

  const filtered = signIns.filter(s => {
    if (onlyFailed && STATUS_SUCCESS(s.status)) return false;
    if (!search) return true;
    return (
      s.userDisplayName?.toLowerCase().includes(search.toLowerCase()) ||
      s.userPrincipalName?.toLowerCase().includes(search.toLowerCase()) ||
      (s.ipAddress || '').includes(search) ||
      (s.location?.countryOrRegion || '').toLowerCase().includes(search.toLowerCase()) ||
      (s.appDisplayName || '').toLowerCase().includes(search.toLowerCase())
    );
  });

  const riskColor = (level?: string) =>
    ({ high: '#ff3b3b', medium: '#f5a623', low: '#4a90d9', none: '#2ecc71' }[level || 'none'] || '#8ba3cc');

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Sign-in Logs</div>
          <div className="page-subtitle">All privileged user authentication events</div>
        </div>
      </div>

      <div className="filter-bar">
        <select className="filter-select" value={hours} onChange={e => setHours(Number(e.target.value))}>
          <option value={6}>Last 6 hours</option>
          <option value={24}>Last 24 hours</option>
          <option value={48}>Last 48 hours</option>
          <option value={72}>Last 72 hours</option>
        </select>
        <input
          className="filter-input"
          placeholder="Search user, IP, country, app..."
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, color: 'var(--text-secondary)', cursor: 'pointer' }}>
          <input type="checkbox" checked={onlyFailed} onChange={e => setOnlyFailed(e.target.checked)} style={{ accentColor: 'var(--amber-500)' }} />
          Failed only
        </label>
        <div style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>
          {filtered.length} events
        </div>
      </div>

      {/* License/Permission Error */}
      {error && (
        <div className="card" style={{ borderLeft: '3px solid var(--yellow-medium)', marginBottom: 16 }}>
          <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
            <span style={{ fontSize: 24 }}>⚠️</span>
            <div>
              <div style={{ fontWeight: 700, marginBottom: 4, color: 'var(--amber-400)' }}>{error.message}</div>
              {error.hint && (
                <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{error.hint}</div>
              )}
              {error.message.includes('AuditLog') || error.message.includes('license') || error.hint ? (
                <div style={{ marginTop: 12, fontSize: 12, color: 'var(--text-muted)', background: 'var(--navy-800)', padding: '10px 14px', borderRadius: 'var(--radius-md)', border: '1px solid var(--navy-border)' }}>
                  <div style={{ fontWeight: 600, marginBottom: 6, color: 'var(--text-secondary)' }}>Required to view sign-in logs:</div>
                  <div>• Entra ID P1 or P2 license (or Microsoft 365 Business Premium)</div>
                  <div>• <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--amber-400)', fontSize: 11 }}>AuditLog.Read.All</span> application permission with admin consent</div>
                  <div style={{ marginTop: 8 }}>
                    <a href="https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Licenses" target="_blank" rel="noreferrer"
                      style={{ color: 'var(--amber-500)', fontSize: 12 }}>
                      → Check licenses in Entra Admin Center ↗
                    </a>
                  </div>
                </div>
              ) : null}
            </div>
          </div>
        </div>
      )}

      <div className="card" style={{ padding: 0 }}>
        {loading ? (
          <div className="loading-state"><div className="loading-spinner" /><div className="loading-text">Fetching sign-in logs...</div></div>
        ) : !error && filtered.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon">📋</div>
            <div className="empty-text">No sign-in events found</div>
            <div className="text-muted" style={{ fontSize: 12, marginTop: 4 }}>Try extending the time range</div>
          </div>
        ) : !error ? (
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Time</th>
                  <th>User</th>
                  <th>IP Address</th>
                  <th>Location</th>
                  <th>Device</th>
                  <th>Application</th>
                  <th>Risk</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(s => {
                  const success = STATUS_SUCCESS(s.status);
                  return (
                    <tr key={s.id}>
                      <td>
                        <span style={{
                          display: 'inline-flex', alignItems: 'center', gap: 4,
                          padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600,
                          background: success ? 'rgba(46,204,113,0.1)' : 'rgba(255,59,59,0.1)',
                          color: success ? '#2ecc71' : '#ff3b3b',
                          border: `1px solid ${success ? 'rgba(46,204,113,0.3)' : 'rgba(255,59,59,0.3)'}`
                        }}>
                          {success ? '✓' : '✗'} {success ? 'Success' : 'Failed'}
                        </span>
                      </td>
                      <td className="mono" style={{ fontSize: 11, whiteSpace: 'nowrap' }}>
                        {format(new Date(s.createdDateTime), 'MM/dd HH:mm:ss')}
                      </td>
                      <td>
                        <div style={{ fontWeight: 600, fontSize: 12 }}>{s.userDisplayName}</div>
                        <div className="text-muted" style={{ fontSize: 11 }}>{s.userPrincipalName}</div>
                      </td>
                      <td className="mono" style={{ fontSize: 11 }}>{s.ipAddress || '—'}</td>
                      <td style={{ fontSize: 12 }}>
                        {s.location?.city ? `${s.location.city}, ${s.location.countryOrRegion}` : s.location?.countryOrRegion || '—'}
                      </td>
                      <td style={{ fontSize: 12 }}>
                        <div>{s.deviceDetail?.displayName || '—'}</div>
                        {s.deviceDetail?.operatingSystem && (
                          <div className="text-muted" style={{ fontSize: 11 }}>{s.deviceDetail.operatingSystem}</div>
                        )}
                      </td>
                      <td style={{ fontSize: 12 }}>{s.appDisplayName || '—'}</td>
                      <td>
                        {s.riskLevelAggregated && s.riskLevelAggregated !== 'none' ? (
                          <span style={{
                            padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 700,
                            fontFamily: 'var(--font-mono)', textTransform: 'uppercase',
                            background: `${riskColor(s.riskLevelAggregated)}20`,
                            color: riskColor(s.riskLevelAggregated),
                            border: `1px solid ${riskColor(s.riskLevelAggregated)}40`
                          }}>{s.riskLevelAggregated}</span>
                        ) : <span className="text-muted" style={{ fontSize: 11 }}>—</span>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : null}
      </div>
    </div>
  );
}
