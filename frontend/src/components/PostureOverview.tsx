import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, RadarChart, Radar, PolarGrid, PolarAngleAxis } from 'recharts';
import { formatDistanceToNow } from 'date-fns';

interface PostureData {
  composite: number;
  grade: { letter: string; label: string; color: string };
  breakdown: Record<string, { score: number; label: string; icon: string; weight: number }>;
  recommendations: Array<{ dimension: string; label: string; score: number; action: string }>;
  tenant?: any;
}

const sparkData = [28, 35, 42, 38, 55, 48, 62, 58, 45, 68, 72, 65].map((v, i) => ({ h: `${i * 2}h`, v }));

export default function PostureOverview() {
  const navigate = useNavigate();
  const [posture, setPosture] = useState<PostureData | null>(null);
  const [stats, setStats]     = useState<any>(null);
  const [alerts, setAlerts]   = useState<any[]>([]);
  const [users, setUsers]     = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      fetch('/api/posture', { credentials: 'include' }).then(r => r.json()),
      api.getAlertStats(),
      api.getAlerts({}),
      api.getUsers()
    ]).then(([p, s, a, u]) => {
      setPosture(p);
      setStats(s);
      setAlerts((a as any[]).filter(x => x.status === 'open').slice(0, 6));
      setUsers(u as any[]);
    }).finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="loading-state"><div className="loading-spinner" /><div className="loading-text">Calculating security posture...</div></div>;

  const g = posture?.grade;
  const atRiskUsers = users.filter(u => u.riskLevel !== 'clean');

  // Radar data
  const radarData = posture ? Object.values(posture.breakdown).map(d => ({
    subject: d.label.split(' ')[0], // short label
    score: d.score, fullMark: 100
  })) : [];

  const onboarding = posture?.tenant?.onboarding || {};
  const onboardingSteps = [
    { key: 'connected',          label: 'Tenant connected',         done: onboarding.connected },
    { key: 'permissionsGranted', label: 'Graph permissions verified', done: onboarding.permissionsGranted },
    { key: 'firstScanDone',      label: 'First scan completed',      done: onboarding.firstScanDone },
    { key: 'alertChannelTested', label: 'Alert channel tested',      done: onboarding.alertChannelTested },
    { key: 'webhookActive',      label: 'Real-time webhooks active', done: onboarding.webhookActive },
    { key: 'workHoursSet',       label: 'Work hours configured',     done: onboarding.workHoursSet },
  ];
  const onboardingPct = Math.round(onboardingSteps.filter(s => s.done).length / onboardingSteps.length * 100);
  const onboardingDone = onboardingPct === 100;

  return (
    <div>
      {/* Onboarding Banner */}
      {!onboardingDone && (
        <div style={{ padding: '14px 20px', background: 'rgba(245,166,35,0.08)', border: '1px solid rgba(245,166,35,0.25)', borderRadius: 10, marginBottom: 20, display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 700, color: 'var(--amber-400)', marginBottom: 4 }}>
              ⚡ Setup in progress — {onboardingPct}% complete
            </div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {onboardingSteps.map(s => (
                <span key={s.key} style={{ fontSize: 11, padding: '2px 8px', borderRadius: 20, background: s.done ? 'rgba(46,204,113,0.15)' : 'rgba(255,255,255,0.05)', color: s.done ? '#2ecc71' : 'var(--text-muted)', border: `1px solid ${s.done ? 'rgba(46,204,113,0.3)' : 'var(--navy-border)'}` }}>
                  {s.done ? '✓' : '○'} {s.label}
                </span>
              ))}
            </div>
          </div>
          <button className="btn btn-primary btn-sm" onClick={() => navigate('/settings')}>Complete Setup →</button>
        </div>
      )}

      <div className="page-header">
        <div>
          <div className="page-title">Security Overview</div>
          <div className="page-subtitle">Privileged identity monitoring — real-time threat detection</div>
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>{new Date().toLocaleString()}</div>
      </div>

      {/* Posture Score + Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: 20, marginBottom: 20 }}>

        {/* Posture Score Card */}
        <div className="card" style={{ minWidth: 220, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 8, borderTop: `3px solid ${g?.color}` }}>
          <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.8px' }}>Security Posture</div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 72, fontWeight: 700, color: g?.color, lineHeight: 1 }}>{g?.letter}</div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 22, color: g?.color }}>{posture?.composite}/100</div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{g?.label}</div>
          {/* Score bar */}
          <div style={{ width: '100%', height: 6, background: 'var(--navy-700)', borderRadius: 3, overflow: 'hidden' }}>
            <div style={{ height: '100%', width: (posture?.composite || 0) + '%', background: g?.color, borderRadius: 3, transition: 'width 1s ease' }} />
          </div>
          <button className="btn btn-ghost btn-sm" style={{ width: '100%', justifyContent: 'center', marginTop: 4 }} onClick={() => navigate('/exposure')}>
            View breakdown →
          </button>
        </div>

        {/* Stats Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
          <div className="stat-card critical clickable" onClick={() => navigate('/threats?severity=critical')}>
            <div className="stat-value">{stats?.critical ?? 0}</div><div className="stat-label">Critical Threats</div><div className="stat-arrow">→</div>
          </div>
          <div className="stat-card high clickable" onClick={() => navigate('/threats?severity=high')}>
            <div className="stat-value">{stats?.high ?? 0}</div><div className="stat-label">High Priority</div><div className="stat-arrow">→</div>
          </div>
          <div className="stat-card neutral clickable" onClick={() => navigate('/threats')}>
            <div className="stat-value">{stats?.open ?? 0}</div><div className="stat-label">Active Threats</div><div className="stat-arrow">→</div>
          </div>
          <div className="stat-card amber clickable" onClick={() => navigate('/exposure')}>
            <div className="stat-value">{users.length}</div><div className="stat-label">Privileged Exposure</div><div className="stat-arrow">→</div>
          </div>
          <div className="stat-card medium clickable" onClick={() => navigate('/threats?severity=medium')}>
            <div className="stat-value">{stats?.medium ?? 0}</div><div className="stat-label">Medium Alerts</div><div className="stat-arrow">→</div>
          </div>
          <div className="stat-card clean clickable" onClick={() => navigate('/threats?status=resolved')}>
            <div className="stat-value">{stats?.resolvedToday ?? 0}</div><div className="stat-label">Resolved Today</div><div className="stat-arrow">→</div>
          </div>
        </div>
      </div>

      <div className="two-col" style={{ marginBottom: 20 }}>
        {/* Active Threats */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">⚠️ Active Privileged Threats</div>
            <button className="btn btn-ghost btn-sm" onClick={() => navigate('/threats')}>View all →</button>
          </div>
          {alerts.length === 0 ? (
            <div style={{ padding: '20px 0', textAlign: 'center' }}>
              <div style={{ fontSize: 24, marginBottom: 8 }}>🛡️</div>
              <div style={{ fontSize: 13, color: 'var(--green-clean)', fontWeight: 600 }}>No active threats</div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>
                {users.length > 0 ? `Monitoring ${users.length} privileged accounts` : 'Connect a tenant to start monitoring'}
              </div>
            </div>
          ) : (
            <table className="data-table">
              <thead><tr><th>Severity</th><th>Account</th><th>Threat</th><th>Detected</th></tr></thead>
              <tbody>
                {alerts.map(alert => (
                  <tr key={alert.id} style={{ cursor: 'pointer' }} onClick={() => navigate('/threats')}>
                    <td><span className={`severity-badge ${alert.severity}`}>{alert.severity}</span></td>
                    <td>
                      <div style={{ fontWeight: 600, fontSize: 12 }}>{alert.userDisplayName}</div>
                      <div className="text-muted" style={{ fontSize: 11 }}>{alert.country || '—'}</div>
                    </td>
                    <td style={{ fontSize: 12 }}>
                      {(alert as any).appTier === 'CRITICAL' && <span style={{ color: '#ff3b3b', fontSize: 10 }}>🔴 </span>}
                      {alert.anomalyLabel}
                    </td>
                    <td className="text-muted" style={{ fontSize: 11, whiteSpace: 'nowrap' }}>
                      {formatDistanceToNow(new Date(alert.detectedAt), { addSuffix: true })}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Posture Breakdown Radar */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">🎯 Posture Breakdown</div>
          </div>
          {radarData.length > 0 && (
            <ResponsiveContainer width="100%" height={160}>
              <RadarChart data={radarData}>
                <PolarGrid stroke="rgba(30,48,96,0.6)" />
                <PolarAngleAxis dataKey="subject" tick={{ fontSize: 10, fill: '#4a6490' }} />
                <Radar dataKey="score" stroke={g?.color || '#f5a623'} fill={g?.color || '#f5a623'} fillOpacity={0.15} strokeWidth={2} />
              </RadarChart>
            </ResponsiveContainer>
          )}
          {/* Dimension scores */}
          {posture && Object.values(posture.breakdown).map(d => (
            <div key={d.label} style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 6 }}>
              <span style={{ fontSize: 14, flexShrink: 0 }}>{d.icon}</span>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 2 }}>{d.label}</div>
                <div style={{ height: 4, background: 'var(--navy-700)', borderRadius: 2, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: d.score + '%', background: d.score >= 70 ? '#2ecc71' : d.score >= 40 ? '#f5a623' : '#ff3b3b', borderRadius: 2 }} />
                </div>
              </div>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700, color: d.score >= 70 ? '#2ecc71' : d.score >= 40 ? '#f5a623' : '#ff3b3b', minWidth: 28, textAlign: 'right' }}>{d.score}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Top Recommendations */}
      {posture?.recommendations && posture.recommendations.length > 0 && (
        <div className="card" style={{ marginBottom: 20 }}>
          <div className="card-header">
            <div className="card-title">💡 Top Recommendations to Improve Posture</div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 12 }}>
            {posture.recommendations.map((r, i) => (
              <div key={i} style={{ padding: '12px 14px', background: 'var(--navy-800)', border: '1px solid var(--navy-border)', borderRadius: 8, borderLeft: `3px solid ${r.score < 40 ? '#ff3b3b' : '#f5a623'}` }}>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>{r.label}</div>
                <div style={{ fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.5 }}>{r.action}</div>
                <div style={{ fontSize: 11, color: r.score < 40 ? '#ff3b3b' : '#f5a623', marginTop: 6, fontFamily: 'var(--font-mono)' }}>
                  Current score: {r.score}/100
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Alert Activity Chart */}
      <div className="card">
        <div className="card-header"><div className="card-title">Threat Activity (Last 24h)</div></div>
        <ResponsiveContainer width="100%" height={120}>
          <AreaChart data={sparkData} margin={{ top: 5, right: 8, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="ag" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#f5a623" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#f5a623" stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis dataKey="h" tick={{ fontSize: 10, fill: '#4a6490' }} axisLine={false} tickLine={false} />
            <YAxis tick={{ fontSize: 10, fill: '#4a6490' }} axisLine={false} tickLine={false} />
            <Tooltip contentStyle={{ background: '#0f2040', border: '1px solid #1e3060', borderRadius: 6, fontSize: 12 }} itemStyle={{ color: '#f5a623' }} />
            <Area type="monotone" dataKey="v" stroke="#f5a623" strokeWidth={2} fill="url(#ag)" />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
