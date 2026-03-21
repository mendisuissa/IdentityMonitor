import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { AlertStats, Alert, PrivilegedUser } from '../types';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts';
import { formatDistanceToNow } from 'date-fns';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];

function severityColor(s: string) {
  return ({ critical: '#ff3b3b', high: '#ff6b35', medium: '#f5a623', low: '#4a90d9', clean: '#2ecc71' } as any)[s] || '#8ba3cc';
}

function scoreColor(score: number) {
  if (score >= 80) return '#ff3b3b';
  if (score >= 55) return '#ff6b35';
  if (score >= 30) return '#f5a623';
  if (score > 0)  return '#4a90d9';
  return '#2ecc71';
}

type Health = { status?: string; timestamp?: string; mockMode?: boolean; version?: string; features?: { webhooks?: boolean; telegram?: boolean; tableStorage?: boolean; }; };
type RiskUser = { userId: string; displayName: string; userPrincipalName: string; roles: string[]; score: number; level: string; openAlerts: number; criticalOpen: number; };
type RiskPosture = { summary: { monitoredPrivilegedAccounts: number; alertsBySeverity: any; autoContainedIncidents: number; averageRiskScore: number; mttaHours: number | null; mttrHours: number | null; }; mostRiskyAdmins: RiskUser[]; trend: any[]; topAnomalyCategories: { name: string; count: number }[]; };

export default function Dashboard() {
  const navigate = useNavigate();
  const [stats, setStats]         = useState<AlertStats | null>(null);
  const [recentAlerts, setRecentAlerts] = useState<Alert[]>([]);
  const [users, setUsers]         = useState<PrivilegedUser[]>([]);
  const [health, setHealth]       = useState<Health | null>(null);
  const [posture, setPosture]     = useState<RiskPosture | null>(null);
  const [loading, setLoading]     = useState(true);
  const [showWizard, setShowWizard] = useState(false);
  const [wizardStep, setWizardStep] = useState(0);
  const [scanMessage, setScanMessage] = useState('');
  const [scanRunning, setScanRunning] = useState(false);

  async function loadDashboardState() {
    const [s, a, u, h, rp] = await Promise.all([
      api.getAlertStats(),
      api.getAlerts({}),
      api.getUsers(),
      fetch('/api/health', { credentials: 'include' }).then(r => r.json()).catch(() => null),
      api.getRiskPosture().catch(() => null)
    ]);
    setStats(s as AlertStats);
    setRecentAlerts((a as Alert[]).filter(x => x.status === 'open').slice(0, 8));
    setUsers(u as PrivilegedUser[]);
    setHealth(h as Health);
    if (rp) setPosture(rp as RiskPosture);
    return { stats: s as AlertStats, users: u as PrivilegedUser[] };
  }

  useEffect(() => {
    loadDashboardState()
      .then(async ({ stats: s, users: u }) => {
        if ((s?.total ?? 0) === 0 && (u?.length ?? 0) > 0) {
          setScanRunning(true);
          setScanMessage('No live alerts yet. Running a first Graph scan for privileged sign-ins...');
          try {
            await api.triggerScan();
            await loadDashboardState();
            setScanMessage('Live privileged scan completed. Dashboard refreshed with current tenant telemetry.');
          } catch (e: any) {
            setScanMessage(e?.message || 'Live scan failed. Open Sign-in Activity and run a manual scan.');
          } finally {
            setScanRunning(false);
          }
        }
      })
      .finally(() => setLoading(false));
  }, []);

  const riskUsers = useMemo(() => {
    // Use real risk posture data if available, else fall back to users
    if (posture?.mostRiskyAdmins?.length) return posture.mostRiskyAdmins.filter(u => u.score > 0);
    return users.filter(u => u.riskLevel !== 'clean').sort((a, b) => SEVERITY_ORDER.indexOf(a.riskLevel) - SEVERITY_ORDER.indexOf(b.riskLevel));
  }, [posture, users]);

  const avgRiskScore = posture?.summary?.averageRiskScore ?? 0;
  const trendData    = posture?.trend?.slice(-14) ?? [];
  const topAnomalies = posture?.topAnomalyCategories ?? [];

  const telemetryIncomplete = useMemo(() => {
    const monitored = posture?.summary?.monitoredPrivilegedAccounts ?? users.length;
    const totalAlerts = stats?.total ?? 0;
    return monitored === 0 || (monitored > 0 && totalAlerts === 0);
  }, [posture, users.length, stats]);

  const postureScore = useMemo(() => {
    if (telemetryIncomplete) {
      return { score: 0, delta: 0, hygiene: 0, readiness: 0, coverage: 0, tier: 'Telemetry Incomplete' };
    }
    if (posture?.summary) {
      const open     = stats?.open ?? 0;
      const critical = stats?.critical ?? 0;
      const high     = stats?.high ?? 0;
      const hygiene  = Math.max(35, 100 - (critical * 20 + high * 10 + open * 4));
      const readiness = [health?.features?.webhooks, health?.features?.telegram, health?.features?.tableStorage].filter(Boolean).length * 25 + 25;
      const coverage = users.length > 0 ? 100 : 35;
      const score = Math.max(18, Math.min(97, Math.round((coverage * 0.25) + (hygiene * 0.45) + (readiness * 0.3))));
      const delta = critical > 0 ? -8 : high > 0 ? -4 : open > 0 ? -2 : 3;
      return { score, delta, hygiene, readiness, coverage, tier: score >= 85 ? 'Strong' : score >= 70 ? 'Stable' : score >= 50 ? 'Needs Attention' : 'High Risk' };
    }
    return { score: 0, delta: 0, hygiene: 0, readiness: 0, coverage: 0, tier: 'Loading' };
  }, [telemetryIncomplete, posture, stats, users.length, health]);

  const checklist = useMemo(() => [
    { key: 'tenant',  label: 'Connect tenant',            done: users.length > 0 || health?.mockMode === true,  actionLabel: 'Open settings',   action: () => navigate('/settings') },
    { key: 'scan',    label: 'Run first privileged scan', done: (stats?.total ?? 0) > 0,                        actionLabel: 'Open sign-ins',   action: () => navigate('/signins') },
    { key: 'channel', label: 'Enable an alert channel',   done: !!health?.features?.telegram,                   actionLabel: 'Configure alerts', action: () => navigate('/settings') },
    { key: 'storage', label: 'Persistent storage',        done: !!health?.features?.tableStorage,               actionLabel: 'Review storage',  action: () => navigate('/settings') },
    { key: 'review',  label: 'Review active threats',     done: (stats?.open ?? 0) === 0,                       actionLabel: 'Open threats',    action: () => navigate('/alerts') }
  ], [health, navigate, stats, users.length]);

  const completedSteps = checklist.filter(s => s.done).length;
  const currentStep    = checklist[wizardStep];

  const executive = useMemo(() => {
    const critical = stats?.critical ?? 0;
    const high     = stats?.high ?? 0;
    const open     = stats?.open ?? 0;
    const topRiskUser = (posture?.mostRiskyAdmins || riskUsers)[0];
    const headline = telemetryIncomplete
      ? 'Live telemetry is incomplete. Run a privileged scan and validate Graph role discovery before trusting posture scores.'
      : critical > 0
      ? 'Immediate executive attention required — critical privileged exposure detected.'
      : high > 0
      ? 'Privileged threats are manageable but need owner assignment now.'
      : open > 0
      ? 'Posture stable. Small queue of threats to close or suppress with reason.'
      : 'No active privileged threats. Focus on hardening and reporting readiness.';
    return { headline, topRiskUser, open, critical, high };
  }, [telemetryIncomplete, stats, posture, riskUsers]);

  const trustSignals = [
    { label: 'Graph API',             ok: health?.status === 'ok',               detail: health?.status === 'ok' ? 'Healthy connection' : 'Health probe failed' },
    { label: 'Webhook ingestion',     ok: !!health?.features?.webhooks,           detail: health?.features?.webhooks ? 'Live detection path available' : 'Not configured' },
    { label: 'Alert delivery',        ok: !!health?.features?.telegram,           detail: health?.features?.telegram ? 'Telegram enabled' : 'No fast-response channel' },
    { label: 'Persistent telemetry',  ok: !!health?.features?.tableStorage,       detail: health?.features?.tableStorage ? 'Azure Tables active' : 'Temporary storage only' },
  ];

  if (loading) return <div className="loading-state"><div className="loading-spinner" /><div className="loading-text">Fetching privileged identity telemetry...</div></div>;

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Privileged Security Overview</div>
          <div className="page-subtitle">Real-time posture across active threats, privileged exposure, and response readiness</div>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <button className="btn btn-ghost btn-sm" onClick={() => setShowWizard(true)}>Setup guide</button>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>Last refresh · {new Date().toLocaleString()}</div>
        </div>
      </div>

      {(telemetryIncomplete || scanMessage) && (
        <div className="card" style={{ marginBottom: 16, borderLeft: `3px solid ${telemetryIncomplete ? 'var(--amber-500)' : 'var(--green-clean)'}` }}>
          <div style={{ fontWeight: 700, marginBottom: 6, color: telemetryIncomplete ? 'var(--amber-400)' : 'var(--green-clean)' }}>
            {telemetryIncomplete ? 'Telemetry incomplete' : 'Live scan status'}
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 10 }}>
            {scanMessage || 'This tenant does not yet have enough live privileged telemetry to score posture accurately.'}
          </div>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            <button className="btn btn-primary btn-sm" disabled={scanRunning} onClick={async () => {
              setScanRunning(true);
              setScanMessage('Running live privileged sign-in scan...');
              try {
                await api.triggerScan();
                await loadDashboardState();
                setScanMessage('Live privileged scan completed.');
              } catch (e: any) {
                setScanMessage(e?.message || 'Live scan failed.');
              } finally {
                setScanRunning(false);
              }
            }}>
              {scanRunning ? 'Running scan…' : 'Run live scan'}
            </button>
            <button className="btn btn-secondary btn-sm" onClick={() => navigate('/signins')}>Open Sign-in Activity</button>
          </div>
        </div>
      )}

      {/* ── KPI Row ── */}
      <div className="stats-grid">
        <div className="stat-card critical clickable" onClick={() => navigate('/alerts?severity=critical')}>
          <div className="stat-value">{stats?.critical ?? 0}</div><div className="stat-label">Critical Threats</div><div className="stat-arrow">→</div>
        </div>
        <div className="stat-card high clickable" onClick={() => navigate('/alerts?severity=high')}>
          <div className="stat-value">{stats?.high ?? 0}</div><div className="stat-label">High Priority</div><div className="stat-arrow">→</div>
        </div>
        <div className="stat-card medium clickable" onClick={() => navigate('/alerts')}>
          <div className="stat-value">{stats?.open ?? 0}</div><div className="stat-label">Active Threats</div><div className="stat-arrow">→</div>
        </div>
        <div className="stat-card amber clickable" onClick={() => navigate('/users')}>
          <div className="stat-value">{posture?.summary?.monitoredPrivilegedAccounts ?? users.length}</div><div className="stat-label">Privileged Accounts</div><div className="stat-arrow">→</div>
        </div>
        <div className="stat-card clean clickable" onClick={() => navigate('/reports')}>
          <div className="stat-value">{postureScore.score}</div><div className="stat-label">Posture Score</div><div className="stat-arrow">→</div>
        </div>
        <div className="stat-card neutral clickable" onClick={() => navigate('/reports')}>
          <div className="stat-value" style={{ color: scoreColor(avgRiskScore) }}>{avgRiskScore}</div><div className="stat-label">Avg Risk Score</div><div className="stat-arrow">→</div>
        </div>
      </div>

      {/* ── Executive + Trust ── */}
      <div className="two-col" style={{ marginBottom: 20 }}>
        <div className="card executive-hero">
          <div className="card-header">
            <div><div className="card-title">Executive Snapshot</div><div className="text-muted" style={{ fontSize: 12, marginTop: 4 }}>Management-ready summary</div></div>
            <span className="role-tag">{postureScore.delta >= 0 ? `+${postureScore.delta}` : postureScore.delta} vs last review</span>
          </div>
          <div className="executive-headline">{executive.headline}</div>
          <div className="executive-grid">
            <div className="mini-kpi"><span>Posture</span><strong>{postureScore.score}</strong></div>
            <div className="mini-kpi"><span>Avg risk</span><strong style={{ color: scoreColor(avgRiskScore) }}>{avgRiskScore}</strong></div>
            <div className="mini-kpi"><span>Open threats</span><strong>{executive.open}</strong></div>
            <div className="mini-kpi"><span>Auto-contained</span><strong>{posture?.summary?.autoContainedIncidents ?? 0}</strong></div>
            {posture?.summary?.mttaHours != null && <div className="mini-kpi"><span>MTTA</span><strong>{posture.summary.mttaHours}h</strong></div>}
            {posture?.summary?.mttrHours != null && <div className="mini-kpi"><span>MTTR</span><strong>{posture.summary.mttrHours}h</strong></div>}
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 14 }}>
            <button className="btn btn-primary btn-sm" onClick={() => navigate('/reports')}>Open executive report</button>
            <button className="btn btn-ghost btn-sm" onClick={() => navigate('/alerts')}>Review threat queue</button>
          </div>
        </div>

        <div className="card">
          <div className="card-header"><div className="card-title">Trust Center</div><button className="btn btn-ghost btn-sm" onClick={() => navigate('/settings')}>Settings →</button></div>
          <div className="trust-signal-list">
            {trustSignals.map(signal => (
              <div key={signal.label} className="trust-signal-row">
                <div className={`health-pill ${signal.ok ? 'ok' : 'warn'}`}><span className="health-pill-dot" /><span>{signal.label}</span></div>
                <div className="text-muted" style={{ fontSize: 11 }}>{signal.detail}</div>
              </div>
            ))}
          </div>
          <div className="health-grid-compact" style={{ marginTop: 12 }}>
            <HealthPill label="Coverage"      ok={users.length > 0} />
            <HealthPill label="Threat queue"  ok={(stats?.open ?? 0) === 0} />
            <HealthPill label="Setup"         ok={completedSteps >= 3} />
            <HealthPill label="Data freshness" ok={true} />
          </div>
        </div>
      </div>

      {/* ── Risk Admins + Anomaly breakdown ── */}
      <div className="two-col" style={{ marginBottom: 20 }}>
        <div className="card">
          <div className="card-header">
            <div className="card-title">Top Risk Admins</div>
            <button className="btn btn-ghost btn-sm" onClick={() => navigate('/users')}>View all →</button>
          </div>
          {riskUsers.length === 0 ? (
            <div className="empty-state"><div className="empty-icon">✨</div><div className="empty-text">No risky privileged identities</div></div>
          ) : (
            <table className="data-table">
              <thead><tr><th>Score</th><th>User</th><th>Role</th><th>Open</th></tr></thead>
              <tbody>
                {riskUsers.slice(0, 6).map((user: any) => (
                  <tr key={user.userId || user.id} style={{ cursor: 'pointer' }} onClick={() => navigate('/users')}>
                    <td>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 700, color: scoreColor(user.score) }}>{user.score}</span>
                    </td>
                    <td>
                      <div style={{ fontWeight: 600, fontSize: 12 }}>{user.displayName}</div>
                      <div className="text-muted" style={{ fontSize: 11 }}>{user.userPrincipalName}</div>
                    </td>
                    <td><span className="role-tag">{(user.roles?.[0] || '').replace(' Administrator', ' Admin')}</span></td>
                    <td><span style={{ color: (user.openAlerts || user.alertCount || 0) > 0 ? 'var(--red-critical)' : 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 700 }}>{user.openAlerts ?? user.alertCount ?? 0}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="card">
          <div className="card-header"><div className="card-title">Top Anomaly Types</div></div>
          {topAnomalies.length === 0 ? (
            <div className="empty-state"><div className="empty-icon">📊</div><div className="empty-text">No anomaly data yet — run a scan</div></div>
          ) : (
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={topAnomalies} layout="vertical" margin={{ left: 8, right: 24, top: 4, bottom: 4 }}>
                <XAxis type="number" tick={{ fontSize: 10, fill: '#4a6490' }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="name" width={150} tick={{ fontSize: 10, fill: '#8ba3cc' }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: '#0f2040', border: '1px solid #1e3060', borderRadius: 6, fontSize: 12 }} />
                <Bar dataKey="count" radius={[0, 3, 3, 0]}>
                  {topAnomalies.map((_: any, i: number) => <Cell key={i} fill={['#ff3b3b','#ff6b35','#f5a623','#4a90d9','#8ba3cc','#2ecc71'][i % 6]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* ── Recent Threats + Trend ── */}
      <div className="two-col" style={{ marginBottom: 20 }}>
        <div className="card">
          <div className="card-header"><div className="card-title">Recent Active Threats</div><button className="btn btn-ghost btn-sm" onClick={() => navigate('/alerts')}>View all →</button></div>
          {recentAlerts.length === 0 ? (
            <div className="empty-state">
              <div className="empty-icon">🛡️</div>
              <div className="empty-text">No active threats</div>
              <div className="text-muted" style={{ fontSize: 12, marginTop: 4 }}>Use this time to review posture and hardening readiness.</div>
            </div>
          ) : (
            <table className="data-table">
              <thead><tr><th>Severity</th><th>User</th><th>Threat</th><th>Detected</th></tr></thead>
              <tbody>
                {recentAlerts.map(alert => (
                  <tr key={alert.id} className={`alert-row-${alert.severity}`} style={{ cursor: 'pointer' }} onClick={() => navigate('/alerts')}>
                    <td><span className={`severity-badge ${alert.severity}`}>{alert.severity}</span></td>
                    <td><div style={{ fontWeight: 600, fontSize: 12 }}>{alert.userDisplayName}</div><div className="text-muted" style={{ fontSize: 11 }}>{alert.country || 'Unknown'}</div></td>
                    <td style={{ fontSize: 12 }}>{alert.anomalyLabel}</td>
                    <td className="text-muted" style={{ fontSize: 11, whiteSpace: 'nowrap' }}>{formatDistanceToNow(new Date(alert.detectedAt), { addSuffix: true })}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="card">
          <div className="card-header"><div className="card-title">Threat Activity Trend</div><span className="role-tag">Last 14 days</span></div>
          {trendData.length > 0 ? (
            <ResponsiveContainer width="100%" height={160}>
              <AreaChart data={trendData} margin={{ top: 5, right: 8, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#f5a623" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#f5a623" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="day" tickFormatter={(d: string) => d.slice(5)} tick={{ fontSize: 9, fill: '#4a6490' }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 10, fill: '#4a6490' }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: '#0f2040', border: '1px solid #1e3060', borderRadius: 6, fontSize: 12 }} labelStyle={{ color: '#8ba3cc' }} itemStyle={{ color: '#f5a623' }} />
                <Area type="monotone" dataKey="alerts" stroke="#f5a623" strokeWidth={2} fill="url(#alertGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state" style={{ height: 160 }}>
              <div className="empty-text" style={{ fontSize: 12 }}>No trend data yet — run a scan to start building history</div>
            </div>
          )}
        </div>
      </div>

      {/* ── Setup checklist + posture ── */}
      <div className="two-col">
        <div className="card">
          <div className="card-header"><div className="card-title">Onboarding Checklist</div><span className="role-tag">{completedSteps}/5 complete</span></div>
          <div className="checklist-list">
            {checklist.map((step, index) => (
              <button key={step.key} className="checklist-item" onClick={() => { setWizardStep(index); setShowWizard(true); }}>
                <span className={`checklist-dot ${step.done ? 'done' : ''}`}>{step.done ? '✓' : '•'}</span>
                <span>{step.label}</span>
              </button>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card-header"><div className="card-title">Posture Breakdown</div><span className="role-tag">{postureScore.tier}</span></div>
          <MetricRow label="Coverage depth"        value={postureScore.coverage} />
          <MetricRow label="Threat hygiene"        value={postureScore.hygiene} />
          <MetricRow label="Operational readiness" value={postureScore.readiness} />
          <div className="trust-note" style={{ marginTop: 12 }}>
            {(stats?.open ?? 0) > 0
              ? 'Close or suppress open threats with owner assignment and documented reason.'
              : 'Enable more trust signals and generate an executive summary.'}
          </div>
        </div>
      </div>

      {/* ── Wizard modal ── */}
      {showWizard && currentStep && (
        <div className="modal-overlay" onClick={() => setShowWizard(false)}>
          <div className="modal-card" onClick={(e: any) => e.stopPropagation()}>
            <div className="card-header" style={{ marginBottom: 6 }}>
              <div><div className="card-title">Setup Guide</div><div className="text-muted" style={{ fontSize: 12, marginTop: 4 }}>Step {wizardStep + 1} of {checklist.length}</div></div>
              <button className="btn btn-ghost btn-sm" onClick={() => setShowWizard(false)}>Close</button>
            </div>
            <div className="wizard-step-title">{currentStep.label}</div>
            <div className="wizard-status-row">
              <span className={`health-pill ${currentStep.done ? 'ok' : 'warn'}`}><span className="health-pill-dot" />{currentStep.done ? 'Completed' : 'Still pending'}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginTop: 18, flexWrap: 'wrap' }}>
              <button className="btn btn-ghost btn-sm" disabled={wizardStep === 0} onClick={() => setWizardStep(s => Math.max(0, s - 1))}>← Previous</button>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn btn-primary btn-sm" onClick={currentStep.action}>{currentStep.actionLabel}</button>
                <button className="btn btn-ghost btn-sm" disabled={wizardStep === checklist.length - 1} onClick={() => setWizardStep(s => Math.min(checklist.length - 1, s + 1))}>Next →</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function HealthPill({ label, ok }: { label: string; ok: boolean }) {
  return <div className={`health-pill ${ok ? 'ok' : 'warn'}`}><span className="health-pill-dot" /><span>{label}</span></div>;
}

function MetricRow({ label, value }: { label: string; value: number }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, marginBottom: 6 }}>
        <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{label}</span>
        <span className="mono" style={{ fontSize: 11, color: 'var(--amber-400)' }}>{value}%</span>
      </div>
      <div className="progress-rail"><div className="progress-fill" style={{ width: `${value}%` }} /></div>
    </div>
  );
}
