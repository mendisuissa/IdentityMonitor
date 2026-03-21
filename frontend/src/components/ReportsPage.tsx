import React, { useEffect, useMemo, useState } from 'react';
import { api } from '../services/api';
import { Alert, AlertStats, RiskPosture } from '../types';
import { generateMonthlySummaryPDF, generateExecutiveSummaryPDF } from '../services/pdfReport';
import TestMailPanel from './TestMailPanel';

function Metric({ label, value, tone }: { label: string; value: string | number; tone?: string }) {
  return <div className={`stat-card ${tone || 'neutral'}`}><div className="stat-value">{value}</div><div className="stat-label">{label}</div></div>;
}

export default function ReportsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<AlertStats | null>(null);
  const [posture, setPosture] = useState<RiskPosture | null>(null);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([api.getAlerts({}), api.getAlertStats(), api.getRiskPosture().catch(() => null)])
      .then(([a, s, p]) => { setAlerts(a as Alert[]); setStats(s as AlertStats); setPosture(p as RiskPosture | null); })
      .finally(() => setLoading(false));
  }, []);

  const executive = useMemo(() => {
    const avgScore = posture?.summary.averageRiskScore ?? 0;
    const score = Math.max(12, Math.min(96, Math.round(100 - avgScore)));
    const headline = score < 55
      ? 'Privileged posture is under pressure and needs active containment discipline.'
      : score < 75
      ? 'Privileged posture is stable but still depends on faster approvals and lower alert backlog.'
      : 'Privileged posture is healthy. Focus on tuning, reporting, and readiness validation.';
    return { score, headline };
  }, [posture]);

  const generate = async (type: string, fn: () => void) => {
    setGenerating(type);
    setTimeout(() => { fn(); setGenerating(null); }, 100);
  };

  if (loading) return <div className="loading-state"><div className="loading-spinner" /><div className="loading-text">Loading posture and reporting…</div></div>;

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Posture & Reports</div>
          <div className="page-subtitle">Executive security reporting, privileged risk posture, false positive trend, and response performance</div>
        </div>
        <div className="role-tag">Retention {posture?.summary.retention?.incidentDays || 180}d incidents</div>
      </div>

      <div className="stats-grid" style={{ marginBottom: 20 }}>
        <Metric label="Executive score" value={executive.score} tone={executive.score < 55 ? 'critical' : executive.score < 75 ? 'amber' : 'clean'} />
        <Metric label="Avg risk score" value={posture?.summary.averageRiskScore ?? 0} tone="medium" />
        <Metric label="MTTA (hours)" value={posture?.summary.mttaHours ?? '—'} tone="neutral" />
        <Metric label="MTTR (hours)" value={posture?.summary.mttrHours ?? '—'} tone="neutral" />
        <Metric label="Auto-contained" value={posture?.summary.autoContainedIncidents ?? 0} tone="clean" />
        <Metric label="Dismissed trend" value={posture?.summary.falsePositiveTrend ?? 0} tone="amber" />
      </div>

      <div className="two-col" style={{ marginBottom: 24 }}>
        <div className="card">
          <div className="card-header">
            <div className="card-title">Executive narrative</div>
            <span className="role-tag">Security manager view</span>
          </div>
          <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 10 }}>{executive.headline}</div>
          <div className="action-list">
            <div className="action-list-item">• Monitored privileged accounts: {posture?.summary.monitoredPrivilegedAccounts ?? 0}</div>
            <div className="action-list-item">• Critical alerts seen: {posture?.summary.alertsBySeverity?.critical ?? 0}</div>
            <div className="action-list-item">• High alerts seen: {posture?.summary.alertsBySeverity?.high ?? 0}</div>
            <div className="action-list-item">• Reporting retention: {posture?.summary.retention?.reportDays ?? 365} days</div>
          </div>
          <div style={{ marginTop: 14, display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            <button className="btn btn-primary" onClick={() => generate('executive', () => generateExecutiveSummaryPDF(alerts as any, stats as any))} disabled={generating === 'executive'}>
              {generating === 'executive' ? 'Generating…' : '↓ Executive PDF'}
            </button>
            <button className="btn btn-ghost" onClick={() => window.open(api.executiveExportUrl('csv'), '_blank')}>↓ Executive CSV</button>
            <button className="btn btn-ghost" onClick={() => window.open(api.executiveExportUrl('json'), '_blank')}>↓ Executive JSON</button>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">Top anomaly categories</div>
            <span className="role-tag">Last 30-day view</span>
          </div>
          <div style={{ display: 'grid', gap: 10 }}>
            {(posture?.topAnomalyCategories || []).map(item => (
              <div key={item.name} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, padding: '10px 12px', border: '1px solid var(--navy-border)', borderRadius: 10 }}>
                <div>{item.name}</div>
                <div className="role-tag">{item.count}</div>
              </div>
            ))}
            {!posture?.topAnomalyCategories?.length && <div className="text-muted">No category trend yet.</div>}
          </div>
        </div>
      </div>

      <div className="two-col" style={{ marginBottom: 24 }}>
        <div className="card">
          <div className="card-header">
            <div className="card-title">Most risky admins</div>
            <span className="role-tag">Privileged risk score</span>
          </div>
          <div style={{ display: 'grid', gap: 10 }}>
            {(posture?.mostRiskyAdmins || []).slice(0, 6).map(admin => (
              <div key={admin.userId} style={{ padding: '12px 14px', border: '1px solid var(--navy-border)', borderRadius: 12 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
                  <div>
                    <div style={{ fontWeight: 700 }}>{admin.displayName}</div>
                    <div className="text-muted" style={{ fontSize: 11 }}>{admin.userPrincipalName}</div>
                  </div>
                  <div className="role-tag">Score {admin.score}</div>
                </div>
                <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-secondary)' }}>
                  {admin.openAlerts} open alerts · {admin.roles.join(', ') || 'No role context'} · countries {admin.baseline.knownCountries.length}
                </div>
              </div>
            ))}
            {!posture?.mostRiskyAdmins?.length && <div className="text-muted">No privileged risk posture yet.</div>}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">Response trend</div>
            <span className="role-tag">7 / 30 day operational view</span>
          </div>
          <div style={{ display: 'grid', gap: 10 }}>
            {(posture?.trend || []).slice(-7).map(day => (
              <div key={day.day} style={{ display: 'grid', gridTemplateColumns: '1fr repeat(4, auto)', gap: 10, alignItems: 'center', fontSize: 12 }}>
                <div>{day.day}</div>
                <span className="role-tag">Alerts {day.alerts}</span>
                <span className="role-tag">Contained {day.autoContained}</span>
                <span className="role-tag">Resolved {day.resolved}</span>
                <span className="role-tag">Dismissed {day.dismissed}</span>
              </div>
            ))}
            {!posture?.trend?.length && <div className="text-muted">Trend builds as alerts and cases accumulate.</div>}
          </div>
          <div style={{ marginTop: 14 }}>
            <button className="btn btn-ghost" onClick={() => generate('monthly', () => generateMonthlySummaryPDF(alerts as any, stats as any, new Date().toLocaleString('en-GB', { month: 'long', year: 'numeric' })))} disabled={generating === 'monthly'}>
              {generating === 'monthly' ? 'Generating…' : '↓ Monthly PDF'}
            </button>
          </div>
        </div>
      </div>

      <TestMailPanel />
    </div>
  );
}
