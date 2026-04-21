import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  BarChart, Bar, Cell, XAxis, YAxis, Tooltip, ResponsiveContainer,
  CartesianGrid, Legend,
} from 'recharts';
import { api } from '../services/api';
import { Alert, AlertStats, RiskPosture } from '../types';
import { generateMonthlySummaryPDF, generateExecutiveSummaryPDF } from '../services/pdfReport';
import TestMailPanel from './TestMailPanel';

// ── Design tokens ────────────────────────────────────────────────────────────
const CORAL   = '#E8784A';
const AMBER   = '#F5A462';
const GREEN   = '#34C97D';
const RED     = '#EF4444';
const ORANGE  = '#F97316';
const YELLOW  = '#EAB308';
const BLUE    = '#3B82F6';
const PURPLE  = '#9B8AFB';

// ── MetricCard ────────────────────────────────────────────────────────────────
interface MetricCardProps {
  label: string;
  value: string | number;
  tone?: 'critical' | 'amber' | 'clean' | 'neutral' | 'medium';
  sub?: string;
  onClick?: () => void;
}
function MetricCard({ label, value, tone = 'neutral', sub, onClick }: MetricCardProps) {
  return (
    <div
      className={`stat-card ${tone}`}
      onClick={onClick}
      style={{ cursor: onClick ? 'pointer' : undefined, position: 'relative' }}
    >
      {onClick && (
        <span style={{ position: 'absolute', top: 10, right: 12, fontSize: 11, color: 'var(--text-muted)', opacity: 0.6 }}>
          →
        </span>
      )}
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
      {sub && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{sub}</div>}
    </div>
  );
}

// ── Custom tooltip for charts ────────────────────────────────────────────────
function ChartTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: 'var(--navy-card)', border: '1px solid var(--navy-border)', borderRadius: 8, padding: '8px 12px', fontSize: 12 }}>
      <div style={{ fontWeight: 600, marginBottom: 4 }}>{label}</div>
      {payload.map((p: any) => (
        <div key={p.dataKey} style={{ color: p.color }}>
          {p.name}: <strong>{p.value}</strong>
        </div>
      ))}
    </div>
  );
}

// ── Severity bar chart ───────────────────────────────────────────────────────
function SeverityChart({ data }: { data: Record<string, number> }) {
  const bars = [
    { key: 'critical', label: 'Critical', color: RED },
    { key: 'high',     label: 'High',     color: ORANGE },
    { key: 'medium',   label: 'Medium',   color: YELLOW },
    { key: 'low',      label: 'Low',      color: BLUE },
  ].map(b => ({ name: b.label, value: data[b.key] ?? 0, color: b.color }));

  return (
    <ResponsiveContainer width="100%" height={180}>
      <BarChart data={bars} layout="vertical" margin={{ left: 0, right: 20, top: 0, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--navy-border)" horizontal={false} />
        <XAxis type="number" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
        <YAxis type="category" dataKey="name" width={58} tick={{ fill: 'var(--text-secondary)', fontSize: 12 }} axisLine={false} tickLine={false} />
        <Tooltip content={<ChartTooltip />} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
        <Bar dataKey="value" radius={[0, 6, 6, 0]} maxBarSize={24}>
          {bars.map(b => <Cell key={b.name} fill={b.color} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

// ── Trend bar chart ──────────────────────────────────────────────────────────
function TrendChart({ days }: { days: any[] }) {
  const data = days.slice(-14).map(d => ({
    day: d.day?.slice(5) ?? d.day,
    Alerts:    d.alerts      ?? 0,
    Resolved:  d.resolved    ?? 0,
    Dismissed: d.dismissed   ?? 0,
  }));

  if (!data.length) return <div className="text-muted" style={{ padding: 24, textAlign: 'center' }}>Trend builds as alerts accumulate.</div>;

  return (
    <ResponsiveContainer width="100%" height={200}>
      <BarChart data={data} margin={{ left: -10, right: 8, top: 4, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--navy-border)" vertical={false} />
        <XAxis dataKey="day" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} axisLine={false} tickLine={false} />
        <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 10 }} axisLine={false} tickLine={false} />
        <Tooltip content={<ChartTooltip />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
        <Legend wrapperStyle={{ fontSize: 11, color: 'var(--text-secondary)' }} />
        <Bar dataKey="Alerts"    fill={CORAL}  radius={[3,3,0,0]} maxBarSize={14} />
        <Bar dataKey="Resolved"  fill={GREEN}  radius={[3,3,0,0]} maxBarSize={14} />
        <Bar dataKey="Dismissed" fill={AMBER}  radius={[3,3,0,0]} maxBarSize={14} />
      </BarChart>
    </ResponsiveContainer>
  );
}

// ── Anomaly horizontal chart ──────────────────────────────────────────────────
function AnomalyChart({ categories }: { categories: { name: string; count: number }[] }) {
  if (!categories.length) return <div className="text-muted" style={{ padding: 24, textAlign: 'center' }}>No anomaly categories yet.</div>;

  return (
    <ResponsiveContainer width="100%" height={Math.max(140, categories.length * 36)}>
      <BarChart data={categories} layout="vertical" margin={{ left: 0, right: 28, top: 0, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--navy-border)" horizontal={false} />
        <XAxis type="number" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
        <YAxis type="category" dataKey="name" width={140} tick={{ fill: 'var(--text-secondary)', fontSize: 11 }} axisLine={false} tickLine={false} />
        <Tooltip content={<ChartTooltip />} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
        <Bar dataKey="count" name="Events" fill={PURPLE} radius={[0, 6, 6, 0]} maxBarSize={22} />
      </BarChart>
    </ResponsiveContainer>
  );
}

// ── Score ring ───────────────────────────────────────────────────────────────
function ScoreRing({ score }: { score: number }) {
  const r = 44;
  const circ = 2 * Math.PI * r;
  const fill = circ * (score / 100);
  const color = score < 55 ? RED : score < 75 ? ORANGE : GREEN;
  return (
    <svg width={110} height={110} viewBox="0 0 110 110" style={{ flexShrink: 0 }}>
      <circle cx="55" cy="55" r={r} fill="none" stroke="var(--navy-border)" strokeWidth={10} />
      <circle cx="55" cy="55" r={r} fill="none" stroke={color} strokeWidth={10}
        strokeDasharray={`${fill} ${circ}`} strokeLinecap="round" transform="rotate(-90 55 55)" />
      <text x="55" y="51" textAnchor="middle" fill={color} fontSize={22} fontWeight={700}>{score}</text>
      <text x="55" y="67" textAnchor="middle" fill="var(--text-muted)" fontSize={11}>/100</text>
    </svg>
  );
}

// ── Main component ───────────────────────────────────────────────────────────
export default function ReportsPage() {
  const navigate = useNavigate();
  const [alerts, setAlerts]   = useState<Alert[]>([]);
  const [stats, setStats]     = useState<AlertStats | null>(null);
  const [posture, setPosture] = useState<RiskPosture | null>(null);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState<string | null>(null);
  const [loadedAt] = useState(() => new Date().toLocaleTimeString());

  useEffect(() => {
    Promise.all([
      api.getAlerts({}),
      api.getAlertStats(),
      api.getRiskPosture().catch(() => null),
    ]).then(([a, s, p]) => {
      setAlerts(a as Alert[]);
      setStats(s as AlertStats);
      setPosture(p as RiskPosture | null);
    }).finally(() => setLoading(false));
  }, []);

  const executive = useMemo(() => {
    const avgScore = posture?.summary.averageRiskScore ?? 0;
    const score = Math.max(12, Math.min(96, Math.round(100 - avgScore)));
    const headline = score < 55
      ? 'Privileged posture is under pressure — active containment needed.'
      : score < 75
      ? 'Posture is stable but alert backlog and approval latency need attention.'
      : 'Posture is healthy. Focus on tuning, reporting, and readiness validation.';
    return { score, headline };
  }, [posture]);

  const resolutionRate = useMemo(() => {
    const sev = posture?.summary.alertsBySeverity ?? {};
    const total = Object.values(sev).reduce((a: number, v: any) => a + (v as number), 0);
    const resolved = (posture?.trend ?? []).reduce((a: number, d: any) => a + (d.resolved ?? 0), 0);
    if (!total) return '—';
    return `${Math.round((resolved / Math.max(total, resolved)) * 100)}%`;
  }, [posture]);

  const generate = (type: string, fn: () => void) => {
    setGenerating(type);
    setTimeout(() => { fn(); setGenerating(null); }, 100);
  };

  if (loading) {
    return (
      <div className="loading-state">
        <div className="loading-spinner" />
        <div className="loading-text">Loading posture and reporting…</div>
      </div>
    );
  }

  const sev = posture?.summary.alertsBySeverity ?? {};
  const hasAnomalies = (posture?.topAnomalyCategories ?? []).length > 0;

  return (
    <div>
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="page-header">
        <div>
          <div className="page-title">Posture & Reports</div>
          <div className="page-subtitle">
            Executive reporting · risk posture · response performance
            <span style={{ marginLeft: 12, fontSize: 11, color: 'var(--text-muted)' }}>
              Loaded {loadedAt}
            </span>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <div className="role-tag">Retention {posture?.summary.retention?.incidentDays || 180}d</div>
          <button className="btn btn-ghost" style={{ fontSize: 12 }}
            onClick={() => { setLoading(true); Promise.all([api.getAlerts({}), api.getAlertStats(), api.getRiskPosture().catch(() => null)]).then(([a, s, p]) => { setAlerts(a as Alert[]); setStats(s as AlertStats); setPosture(p as RiskPosture | null); }).finally(() => setLoading(false)); }}>
            ↻ Refresh
          </button>
        </div>
      </div>

      {/* ── Metric row ─────────────────────────────────────────────────── */}
      <div className="stats-grid" style={{ marginBottom: 24 }}>
        <MetricCard label="Executive score" value={executive.score}
          tone={executive.score < 55 ? 'critical' : executive.score < 75 ? 'amber' : 'clean'} />
        <MetricCard label="Avg risk score" value={posture?.summary.averageRiskScore ?? 0} tone="medium" />
        <MetricCard label="MTTA (hours)" value={posture?.summary.mttaHours ?? '—'} tone="neutral"
          sub="Mean time to acknowledge" />
        <MetricCard label="MTTR (hours)" value={posture?.summary.mttrHours ?? '—'} tone="neutral"
          sub="Mean time to resolve" />
        <MetricCard label="Auto-contained" value={posture?.summary.autoContainedIncidents ?? 0} tone="clean"
          sub="Playbook executions" />
        <MetricCard label="Resolution rate" value={resolutionRate} tone="neutral"
          sub="Resolved ÷ total alerts"
          onClick={() => navigate('/alerts?status=resolved')} />
      </div>

      {/* ── Executive narrative + Severity chart ───────────────────────── */}
      <div className="two-col" style={{ marginBottom: 24 }}>
        <div className="card">
          <div className="card-header">
            <div className="card-title">Executive narrative</div>
            <span className="role-tag">Security manager view</span>
          </div>
          <div style={{ display: 'flex', gap: 20, alignItems: 'center', marginBottom: 16 }}>
            <ScoreRing score={executive.score} />
            <div>
              <div style={{ fontSize: 15, fontWeight: 600, lineHeight: 1.4, marginBottom: 10 }}>
                {executive.headline}
              </div>
              <div className="action-list">
                <div className="action-list-item">Monitored privileged accounts: <strong>{posture?.summary.monitoredPrivilegedAccounts ?? 0}</strong></div>
                <div className="action-list-item">Reporting retention: <strong>{posture?.summary.retention?.reportDays ?? 365} days</strong></div>
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button className="btn btn-primary"
              onClick={() => generate('executive', () => generateExecutiveSummaryPDF(alerts as any, stats as any))}
              disabled={generating === 'executive'}>
              {generating === 'executive' ? 'Generating…' : '↓ Executive PDF'}
            </button>
            <button className="btn btn-ghost"
              onClick={() => window.open(api.executiveExportUrl('csv'), '_blank')}>
              ↓ CSV
            </button>
            <button className="btn btn-ghost"
              onClick={() => window.open(api.executiveExportUrl('json'), '_blank')}>
              ↓ JSON
            </button>
            <button className="btn btn-ghost"
              onClick={() => generate('monthly', () => generateMonthlySummaryPDF(alerts as any, stats as any, new Date().toLocaleString('en-GB', { month: 'long', year: 'numeric' })))}
              disabled={generating === 'monthly'}>
              {generating === 'monthly' ? 'Generating…' : '↓ Monthly PDF'}
            </button>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">Alert severity breakdown</div>
            <span className="role-tag">All time</span>
          </div>
          <SeverityChart data={sev} />
          <div style={{ display: 'flex', gap: 16, marginTop: 14, flexWrap: 'wrap' }}>
            {[
              { key: 'critical', label: 'Critical', color: RED },
              { key: 'high',     label: 'High',     color: ORANGE },
              { key: 'medium',   label: 'Medium',   color: YELLOW },
              { key: 'low',      label: 'Low',      color: BLUE },
            ].map(s => (
              <div key={s.key}
                style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, cursor: 'pointer', color: 'var(--text-secondary)' }}
                onClick={() => navigate(`/alerts?severity=${s.key}`)}>
                <span style={{ width: 10, height: 10, borderRadius: 2, background: s.color, flexShrink: 0 }} />
                {s.label} <strong style={{ color: 'var(--text-primary)' }}>{sev[s.key] ?? 0}</strong>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Response trend + Anomaly chart ─────────────────────────────── */}
      <div className="two-col" style={{ marginBottom: 24 }}>
        <div className="card">
          <div className="card-header">
            <div className="card-title">14-day response trend</div>
            <span className="role-tag">Operational view</span>
          </div>
          <TrendChart days={posture?.trend ?? []} />
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">Top anomaly categories</div>
            <span className="role-tag">Last 30 days</span>
          </div>
          {hasAnomalies
            ? <AnomalyChart categories={posture!.topAnomalyCategories} />
            : <div className="text-muted" style={{ padding: '24px 0', textAlign: 'center' }}>No category trend yet.</div>
          }
        </div>
      </div>

      {/* ── Risky admins ───────────────────────────────────────────────── */}
      <div className="card" style={{ marginBottom: 24 }}>
        <div className="card-header">
          <div className="card-title">Most risky admins</div>
          <span className="role-tag">Privileged risk score · click to drill down</span>
        </div>
        {(posture?.mostRiskyAdmins ?? []).length === 0
          ? <div className="text-muted">No privileged risk posture yet.</div>
          : (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 }}>
              {(posture?.mostRiskyAdmins ?? []).slice(0, 8).map(admin => {
                const scoreColor = admin.score >= 70 ? RED : admin.score >= 45 ? ORANGE : AMBER;
                return (
                  <div key={admin.userId}
                    onClick={() => navigate(`/users?userId=${admin.userId}`)}
                    style={{
                      padding: '14px 16px',
                      border: `1px solid ${scoreColor}44`,
                      borderLeft: `4px solid ${scoreColor}`,
                      borderRadius: 12,
                      cursor: 'pointer',
                      background: 'var(--navy-card)',
                      transition: 'background 0.15s',
                    }}
                    onMouseEnter={e => (e.currentTarget.style.background = 'var(--navy-hover)')}
                    onMouseLeave={e => (e.currentTarget.style.background = 'var(--navy-card)')}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 }}>
                      <div style={{ minWidth: 0 }}>
                        <div style={{ fontWeight: 700, fontSize: 14, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {admin.displayName}
                        </div>
                        <div className="text-muted" style={{ fontSize: 11, marginTop: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {admin.userPrincipalName}
                        </div>
                      </div>
                      <div style={{ background: scoreColor, color: '#fff', fontWeight: 700, fontSize: 13, padding: '3px 10px', borderRadius: 20, flexShrink: 0 }}>
                        {admin.score}
                      </div>
                    </div>
                    <div style={{ marginTop: 10, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                      <span className="role-tag" style={{ background: 'rgba(239,68,68,0.12)', color: '#EF4444' }}>
                        {admin.openAlerts} open alerts
                      </span>
                      {admin.baseline?.knownCountries?.length > 0 && (
                        <span className="role-tag">{admin.baseline.knownCountries.length} countries</span>
                      )}
                    </div>
                    {admin.roles?.length > 0 && (
                      <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.4 }}>
                        {admin.roles.slice(0, 3).join(' · ')}
                        {admin.roles.length > 3 && ` +${admin.roles.length - 3} more`}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )
        }
      </div>

      {/* ── Mail test panel ────────────────────────────────────────────── */}
      <TestMailPanel />
    </div>
  );
}
