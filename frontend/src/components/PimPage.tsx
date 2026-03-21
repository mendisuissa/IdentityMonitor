import React, { useEffect, useState } from 'react';

interface PimResult {
  score: number;
  grade: { letter: string; label: string; color: string };
  findings: any[];
  recommendations: any[];
  recommendationSummary?: { riskBased: number; bestPractice: number };
  stats: any;
  warnings?: string[];
  analyzedAt: string;
}

const EFFORT_LABEL: Record<string, string> = { low: '⚡ Quick win', medium: '🔧 Some effort', high: '🏗️ Major project' };
const PRIORITY_COLOR: Record<string, string> = { critical: '#ff3b3b', high: '#ff6b35', medium: '#f5a623', low: '#4a90d9' };

export default function PimPage() {
  const [data, setData]     = useState<PimResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]   = useState('');

  useEffect(() => {
    fetch('/api/pim/analyze', { credentials: 'include' })
      .then(r => r.json())
      .then(d => { if (d.error) setError(d.error); else setData(d); })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="loading-state"><div className="loading-spinner" /><div className="loading-text">Analyzing PIM configuration...</div></div>;

  if (error) return (
    <div className="card" style={{ borderLeft: '3px solid var(--amber-500)' }}>
      <div style={{ fontWeight: 700, color: 'var(--amber-400)', marginBottom: 8 }}>⚠️ PIM Analysis unavailable</div>
      <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>{error}</div>
    </div>
  );

  if (!data) return null;
  const { score, grade, findings, recommendations, recommendationSummary, stats, warnings = [] } = data;
  const riskRecommendations = recommendations.filter((r: any) => (r.type || 'risk') === 'risk');
  const bestPracticeRecommendations = recommendations.filter((r: any) => (r.type || 'risk') === 'best-practice');

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">PIM Security Analysis</div>
          <div className="page-subtitle">Privileged Identity Management — detect permanent admins, missing JIT, over-privilege</div>
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          Last analyzed: {new Date(data.analyzedAt).toLocaleString()}
        </div>
      </div>

      {warnings.length > 0 && (
        <div className="card" style={{ marginBottom: 16, borderLeft: '3px solid var(--amber-500)' }}>
          <div style={{ fontWeight: 700, color: 'var(--amber-400)', marginBottom: 8 }}>Telemetry warning</div>
          {warnings.map((w, i) => <div key={i} style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 6 }}>{w}</div>)}
        </div>
      )}

      {/* Score Banner */}
      <div className="card" style={{ marginBottom: 20, background: `linear-gradient(135deg, var(--navy-900), var(--navy-800))`, borderColor: grade.color + '40' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 28, flexWrap: 'wrap' }}>
          <div style={{ textAlign: 'center', flexShrink: 0 }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 72, fontWeight: 700, color: grade.color, lineHeight: 1 }}>{grade.letter}</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>{grade.label}</div>
          </div>
          <div style={{ flex: 1, borderLeft: '1px solid var(--navy-border)', paddingLeft: 28 }}>
            <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 6 }}>
              PIM Score: <span style={{ color: grade.color, fontFamily: 'var(--font-mono)' }}>{score}/100</span>
            </div>
            {/* Score bar */}
            <div style={{ height: 8, background: 'var(--navy-700)', borderRadius: 4, marginBottom: 12, overflow: 'hidden' }}>
              <div style={{ height: '100%', width: score + '%', background: grade.color, borderRadius: 4, transition: 'width 1s ease' }} />
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 12 }}>
              {[
                { label: 'Permanent Roles', value: stats.permanentCount, warn: stats.permanentCount > 3 },
                { label: 'JIT (Eligible)', value: stats.eligibleCount, good: stats.eligibleCount > 0 },
                { label: 'Global Admins', value: stats.globalAdmins, warn: stats.globalAdmins > 2 },
                { label: 'PIM Enabled', value: stats.pimEnabled ? '✓ Yes' : '✗ No', good: stats.pimEnabled, bad: !stats.pimEnabled }
              ].map(s => (
                <div key={s.label} style={{ padding: '8px 12px', background: 'var(--navy-800)', borderRadius: 6, border: '1px solid var(--navy-border)' }}>
                  <div style={{ fontSize: 18, fontWeight: 700, fontFamily: 'var(--font-mono)', color: (s as any).bad ? '#ff3b3b' : (s as any).good ? '#2ecc71' : (s as any).warn ? '#f5a623' : 'var(--text-primary)' }}>{s.value}</div>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginTop: 2 }}>{s.label}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="two-col">
        {/* Findings */}
        <div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px', color: 'var(--text-muted)', marginBottom: 12 }}>
            🔍 Findings ({findings.length})
          </div>
          {findings.length === 0 ? (
            <div className="card">
              <div className="empty-state">
                <div className="empty-icon">{stats?.telemetryIncomplete ? '⚠️' : '✅'}</div>
                <div className="empty-text">{stats?.telemetryIncomplete ? 'No live role evidence returned from Graph yet. Do not treat this as a clean PIM result.' : 'No issues found — excellent PIM hygiene!'}</div>
              </div>
            </div>
          ) : findings.map((f, i) => (
            <div key={i} className="card" style={{ marginBottom: 12, borderLeft: `3px solid ${PRIORITY_COLOR[f.severity] || '#8ba3cc'}` }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                <span className={`severity-badge ${f.severity}`}>{f.severity}</span>
                <span style={{ fontWeight: 700, fontSize: 13 }}>{f.title}</span>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: f.recommendation ? 8 : 0 }}>{f.detail}</div>
              {f.recommendation && (
                <div style={{ fontSize: 11, color: 'var(--amber-400)', background: 'rgba(245,166,35,0.08)', padding: '6px 10px', borderRadius: 4, marginTop: 6 }}>
                  💡 {f.recommendation}
                </div>
              )}
              {f.users && f.users.length > 0 && (
                <div style={{ marginTop: 8, display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {f.users.slice(0, 3).map((u: any, j: number) => (
                    <span key={j} style={{ padding: '2px 8px', background: 'var(--navy-800)', border: '1px solid var(--navy-border)', borderRadius: 4, fontSize: 11, fontFamily: 'var(--font-mono)' }}>
                      {u.roleName?.replace(' Administrator', ' Admin')}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Recommendations */}
        <div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px', color: 'var(--text-muted)', marginBottom: 12 }}>
            🎯 Recommendations ({recommendations.length})
            <span style={{ marginLeft: 8, fontSize: 10, color: 'var(--text-muted)' }}>risk: {recommendationSummary?.riskBased ?? riskRecommendations.length} · best-practice: {recommendationSummary?.bestPractice ?? bestPracticeRecommendations.length}</span>
          </div>
          {recommendations.length === 0 ? (
            <div className="card">
              <div className="empty-state">
                <div className="empty-icon">📘</div>
                <div className="empty-text">No recommendations generated yet.</div>
              </div>
            </div>
          ) : recommendations.map((r, i) => (
            <div key={i} className="card" style={{ marginBottom: 12 }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8, marginBottom: 8 }}>
                <div style={{ fontWeight: 700, fontSize: 13, flex: 1 }}>{r.action}</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                  <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 700, fontFamily: 'var(--font-mono)', background: ((PRIORITY_COLOR[r.priority] || '#8ba3cc') + '20'), color: PRIORITY_COLOR[r.priority] || '#8ba3cc' }}>
                    {String(r.priority || 'low').toUpperCase()}
                  </span>
                  <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 700, fontFamily: 'var(--font-mono)', background: r.type === 'best-practice' ? 'rgba(74,144,217,0.14)' : 'rgba(245,166,35,0.12)', color: r.type === 'best-practice' ? '#4a90d9' : '#f5a623' }}>
                    {r.type === 'best-practice' ? 'BEST PRACTICE' : 'RISK'}
                  </span>
                </div>
              </div>
              <div style={{ fontSize: 12, color: 'var(--green-clean)', marginBottom: 6 }}>📈 {r.impact}</div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8 }}>{EFFORT_LABEL[r.effort] || r.effort}</div>
              {r.howTo && (
                <div style={{ fontSize: 11, color: 'var(--text-muted)', background: 'var(--navy-800)', padding: '6px 10px', borderRadius: 4, fontFamily: 'var(--font-mono)', lineHeight: 1.5 }}>
                  📍 {r.howTo}
                </div>
              )}
              {r.requiresLicense && (
                <div style={{ fontSize: 11, color: 'var(--amber-400)', marginTop: 6 }}>⚠️ Requires: {r.requiresLicense}</div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
