import React, { useState } from 'react';

interface Props {
  onAlertTriggered: () => void;
}

const SCENARIOS = [
  // ── Sign-in anomalies ──────────────────────────────────────────────────
  {
    key: 'impossible_travel',
    label: '✈️ Impossible Travel',
    desc: 'Global Admin: Tel Aviv → Tokyo in 40 minutes (9,200 km)',
    severity: 'critical',
    category: 'Sign-in'
  },
  {
    key: 'new_country',
    label: '🌍 New Country',
    desc: 'Intune Admin first sign-in from North Korea',
    severity: 'high',
    category: 'Sign-in'
  },
  {
    key: 'unknown_device',
    label: '📱 Unknown Device',
    desc: 'Intune Admin on unrecognized Android in Beijing',
    severity: 'medium',
    category: 'Sign-in'
  },
  {
    key: 'off_hours',
    label: '🌙 Off-Hours Sign-in',
    desc: 'Security Admin signs in at 03:14 UTC from Berlin',
    severity: 'low',
    category: 'Sign-in'
  },
  {
    key: 'failed_mfa',
    label: '🔐 MFA Failure',
    desc: 'Exchange Admin — MFA rejected from Russia (error 500121)',
    severity: 'high',
    category: 'Sign-in'
  },
  {
    key: 'high_risk',
    label: '☠️ High Entra Risk',
    desc: 'Global Admin flagged by Entra ID — leaked creds / anonymous proxy',
    severity: 'critical',
    category: 'Sign-in'
  },
  {
    key: 'high_velocity',
    label: '⚡ Sign-in Velocity',
    desc: '12 sign-ins in 10 min from Ukraine — credential stuffing pattern',
    severity: 'medium',
    category: 'Sign-in'
  },
  // ── Audit / action anomalies ───────────────────────────────────────────
  {
    key: 'lateral_movement',
    label: '🔀 Lateral Movement',
    desc: 'SharePoint Admin adds himself to Global Admin + grants Graph permissions',
    severity: 'critical',
    category: 'Audit'
  },
  {
    key: 'unusual_deletion',
    label: '🗑️ Unusual Deletions',
    desc: 'User Admin deletes 17 objects in one session (avg 1.2/day)',
    severity: 'high',
    category: 'Audit'
  },
  {
    key: 'unusual_rule_creation',
    label: '📋 Suspicious Policy Creation',
    desc: 'CA Admin creates 4 new CA policies + named location in one session',
    severity: 'high',
    category: 'Audit'
  },
];

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

export default function MockPanel({ onAlertTriggered }: Props) {
  const [loading, setLoading]   = useState<string | null>(null);
  const [results, setResults]   = useState<Record<string, { ok: boolean; message: string }>>({});
  const [sendEmail, setSendEmail] = useState(false);
  const [activeCategory, setActiveCategory] = useState<'All' | 'Sign-in' | 'Audit'>('All');

  const trigger = async (scenario: string) => {
    setLoading(scenario);
    setResults(prev => ({ ...prev, [scenario]: undefined as any }));
    try {
      const res = await fetch('/api/mock/trigger-alert', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ scenario, sendEmail })
      });
      const data = await res.json();
      const emailMsg = sendEmail
        ? data.emailSent ? '✅ Email sent' : `❌ Email failed: ${data.emailError}`
        : '✅ Alert created';
      setResults(prev => ({ ...prev, [scenario]: { ok: true, message: emailMsg } }));
      onAlertTriggered();
    } catch (err: any) {
      setResults(prev => ({ ...prev, [scenario]: { ok: false, message: 'Failed: ' + err.message } }));
    } finally {
      setLoading(null);
    }
  };

  const triggerAll = async () => {
    const visible = SCENARIOS.filter(s => activeCategory === 'All' || s.category === activeCategory);
    for (const s of visible) {
      await trigger(s.key);
      await new Promise(r => setTimeout(r, 300));
    }
  };

  const visible = SCENARIOS.filter(s => activeCategory === 'All' || s.category === activeCategory);
  const categories = ['All', 'Sign-in', 'Audit'] as const;

  return (
    <div className="mock-panel">
      <div className="mock-panel-header">
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700, color: 'var(--amber-500)' }}>
          ⚡ TEST ALERT TRIGGER
        </span>
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer' }}>
          <input type="checkbox" checked={sendEmail} onChange={e => setSendEmail(e.target.checked)} style={{ accentColor: 'var(--amber-500)' }} />
          Send real email
        </label>
      </div>

      {/* Category tabs */}
      <div style={{ display: 'flex', gap: 6, padding: '10px 16px 0', borderBottom: '1px solid var(--navy-border)' }}>
        {categories.map(cat => (
          <button
            key={cat}
            onClick={() => setActiveCategory(cat)}
            style={{
              background: activeCategory === cat ? 'rgba(232,120,74,0.15)' : 'transparent',
              border: activeCategory === cat ? '1px solid rgba(232,120,74,0.4)' : '1px solid transparent',
              borderRadius: 6, padding: '4px 12px', fontSize: 12, cursor: 'pointer',
              color: activeCategory === cat ? '#E8784A' : 'var(--text-muted)',
              fontWeight: activeCategory === cat ? 600 : 400,
            }}
          >
            {cat} {cat !== 'All' && <span style={{ opacity: 0.6 }}>({SCENARIOS.filter(s => s.category === cat).length})</span>}
          </button>
        ))}
        <button
          className="btn btn-sm btn-ghost"
          style={{ marginLeft: 'auto', fontSize: 11 }}
          disabled={!!loading}
          onClick={triggerAll}
        >
          🚀 Trigger all ({visible.length})
        </button>
      </div>

      <div className="mock-scenarios">
        {visible.map(s => {
          const res = results[s.key];
          return (
            <div key={s.key} className="mock-scenario-card">
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 600, fontSize: 13 }}>{s.label}</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{s.desc}</div>
                {res && (
                  <div style={{ fontSize: 11, marginTop: 4, color: res.ok ? '#00C98B' : '#ff4444' }}>
                    {res.message}
                  </div>
                )}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
                <span className={`severity-badge ${s.severity}`}>{s.severity}</span>
                <button
                  className="btn btn-primary btn-sm"
                  onClick={() => trigger(s.key)}
                  disabled={loading === s.key}
                  style={{ minWidth: 64 }}
                >
                  {loading === s.key ? '⟳' : 'Trigger'}
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
