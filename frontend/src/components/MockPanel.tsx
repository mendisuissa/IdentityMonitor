import React, { useState } from 'react';

interface Props {
  onAlertTriggered: () => void;
}

const SCENARIOS = [
  {
    key: 'impossible_travel',
    label: '✈️ Impossible Travel',
    desc: 'Global Admin: Tel Aviv → Tokyo in 40 minutes',
    severity: 'critical'
  },
  {
    key: 'new_country',
    label: '🌍 New Country',
    desc: 'Intune Admin first sign-in from North Korea',
    severity: 'high'
  },
  {
    key: 'unknown_device',
    label: '📱 Unknown Device',
    desc: 'Intune Admin on unrecognized Android in Beijing',
    severity: 'medium'
  }
];

export default function MockPanel({ onAlertTriggered }: Props) {
  const [loading, setLoading] = useState<string | null>(null);
  const [result, setResult] = useState<{ ok: boolean; message: string } | null>(null);
  const [sendEmail, setSendEmail] = useState(true);

  const trigger = async (scenario: string) => {
    setLoading(scenario);
    setResult(null);
    try {
      const res = await fetch('/api/mock/trigger-alert', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ scenario, sendEmail })
      });
      const data = await res.json();
      const emailMsg = sendEmail
        ? data.emailSent
          ? '✅ Email sent! Check your inbox.'
          : `❌ Email failed: ${data.emailError}`
        : '📋 Alert logged (email disabled)';
      setResult({ ok: data.emailSent || !sendEmail, message: emailMsg });
      onAlertTriggered();
    } catch (err: any) {
      setResult({ ok: false, message: 'Request failed: ' + err.message });
    } finally {
      setLoading(null);
    }
  };

  return (
    <div className="mock-panel">
      <div className="mock-panel-header">
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700, color: 'var(--amber-500)' }}>
          ⚡ TEST ALERT TRIGGER
        </span>
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer' }}>
          <input
            type="checkbox"
            checked={sendEmail}
            onChange={e => setSendEmail(e.target.checked)}
            style={{ accentColor: 'var(--amber-500)' }}
          />
          Send real email to ALERT_ADMIN_EMAIL
        </label>
      </div>
      <div className="mock-scenarios">
        {SCENARIOS.map(s => (
          <div key={s.key} className="mock-scenario-card">
            <div>
              <div style={{ fontWeight: 600, fontSize: 13 }}>{s.label}</div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>{s.desc}</div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
              <span className={`severity-badge ${s.severity}`}>{s.severity}</span>
              <button
                className="btn btn-primary btn-sm"
                onClick={() => trigger(s.key)}
                disabled={loading === s.key}
              >
                {loading === s.key ? '⟳' : 'Trigger'}
              </button>
            </div>
          </div>
        ))}
      </div>
      {result && (
        <div style={{
          padding: '10px 32px',
          borderTop: '1px solid var(--navy-border)',
          fontSize: 13,
          color: result.ok ? 'var(--green-clean)' : 'var(--red-critical)'
        }}>
          {result.message}
          {result.ok && <span className="text-muted" style={{ marginLeft: 8 }}>— Check Alerts tab</span>}
        </div>
      )}
    </div>
  );
}
