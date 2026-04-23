import React, { useState } from 'react';
import { apiFetch } from '../services/api';

const GUMROAD_URL = 'https://moderne.gumroad.com/l/azxxv';

const FREE_FEATURES = [
  'Sign-in anomaly detection (60s scan cycle)',
  'Alert dashboard & history',
  'User risk overview',
  'Manual investigation tools',
  'Basic sign-in log access',
];

const PREMIUM_FEATURES = [
  'Telegram alerts with action buttons',
  'Email notifications (multi-admin)',
  'Automated session revoke',
  'Automated user disable',
  'Conditional Access management',
  'PIM privilege monitoring',
  'Audit Center (365 days)',
  'Reports & exports',
  'Priority support',
];

const FAQ_ITEMS = [
  {
    q: 'What happens if I cancel?',
    a: 'Your account stays active on the Free tier — detection keeps running, and you can still view all alerts. Premium notifications and auto-remediation are paused until you resubscribe.',
  },
  {
    q: 'Do I need a credit card to start?',
    a: 'No. The Free tier is free forever with no credit card required.',
  },
  {
    q: 'Do you store my tenant data?',
    a: 'All data stays in your own Azure subscription. We never see your tenant data.',
  },
];

export default function PricingPage() {
  const [loading, setLoading] = useState(false);
  const [error, setError]   = useState('');

  const handleUpgrade = async () => {
    setLoading(true);
    setError('');
    try {
      // Try to get a pre-filled URL (works when user is logged in)
      const res = await apiFetch<{ url: string }>('/billing/checkout').catch(() => null);
      window.location.href = res?.url || GUMROAD_URL;
    } catch {
      window.location.href = GUMROAD_URL;
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        minHeight: '100vh',
        background: 'radial-gradient(ellipse at 50% 0%, rgba(232,120,74,0.06) 0%, transparent 55%), #0C0C11',
        color: 'var(--text-primary)',
        fontFamily: 'var(--font-sans)',
        padding: '0 16px 80px',
      }}
    >
      {/* ── Header ── */}
      <div style={{ textAlign: 'center', padding: '72px 16px 40px', maxWidth: 640, margin: '0 auto' }}>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 10, marginBottom: 20 }}>
          <div
            style={{
              width: 40, height: 40, borderRadius: 12,
              background: 'linear-gradient(135deg, #E8784A, #F5A462)',
              boxShadow: '0 0 20px rgba(232,120,74,0.35)',
              display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 20,
            }}
          >
            🛡️
          </div>
          <span style={{ fontSize: 14, fontWeight: 700, letterSpacing: 0.3 }}>IdentityMonitor</span>
        </div>
        <h1 style={{ fontSize: 38, fontWeight: 800, letterSpacing: -0.5, marginBottom: 12, lineHeight: 1.15 }}>
          Free to monitor. Pay to act.
        </h1>
        <p style={{ fontSize: 16, color: 'var(--text-secondary)', marginBottom: 0 }}>
          Detection runs for everyone. Premium unlocks real-time alerts and automated response.
        </p>
      </div>

      {/* ── Plans side-by-side ── */}
      <div
        style={{
          display: 'flex', gap: 24, justifyContent: 'center', flexWrap: 'wrap',
          maxWidth: 860, margin: '0 auto 64px',
        }}
      >
        {/* Free card */}
        <div
          style={{
            flex: '1 1 340px', maxWidth: 400,
            background: 'rgba(255,255,255,0.035)',
            border: '1px solid rgba(255,255,255,0.09)',
            borderRadius: 20, padding: '32px 28px',
            display: 'flex', flexDirection: 'column', gap: 0,
          }}
        >
          <div style={{ marginBottom: 20 }}>
            <span
              style={{
                display: 'inline-block', padding: '3px 12px', borderRadius: 99,
                fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.6,
                background: 'rgba(255,255,255,0.07)', color: 'var(--text-secondary)',
                border: '1px solid rgba(255,255,255,0.12)',
              }}
            >
              Free forever
            </span>
          </div>

          <h2 style={{ fontSize: 22, fontWeight: 700, marginBottom: 6 }}>Free</h2>

          <div style={{ marginBottom: 28, display: 'flex', alignItems: 'baseline', gap: 4 }}>
            <span style={{ fontSize: 42, fontWeight: 800, letterSpacing: -1 }}>$0</span>
            <span style={{ fontSize: 14, color: 'var(--text-secondary)' }}>/month</span>
          </div>

          <ul style={{ listStyle: 'none', padding: 0, margin: '0 0 32px', display: 'flex', flexDirection: 'column', gap: 10 }}>
            {FREE_FEATURES.map((f) => (
              <li key={f} style={{ display: 'flex', alignItems: 'flex-start', gap: 10, fontSize: 13 }}>
                <span
                  style={{
                    flexShrink: 0, width: 18, height: 18, borderRadius: '50%',
                    background: 'rgba(0,201,139,0.12)', border: '1px solid rgba(0,201,139,0.30)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: 10, marginTop: 1,
                  }}
                >✓</span>
                {f}
              </li>
            ))}
          </ul>

          <div
            style={{
              marginTop: 'auto', padding: '13px 0', borderRadius: 10,
              background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.10)',
              textAlign: 'center', fontSize: 14, fontWeight: 600,
              color: 'var(--text-secondary)',
            }}
          >
            Your current plan
          </div>
        </div>

        {/* Pro card */}
        <div
          style={{
            flex: '1 1 340px', maxWidth: 400,
            background: 'rgba(232,120,74,0.06)',
            border: '1px solid rgba(232,120,74,0.30)',
            borderRadius: 20, padding: '32px 28px',
            display: 'flex', flexDirection: 'column', gap: 0,
            boxShadow: '0 0 40px rgba(232,120,74,0.10)',
          }}
        >
          <div style={{ marginBottom: 20 }}>
            <span
              style={{
                display: 'inline-block', padding: '3px 12px', borderRadius: 99,
                fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.6,
                background: 'rgba(232,120,74,0.12)', color: '#E8784A',
                border: '1px solid rgba(232,120,74,0.35)',
              }}
            >
              Pro
            </span>
          </div>

          <h2 style={{ fontSize: 22, fontWeight: 700, marginBottom: 6 }}>Pro</h2>

          <div style={{ marginBottom: 28, display: 'flex', alignItems: 'baseline', gap: 4 }}>
            <span style={{ fontSize: 42, fontWeight: 800, letterSpacing: -1, color: '#E8784A' }}>$15</span>
            <span style={{ fontSize: 14, color: 'var(--text-secondary)' }}>/month</span>
          </div>

          <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 20, lineHeight: 1.6 }}>
            Everything in Free, plus:
          </p>

          <ul style={{ listStyle: 'none', padding: 0, margin: '0 0 32px', display: 'flex', flexDirection: 'column', gap: 10 }}>
            {PREMIUM_FEATURES.map((f) => (
              <li key={f} style={{ display: 'flex', alignItems: 'flex-start', gap: 10, fontSize: 13 }}>
                <span
                  style={{
                    flexShrink: 0, width: 18, height: 18, borderRadius: '50%',
                    background: 'rgba(232,120,74,0.15)', border: '1px solid rgba(232,120,74,0.40)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: 10, marginTop: 1, color: '#E8784A',
                  }}
                >✓</span>
                {f}
              </li>
            ))}
          </ul>

          <button
            onClick={handleUpgrade}
            disabled={loading}
            style={{
              marginTop: 'auto', padding: '13px 0', borderRadius: 10, border: 'none',
              cursor: loading ? 'not-allowed' : 'pointer',
              fontFamily: 'var(--font-sans)', fontSize: 14, fontWeight: 700, letterSpacing: 0.2,
              background: 'linear-gradient(135deg, #E8784A, #F5A462)',
              color: '#fff', boxShadow: '0 4px 18px rgba(232,120,74,0.30)',
              opacity: loading ? 0.7 : 1,
            }}
          >
            {loading ? (
              <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
                <span
                  style={{
                    display: 'inline-block', width: 14, height: 14,
                    border: '2px solid currentColor', borderTopColor: 'transparent',
                    borderRadius: '50%', animation: 'spin 0.8s linear infinite',
                  }}
                />
                Redirecting…
              </span>
            ) : (
              'Upgrade to Pro →'
            )}
          </button>
        </div>
      </div>

      {/* ── Error ── */}
      {error && (
        <div
          style={{
            maxWidth: 640, margin: '-40px auto 40px',
            background: 'rgba(255,68,85,0.08)', border: '1px solid rgba(255,68,85,0.25)',
            borderRadius: 10, padding: '12px 16px', color: 'var(--red-critical)',
            fontSize: 13, textAlign: 'center',
          }}
        >
          {error}
        </div>
      )}

      {/* ── FAQ ── */}
      <div style={{ maxWidth: 640, margin: '0 auto' }}>
        <h3 style={{ fontSize: 18, fontWeight: 700, textAlign: 'center', marginBottom: 24 }}>
          Frequently asked questions
        </h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {FAQ_ITEMS.map((item) => (
            <div
              key={item.q}
              style={{
                background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)',
                borderRadius: 12, padding: '16px 20px',
              }}
            >
              <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 6 }}>{item.q}</div>
              <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{item.a}</div>
            </div>
          ))}
        </div>
        <div style={{ textAlign: 'center', marginTop: 48, fontSize: 12, color: 'var(--text-muted)' }}>
          Already have an account?{' '}
          <a href="/" style={{ color: '#E8784A', textDecoration: 'none', fontWeight: 600 }}>Sign in</a>
        </div>
      </div>
    </div>
  );
}
