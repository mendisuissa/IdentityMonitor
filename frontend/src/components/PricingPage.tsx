import React, { useState } from 'react';
import { apiFetch } from '../services/api';

interface CheckoutResponse {
  url: string;
}

type Plan = 'pro' | 'msp';

interface PricingFeature {
  text: string;
  included: boolean;
}

interface PricingCard {
  plan: Plan;
  name: string;
  price: number;
  badge: string;
  badgeColor: string;
  features: PricingFeature[];
  highlight: boolean;
}

const PLANS: PricingCard[] = [
  {
    plan: 'pro',
    name: 'Pro',
    price: 29,
    badge: 'Most Popular',
    badgeColor: '#E8784A',
    highlight: true,
    features: [
      { text: '1 Microsoft 365 tenant', included: true },
      { text: 'Real-time anomaly detection', included: true },
      { text: 'Telegram alerts with action buttons', included: true },
      { text: 'Email notifications', included: true },
      { text: 'Conditional Access management', included: true },
      { text: '180-day alert retention', included: true },
      { text: 'Audit Center', included: true },
    ],
  },
  {
    plan: 'msp',
    name: 'MSP',
    price: 99,
    badge: 'MSP',
    badgeColor: '#9B8AFB',
    highlight: false,
    features: [
      { text: 'Up to 10 Microsoft 365 tenants', included: true },
      { text: 'All Pro features', included: true },
      { text: 'MSP Fleet Dashboard', included: true },
      { text: 'Cross-tenant security sweep', included: true },
      { text: 'Bulk notifications', included: true },
      { text: 'Priority support', included: true },
      { text: 'Super Admin view', included: true },
    ],
  },
];

const FAQ_ITEMS = [
  {
    q: 'Can I cancel anytime?',
    a: 'Yes, cancel any time from your billing portal. No questions asked.',
  },
  {
    q: 'What happens after the trial?',
    a: "You'll be asked to add a payment method. If you don't, the account moves to read-only mode.",
  },
  {
    q: 'Do you store my data?',
    a: 'All data stays in your own Azure subscription. We never see your tenant data.',
  },
];

export default function PricingPage() {
  const [loading, setLoading] = useState<Plan | null>(null);
  const [error, setError] = useState('');

  const handleCheckout = async (plan: Plan) => {
    setLoading(plan);
    setError('');
    try {
      const res = await apiFetch<CheckoutResponse>('/billing/checkout', {
        method: 'POST',
        body: JSON.stringify({ plan }),
      });
      if (res?.url) {
        window.location.href = res.url;
      } else {
        setError('Unexpected response from billing service. Please try again.');
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to start checkout. Please try again.');
    } finally {
      setLoading(null);
    }
  };

  return (
    <div
      style={{
        minHeight: '100vh',
        background:
          'radial-gradient(ellipse at 50% 0%, rgba(232,120,74,0.06) 0%, transparent 55%), #0C0C11',
        color: 'var(--text-primary)',
        fontFamily: 'var(--font-sans)',
        padding: '0 16px 80px',
      }}
    >
      {/* ── Header ── */}
      <div
        style={{
          textAlign: 'center',
          padding: '72px 16px 40px',
          maxWidth: 640,
          margin: '0 auto',
        }}
      >
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 10,
            marginBottom: 20,
          }}
        >
          <div
            style={{
              width: 40,
              height: 40,
              borderRadius: 12,
              background: 'linear-gradient(135deg, #E8784A, #F5A462)',
              boxShadow: '0 0 20px rgba(232,120,74,0.35)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 20,
            }}
          >
            🛡️
          </div>
          <span
            style={{
              fontSize: 14,
              fontWeight: 700,
              color: 'var(--text-primary)',
              letterSpacing: 0.3,
            }}
          >
            IdentityMonitor
          </span>
        </div>

        <h1
          style={{
            fontSize: 38,
            fontWeight: 800,
            letterSpacing: -0.5,
            marginBottom: 12,
            lineHeight: 1.15,
          }}
        >
          Simple, transparent pricing
        </h1>
        <p style={{ fontSize: 16, color: 'var(--text-secondary)', marginBottom: 0 }}>
          Start free. Pay when you're ready.
        </p>
      </div>

      {/* ── Trial Banner ── */}
      <div
        style={{
          maxWidth: 640,
          margin: '0 auto 48px',
          background: 'rgba(232,120,74,0.08)',
          border: '1px solid rgba(232,120,74,0.25)',
          borderRadius: 12,
          padding: '14px 20px',
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          textAlign: 'center',
          justifyContent: 'center',
          fontSize: 14,
          color: 'var(--text-primary)',
        }}
      >
        <span style={{ fontSize: 18 }}>🎁</span>
        <span>
          Every new tenant starts with a{' '}
          <strong style={{ color: '#E8784A' }}>90-day free trial</strong> — no credit card
          required
        </span>
      </div>

      {/* ── Pricing Cards ── */}
      <div
        style={{
          display: 'flex',
          gap: 24,
          justifyContent: 'center',
          flexWrap: 'wrap',
          maxWidth: 860,
          margin: '0 auto 64px',
        }}
      >
        {PLANS.map((card) => (
          <div
            key={card.plan}
            style={{
              flex: '1 1 340px',
              maxWidth: 400,
              background: card.highlight
                ? 'rgba(232,120,74,0.06)'
                : 'rgba(255,255,255,0.035)',
              border: card.highlight
                ? '1px solid rgba(232,120,74,0.30)'
                : '1px solid rgba(255,255,255,0.09)',
              borderRadius: 20,
              padding: '32px 28px',
              display: 'flex',
              flexDirection: 'column',
              gap: 0,
              boxShadow: card.highlight
                ? '0 0 40px rgba(232,120,74,0.10)'
                : 'none',
              position: 'relative',
            }}
          >
            {/* Badge */}
            <div style={{ marginBottom: 20 }}>
              <span
                style={{
                  display: 'inline-block',
                  padding: '3px 12px',
                  borderRadius: 99,
                  fontSize: 11,
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  letterSpacing: 0.6,
                  background: `${card.badgeColor}1F`,
                  color: card.badgeColor,
                  border: `1px solid ${card.badgeColor}40`,
                }}
              >
                {card.badge}
              </span>
            </div>

            {/* Plan name */}
            <h2 style={{ fontSize: 22, fontWeight: 700, marginBottom: 6 }}>
              {card.name}
            </h2>

            {/* Price */}
            <div style={{ marginBottom: 28, display: 'flex', alignItems: 'baseline', gap: 4 }}>
              <span
                style={{
                  fontSize: 42,
                  fontWeight: 800,
                  letterSpacing: -1,
                  color: card.highlight ? '#E8784A' : 'var(--text-primary)',
                }}
              >
                ${card.price}
              </span>
              <span style={{ fontSize: 14, color: 'var(--text-secondary)' }}>/month</span>
            </div>

            {/* Features */}
            <ul
              style={{
                listStyle: 'none',
                padding: 0,
                margin: '0 0 32px',
                display: 'flex',
                flexDirection: 'column',
                gap: 10,
              }}
            >
              {card.features.map((f) => (
                <li
                  key={f.text}
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: 10,
                    fontSize: 13,
                    color: f.included ? 'var(--text-primary)' : 'var(--text-muted)',
                  }}
                >
                  <span
                    style={{
                      flexShrink: 0,
                      width: 18,
                      height: 18,
                      borderRadius: '50%',
                      background: f.included
                        ? 'rgba(0,201,139,0.12)'
                        : 'rgba(255,255,255,0.04)',
                      border: f.included
                        ? '1px solid rgba(0,201,139,0.30)'
                        : '1px solid rgba(255,255,255,0.08)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: 10,
                      marginTop: 1,
                    }}
                  >
                    {f.included ? '✓' : '–'}
                  </span>
                  {f.text}
                </li>
              ))}
            </ul>

            {/* CTA */}
            <button
              onClick={() => handleCheckout(card.plan)}
              disabled={loading !== null}
              style={{
                marginTop: 'auto',
                padding: '13px 0',
                borderRadius: 10,
                border: 'none',
                cursor: loading !== null ? 'not-allowed' : 'pointer',
                fontFamily: 'var(--font-sans)',
                fontSize: 14,
                fontWeight: 700,
                letterSpacing: 0.2,
                transition: 'all 180ms ease',
                opacity: loading !== null && loading !== card.plan ? 0.5 : 1,
                background: card.highlight
                  ? 'linear-gradient(135deg, #E8784A, #F5A462)'
                  : 'rgba(255,255,255,0.07)',
                color: card.highlight ? '#fff' : 'var(--text-primary)',
                boxShadow: card.highlight ? '0 4px 18px rgba(232,120,74,0.30)' : 'none',
              }}
            >
              {loading === card.plan ? (
                <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
                  <span
                    style={{
                      display: 'inline-block',
                      width: 14,
                      height: 14,
                      border: '2px solid currentColor',
                      borderTopColor: 'transparent',
                      borderRadius: '50%',
                      animation: 'spin 0.8s linear infinite',
                    }}
                  />
                  Starting trial...
                </span>
              ) : (
                'Start Free Trial'
              )}
            </button>
          </div>
        ))}
      </div>

      {/* ── Error ── */}
      {error && (
        <div
          style={{
            maxWidth: 640,
            margin: '-40px auto 40px',
            background: 'rgba(255,68,85,0.08)',
            border: '1px solid rgba(255,68,85,0.25)',
            borderRadius: 10,
            padding: '12px 16px',
            color: 'var(--red-critical)',
            fontSize: 13,
            textAlign: 'center',
          }}
        >
          {error}
        </div>
      )}

      {/* ── FAQ ── */}
      <div style={{ maxWidth: 640, margin: '0 auto' }}>
        <h3
          style={{
            fontSize: 18,
            fontWeight: 700,
            textAlign: 'center',
            marginBottom: 24,
            color: 'var(--text-primary)',
          }}
        >
          Frequently asked questions
        </h3>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {FAQ_ITEMS.map((item) => (
            <div
              key={item.q}
              style={{
                background: 'rgba(255,255,255,0.03)',
                border: '1px solid rgba(255,255,255,0.08)',
                borderRadius: 12,
                padding: '16px 20px',
              }}
            >
              <div
                style={{
                  fontWeight: 600,
                  fontSize: 14,
                  marginBottom: 6,
                  color: 'var(--text-primary)',
                }}
              >
                {item.q}
              </div>
              <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                {item.a}
              </div>
            </div>
          ))}
        </div>

        <div
          style={{
            textAlign: 'center',
            marginTop: 48,
            fontSize: 12,
            color: 'var(--text-muted)',
          }}
        >
          Already have an account?{' '}
          <a
            href="/"
            style={{ color: '#E8784A', textDecoration: 'none', fontWeight: 600 }}
          >
            Sign in
          </a>
        </div>
      </div>
    </div>
  );
}
