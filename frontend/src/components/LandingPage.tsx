import React, { useState } from 'react';

const ORANGE = '#E8784A';
const BG = '#0C0C11';

// ── Tiny shared helpers ──────────────────────────────────────────────────────

function Badge({ children }: { children: React.ReactNode }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 6,
      padding: '5px 14px', borderRadius: 99,
      background: 'rgba(232,120,74,0.10)', border: '1px solid rgba(232,120,74,0.28)',
      color: ORANGE, fontSize: 12, fontWeight: 700, letterSpacing: 0.4,
    }}>
      {children}
    </span>
  );
}

function Btn({ href, children, primary }: { href: string; children: React.ReactNode; primary?: boolean }) {
  return (
    <a href={href} style={{
      display: 'inline-flex', alignItems: 'center', gap: 8,
      padding: '13px 28px', borderRadius: 11, textDecoration: 'none',
      fontWeight: 700, fontSize: 14, letterSpacing: 0.2, cursor: 'pointer',
      background: primary ? `linear-gradient(135deg, ${ORANGE}, #F5A462)` : 'rgba(255,255,255,0.07)',
      color: primary ? '#fff' : 'rgba(255,255,255,0.85)',
      border: primary ? 'none' : '1px solid rgba(255,255,255,0.12)',
      boxShadow: primary ? '0 4px 24px rgba(232,120,74,0.28)' : 'none',
      transition: 'opacity 150ms',
    }}>
      {children}
    </a>
  );
}

// ── Data ─────────────────────────────────────────────────────────────────────

const FEATURES = [
  {
    icon: '⚡',
    title: '60-second detection',
    desc: 'Continuous scanning every minute. Threats are caught in near real-time, not after the damage is done.',
  },
  {
    icon: '📱',
    title: 'Telegram action alerts',
    desc: 'Rich notifications with one-tap Revoke / Disable / Investigate buttons — straight to your phone.',
  },
  {
    icon: '🔒',
    title: 'Automated remediation',
    desc: 'Sessions revoked and users disabled automatically on critical threats, with full audit trail.',
  },
  {
    icon: '🌍',
    title: 'Global threat signals',
    desc: 'Impossible travel, new countries, unknown devices, MFA failures, high-risk logins — all covered.',
  },
  {
    icon: '🛡️',
    title: 'Conditional Access',
    desc: 'Monitor and manage CA policies from one place without logging into Azure Portal.',
  },
  {
    icon: '📊',
    title: 'Full audit trail',
    desc: '365-day retention. Every alert, every action, every remediation — logged and searchable.',
  },
];

const DETECTIONS = [
  'Impossible Travel',
  'New country sign-in',
  'Unknown device',
  'MFA failure spike',
  'High-risk user detected',
  'Off-hours privileged access',
  'New IP address',
  'Leaked credentials',
];

const STEPS = [
  { n: '1', title: 'Connect your tenant', desc: 'Sign in with your Microsoft 365 Global Admin account. Grant read permissions via standard Microsoft OAuth. Takes 2 minutes.' },
  { n: '2', title: 'We start monitoring', desc: 'The scanner runs every 60 seconds across all your privileged users. No agents, no installs, no firewall changes.' },
  { n: '3', title: 'Get alerted & respond', desc: 'Critical threats trigger instant Telegram notifications with action buttons. Respond in one tap from anywhere.' },
];

// ── Main component ────────────────────────────────────────────────────────────

export default function LandingPage() {
  const [menuOpen, setMenuOpen] = useState(false);

  return (
    <div style={{ background: BG, color: '#e8e8f0', fontFamily: 'system-ui, -apple-system, sans-serif', minHeight: '100vh' }}>

      {/* ── NAV ── */}
      <nav style={{
        position: 'sticky', top: 0, zIndex: 100,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '0 24px', height: 60,
        background: 'rgba(12,12,17,0.88)', backdropFilter: 'blur(12px)',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
      }}>
        <a href="/" style={{ display: 'flex', alignItems: 'center', gap: 10, textDecoration: 'none' }}>
          <div style={{
            width: 32, height: 32, borderRadius: 9,
            background: `linear-gradient(135deg, ${ORANGE}, #F5A462)`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 16, boxShadow: '0 0 16px rgba(232,120,74,0.30)',
          }}>🛡️</div>
          <span style={{ fontWeight: 800, fontSize: 15, color: '#fff', letterSpacing: -0.2 }}>
            IdentityMonitor
          </span>
        </a>

        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <a href="/pricing" style={{ fontSize: 13, color: 'rgba(255,255,255,0.65)', textDecoration: 'none', fontWeight: 500 }}>
            Pricing
          </a>
          <a
            href="/api/auth/login"
            style={{
              fontSize: 13, fontWeight: 700, padding: '7px 18px', borderRadius: 8,
              background: `linear-gradient(135deg, ${ORANGE}, #F5A462)`,
              color: '#fff', textDecoration: 'none',
              boxShadow: '0 2px 12px rgba(232,120,74,0.25)',
            }}
          >
            Sign in →
          </a>
        </div>
      </nav>

      {/* ── HERO ── */}
      <section style={{
        textAlign: 'center', padding: '100px 24px 80px',
        background: 'radial-gradient(ellipse at 50% 0%, rgba(232,120,74,0.08) 0%, transparent 60%)',
      }}>
        <div style={{ marginBottom: 24 }}>
          <Badge>🔴 Live • Microsoft 365 Identity Security</Badge>
        </div>

        <h1 style={{
          fontSize: 'clamp(32px, 6vw, 58px)', fontWeight: 900,
          letterSpacing: -1.5, lineHeight: 1.1, marginBottom: 24,
          maxWidth: 820, margin: '0 auto 24px',
        }}>
          Know when someone breaks into your{' '}
          <span style={{ color: ORANGE }}>Microsoft 365.</span>
          <br />Before they do damage.
        </h1>

        <p style={{
          fontSize: 18, color: 'rgba(255,255,255,0.55)', maxWidth: 560,
          margin: '0 auto 40px', lineHeight: 1.7,
        }}>
          Real-time anomaly detection for privileged identities. Instant Telegram alerts.
          One-tap remediation. Runs every 60 seconds.
        </p>

        <div style={{ display: 'flex', gap: 14, justifyContent: 'center', flexWrap: 'wrap' }}>
          <Btn href="/api/auth/login" primary>Start for free →</Btn>
          <Btn href="/pricing">See pricing</Btn>
        </div>

        <div style={{ marginTop: 24, fontSize: 12, color: 'rgba(255,255,255,0.3)', display: 'flex', gap: 20, justifyContent: 'center' }}>
          <span>✓ No credit card</span>
          <span>✓ Free tier forever</span>
          <span>✓ Microsoft 365 only</span>
        </div>
      </section>

      {/* ── DETECTION STRIP ── */}
      <section style={{ padding: '0 24px 80px' }}>
        <div style={{ maxWidth: 900, margin: '0 auto' }}>
          <div style={{ textAlign: 'center', marginBottom: 24, fontSize: 12, fontWeight: 700, letterSpacing: 1, color: 'rgba(255,255,255,0.3)', textTransform: 'uppercase' }}>
            What we detect
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, justifyContent: 'center' }}>
            {DETECTIONS.map(d => (
              <span key={d} style={{
                padding: '7px 16px', borderRadius: 99, fontSize: 13, fontWeight: 500,
                background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.09)',
                color: 'rgba(255,255,255,0.70)',
              }}>
                {d}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* ── FEATURES ── */}
      <section style={{ padding: '0 24px 100px' }}>
        <div style={{ maxWidth: 1000, margin: '0 auto' }}>
          <h2 style={{ textAlign: 'center', fontSize: 28, fontWeight: 800, marginBottom: 48, letterSpacing: -0.5 }}>
            Everything you need to stay ahead of identity threats
          </h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 20 }}>
            {FEATURES.map(f => (
              <div key={f.title} style={{
                background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)',
                borderRadius: 16, padding: '24px 22px',
              }}>
                <div style={{ fontSize: 28, marginBottom: 12 }}>{f.icon}</div>
                <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 8 }}>{f.title}</div>
                <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.5)', lineHeight: 1.65 }}>{f.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── HOW IT WORKS ── */}
      <section style={{ padding: '0 24px 100px', background: 'rgba(255,255,255,0.015)' }}>
        <div style={{ maxWidth: 800, margin: '0 auto', paddingTop: 80 }}>
          <h2 style={{ textAlign: 'center', fontSize: 28, fontWeight: 800, marginBottom: 56, letterSpacing: -0.5 }}>
            Up and running in 5 minutes
          </h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 32 }}>
            {STEPS.map(s => (
              <div key={s.n} style={{ display: 'flex', gap: 24, alignItems: 'flex-start' }}>
                <div style={{
                  flexShrink: 0, width: 44, height: 44, borderRadius: '50%',
                  background: `linear-gradient(135deg, ${ORANGE}, #F5A462)`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontWeight: 900, fontSize: 18, color: '#fff',
                  boxShadow: '0 4px 16px rgba(232,120,74,0.30)',
                }}>
                  {s.n}
                </div>
                <div>
                  <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 6 }}>{s.title}</div>
                  <div style={{ fontSize: 14, color: 'rgba(255,255,255,0.5)', lineHeight: 1.7 }}>{s.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── PRICING PREVIEW ── */}
      <section style={{ padding: '80px 24px 100px' }}>
        <div style={{ maxWidth: 700, margin: '0 auto', textAlign: 'center' }}>
          <h2 style={{ fontSize: 28, fontWeight: 800, marginBottom: 12, letterSpacing: -0.5 }}>
            Simple, honest pricing
          </h2>
          <p style={{ fontSize: 15, color: 'rgba(255,255,255,0.45)', marginBottom: 48 }}>
            Start free. Upgrade when you need real-time alerts.
          </p>

          <div style={{ display: 'flex', gap: 20, flexWrap: 'wrap', justifyContent: 'center' }}>
            {/* Free */}
            <div style={{
              flex: '1 1 260px', maxWidth: 300,
              background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.09)',
              borderRadius: 18, padding: '28px 24px', textAlign: 'left',
            }}>
              <div style={{ fontSize: 13, fontWeight: 700, color: 'rgba(255,255,255,0.4)', marginBottom: 12 }}>FREE</div>
              <div style={{ fontSize: 36, fontWeight: 900, marginBottom: 20 }}>$0<span style={{ fontSize: 14, fontWeight: 400, color: 'rgba(255,255,255,0.4)' }}>/mo</span></div>
              {['Anomaly detection', 'Alert dashboard', 'User risk overview'].map(f => (
                <div key={f} style={{ fontSize: 13, color: 'rgba(255,255,255,0.55)', marginBottom: 8, display: 'flex', gap: 8 }}>
                  <span style={{ color: '#00C98B' }}>✓</span> {f}
                </div>
              ))}
              <a href="/api/auth/login" style={{
                display: 'block', marginTop: 24, padding: '11px 0', borderRadius: 9, textAlign: 'center',
                background: 'rgba(255,255,255,0.07)', border: '1px solid rgba(255,255,255,0.10)',
                color: '#fff', textDecoration: 'none', fontSize: 13, fontWeight: 700,
              }}>Get started free</a>
            </div>

            {/* Pro */}
            <div style={{
              flex: '1 1 260px', maxWidth: 300,
              background: 'rgba(232,120,74,0.07)', border: '1px solid rgba(232,120,74,0.30)',
              borderRadius: 18, padding: '28px 24px', textAlign: 'left',
              boxShadow: '0 0 40px rgba(232,120,74,0.10)',
            }}>
              <div style={{ fontSize: 13, fontWeight: 700, color: ORANGE, marginBottom: 12 }}>PRO</div>
              <div style={{ fontSize: 36, fontWeight: 900, color: ORANGE, marginBottom: 20 }}>$15<span style={{ fontSize: 14, fontWeight: 400, color: 'rgba(255,255,255,0.4)' }}>/mo</span></div>
              {['Everything in Free', 'Telegram alerts + action buttons', 'Email notifications', 'Auto session revoke', 'Conditional Access + PIM'].map(f => (
                <div key={f} style={{ fontSize: 13, color: 'rgba(255,255,255,0.70)', marginBottom: 8, display: 'flex', gap: 8 }}>
                  <span style={{ color: ORANGE }}>✓</span> {f}
                </div>
              ))}
              <a href="/pricing" style={{
                display: 'block', marginTop: 24, padding: '11px 0', borderRadius: 9, textAlign: 'center',
                background: `linear-gradient(135deg, ${ORANGE}, #F5A462)`,
                color: '#fff', textDecoration: 'none', fontSize: 13, fontWeight: 700,
                boxShadow: '0 4px 16px rgba(232,120,74,0.30)',
              }}>Upgrade to Pro</a>
            </div>
          </div>
        </div>
      </section>

      {/* ── CTA BANNER ── */}
      <section style={{
        margin: '0 24px 80px', borderRadius: 20,
        background: `linear-gradient(135deg, rgba(232,120,74,0.12), rgba(232,120,74,0.04))`,
        border: '1px solid rgba(232,120,74,0.22)',
        padding: '52px 32px', textAlign: 'center',
        maxWidth: 860, marginLeft: 'auto', marginRight: 'auto',
      }}>
        <h2 style={{ fontSize: 28, fontWeight: 800, marginBottom: 12, letterSpacing: -0.5 }}>
          Start monitoring your Microsoft 365 today
        </h2>
        <p style={{ fontSize: 15, color: 'rgba(255,255,255,0.45)', marginBottom: 32 }}>
          Free forever. No credit card. Setup in 5 minutes.
        </p>
        <Btn href="/api/auth/login" primary>Connect my Microsoft 365 →</Btn>
      </section>

      {/* ── FOOTER ── */}
      <footer style={{
        borderTop: '1px solid rgba(255,255,255,0.06)',
        padding: '32px 24px', textAlign: 'center',
      }}>
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 8, marginBottom: 16 }}>
          <div style={{
            width: 24, height: 24, borderRadius: 7,
            background: `linear-gradient(135deg, ${ORANGE}, #F5A462)`,
            display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12,
          }}>🛡️</div>
          <span style={{ fontWeight: 800, fontSize: 13 }}>IdentityMonitor</span>
          <span style={{ fontSize: 12, color: 'rgba(255,255,255,0.25)' }}>by ModernEndpoint.tech</span>
        </div>

        <div style={{ display: 'flex', justifyContent: 'center', gap: 24, fontSize: 12, color: 'rgba(255,255,255,0.30)', flexWrap: 'wrap' }}>
          <a href="/pricing" style={{ color: 'inherit', textDecoration: 'none' }}>Pricing</a>
          <a href="/terms"   style={{ color: 'inherit', textDecoration: 'none' }}>Terms of Service</a>
          <a href="/privacy" style={{ color: 'inherit', textDecoration: 'none' }}>Privacy Policy</a>
          <a href="mailto:support@modernendpoint.tech" style={{ color: 'inherit', textDecoration: 'none' }}>support@modernendpoint.tech</a>
        </div>

        <div style={{ marginTop: 16, fontSize: 11, color: 'rgba(255,255,255,0.15)' }}>
          © {new Date().getFullYear()} ModernEndpoint.tech · All rights reserved
        </div>
      </footer>

    </div>
  );
}
