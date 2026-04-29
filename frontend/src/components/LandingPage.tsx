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
    icon: '🔥',
    title: 'One-tap remediation',
    desc: 'Revoke sessions, disable users, and contain threats instantly — from your phone, in one tap. No Azure Portal needed.',
    highlight: true,
  },
  {
    icon: '📱',
    title: 'Telegram action alerts',
    desc: 'Rich notifications with Revoke / Disable / Dismiss / Investigate buttons — straight to your phone the moment a threat fires.',
  },
  {
    icon: '🤖',
    title: 'Automatic response',
    desc: 'Configure critical alerts to auto-revoke sessions and disable users before you even pick up your phone.',
    highlight: true,
  },
  {
    icon: '🌍',
    title: 'Global threat signals',
    desc: 'Impossible travel, new countries, unknown devices, MFA failures, high-risk logins — all covered.',
  },
  {
    icon: '🛡️',
    title: 'Defender vulnerability scan',
    desc: 'Pulls CVEs directly from Microsoft Defender TVM — scored by CVSS, EPSS exploit probability, and affected device count. Know what to fix first.',
    highlight: true,
  },
  {
    icon: '🔧',
    title: 'One-click endpoint remediation',
    desc: 'Windows Update, app patches, PowerShell scripts, Intune policies — applied per CVE, per device, without touching the Azure Portal.',
    highlight: true,
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
          <img src="/logo.svg" alt="IdentityMonitor logo" style={{ width: 34, height: 34, filter: 'drop-shadow(0 0 8px rgba(232,120,74,0.40))' }} />
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
          <Badge>🔴 Detect · Contain · Remediate — Microsoft 365</Badge>
        </div>

        <h1 style={{
          fontSize: 'clamp(32px, 6vw, 58px)', fontWeight: 900,
          letterSpacing: -1.5, lineHeight: 1.1,
          maxWidth: 820, margin: '0 auto 24px',
        }}>
          Detect threats in your{' '}
          <span style={{ color: ORANGE }}>Microsoft 365.</span>
          <br />Contain them before they cause damage.
        </h1>

        <p style={{
          fontSize: 18, color: 'rgba(255,255,255,0.55)', maxWidth: 600,
          margin: '0 auto 40px', lineHeight: 1.7,
        }}>
          Continuous identity & endpoint monitoring every 60 seconds —
          then <strong style={{ color: 'rgba(255,255,255,0.85)' }}>revoke sessions, patch CVEs, run remediation scripts, and disable accounts</strong> in one tap. No Azure Portal needed.
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

      {/* ── DETECT + ACT STRIP ── */}
      <section style={{ padding: '0 24px 80px' }}>
        <div style={{ maxWidth: 940, margin: '0 auto' }}>

          {/* Detect row */}
          <div style={{ textAlign: 'center', marginBottom: 14, fontSize: 11, fontWeight: 700, letterSpacing: 1, color: 'rgba(255,255,255,0.28)', textTransform: 'uppercase' }}>
            🔍 What we detect
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, justifyContent: 'center', marginBottom: 28 }}>
            {DETECTIONS.map(d => (
              <span key={d} style={{
                padding: '6px 15px', borderRadius: 99, fontSize: 12, fontWeight: 500,
                background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.09)',
                color: 'rgba(255,255,255,0.65)',
              }}>
                {d}
              </span>
            ))}
          </div>

          {/* Divider */}
          <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', marginBottom: 28 }} />

          {/* Act row */}
          <div style={{ textAlign: 'center', marginBottom: 14, fontSize: 11, fontWeight: 700, letterSpacing: 1, color: ORANGE, textTransform: 'uppercase' }}>
            ⚡ What we do about it
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, justifyContent: 'center' }}>
            {[
              'Revoke active sessions',
              'Disable compromised user',
              'Patch CVE via Windows Update',
              'Run remediation script',
              'Push Intune policy',
              'App update (Chrome, Edge, Office…)',
              'Telegram one-tap action',
              'Auto-remediate on trigger',
            ].map(a => (
              <span key={a} style={{
                padding: '6px 15px', borderRadius: 99, fontSize: 12, fontWeight: 600,
                background: 'rgba(232,120,74,0.08)', border: '1px solid rgba(232,120,74,0.22)',
                color: '#F5A462',
              }}>
                {a}
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
            {FEATURES.map((f: any) => (
              <div key={f.title} style={{
                background: f.highlight ? 'rgba(232,120,74,0.07)' : 'rgba(255,255,255,0.03)',
                border: f.highlight ? '1px solid rgba(232,120,74,0.25)' : '1px solid rgba(255,255,255,0.08)',
                borderRadius: 16, padding: '24px 22px',
              }}>
                <div style={{ fontSize: 28, marginBottom: 12 }}>{f.icon}</div>
                <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 8, color: f.highlight ? ORANGE : undefined }}>{f.title}</div>
                <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.5)', lineHeight: 1.65 }}>{f.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── REMEDIATION SHOWCASE ── */}
      <section style={{ padding: '0 24px 100px' }}>
        <div style={{ maxWidth: 960, margin: '0 auto' }}>
          <div style={{ textAlign: 'center', marginBottom: 56 }}>
            <Badge>🔥 Detect → Alert → Contain</Badge>
            <h2 style={{ fontSize: 28, fontWeight: 800, marginTop: 20, marginBottom: 12, letterSpacing: -0.5 }}>
              From threat detected to session revoked — in seconds
            </h2>
            <p style={{ fontSize: 15, color: 'rgba(255,255,255,0.45)', maxWidth: 560, margin: '0 auto' }}>
              Most tools just tell you something happened. IdentityMonitor lets you stop it.
            </p>
          </div>

          <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap', alignItems: 'stretch' }}>

            {/* Left: Timeline */}
            <div style={{ flex: '1 1 300px', display: 'flex', flexDirection: 'column', gap: 0 }}>
              {[
                { icon: '🔍', color: '#888',    label: 'Detected',  text: 'Impossible travel — Tel Aviv → New York in 90 min' },
                { icon: '📱', color: ORANGE,    label: 'Alerted',   text: 'Telegram message with full context fired in <60s' },
                { icon: '👆', color: '#9B8AFB', label: 'Responded', text: 'You tap Revoke — or it happens automatically' },
                { icon: '✅', color: '#00C98B', label: 'Contained', text: 'Session revoked. Attacker locked out. Audit logged.' },
              ].map((step, i, arr) => (
                <div key={step.label} style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
                  {/* connector */}
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0 }}>
                    <div style={{
                      width: 40, height: 40, borderRadius: '50%', flexShrink: 0,
                      background: `${step.color}22`, border: `2px solid ${step.color}55`,
                      display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 18,
                    }}>
                      {step.icon}
                    </div>
                    {i < arr.length - 1 && (
                      <div style={{ width: 2, height: 36, background: 'rgba(255,255,255,0.08)', margin: '4px 0' }} />
                    )}
                  </div>
                  <div style={{ paddingTop: 8, paddingBottom: i < arr.length - 1 ? 0 : 0 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.8, color: step.color, marginBottom: 2 }}>{step.label}</div>
                    <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.65)', lineHeight: 1.5, marginBottom: 20 }}>{step.text}</div>
                  </div>
                </div>
              ))}
            </div>

            {/* Right: Telegram mockup */}
            <div style={{ flex: '1 1 320px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <div style={{
                background: '#17212B', borderRadius: 16, padding: '20px 18px',
                width: '100%', maxWidth: 380,
                boxShadow: '0 24px 60px rgba(0,0,0,0.5)',
                border: '1px solid rgba(255,255,255,0.07)',
              }}>
                {/* Telegram header */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16, paddingBottom: 12, borderBottom: '1px solid rgba(255,255,255,0.07)' }}>
                  <img src="/logo.svg" alt="" style={{ width: 36, height: 36, borderRadius: '50%', objectFit: 'cover' }} />
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 700, color: '#fff' }}>IdentityMonitor</div>
                    <div style={{ fontSize: 11, color: '#5B7FA6' }}>bot</div>
                  </div>
                </div>

                {/* Alert message */}
                <div style={{ background: '#1E2D3D', borderRadius: 10, padding: '12px 14px', marginBottom: 10 }}>
                  <div style={{ fontSize: 13, fontWeight: 700, color: '#FF4455', marginBottom: 6 }}>🚨 CRITICAL ALERT</div>
                  <div style={{ fontSize: 12, color: '#aaa', lineHeight: 1.6 }}>
                    <div><span style={{ color: '#fff', fontWeight: 600 }}>User:</span> john.doe@contoso.com</div>
                    <div><span style={{ color: '#fff', fontWeight: 600 }}>Threat:</span> Impossible Travel</div>
                    <div><span style={{ color: '#fff', fontWeight: 600 }}>Route:</span> 🇮🇱 Tel Aviv → 🇺🇸 New York</div>
                    <div><span style={{ color: '#fff', fontWeight: 600 }}>Time gap:</span> 90 min (impossible)</div>
                    <div><span style={{ color: '#fff', fontWeight: 600 }}>App:</span> Microsoft Azure Portal</div>
                  </div>
                </div>

                {/* Action buttons — styled to match real app buttons */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
                  {/* btn-danger */}
                  <div style={{
                    padding: '8px 6px', borderRadius: 8, textAlign: 'center', cursor: 'default',
                    background: 'rgba(239,68,68,0.10)', border: '1px solid rgba(239,68,68,0.25)',
                    fontSize: 11, fontWeight: 600, color: '#ef4444',
                  }}>⊘ Revoke Sessions</div>
                  {/* btn-warning (orange variant) */}
                  <div style={{
                    padding: '8px 6px', borderRadius: 8, textAlign: 'center', cursor: 'default',
                    background: 'rgba(232,120,74,0.10)', border: '1px solid rgba(232,120,74,0.25)',
                    fontSize: 11, fontWeight: 600, color: '#E8784A',
                  }}>⊘ Disable User</div>
                  {/* btn-ghost */}
                  <div style={{
                    padding: '8px 6px', borderRadius: 8, textAlign: 'center', cursor: 'default',
                    background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.14)',
                    fontSize: 11, fontWeight: 600, color: 'rgba(255,255,255,0.60)',
                  }}>🔍 Investigate</div>
                  {/* btn-ghost */}
                  <div style={{
                    padding: '8px 6px', borderRadius: 8, textAlign: 'center', cursor: 'default',
                    background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.14)',
                    fontSize: 11, fontWeight: 600, color: 'rgba(255,255,255,0.60)',
                  }}>✓ Dismiss</div>
                </div>

                <div style={{ marginTop: 10, fontSize: 10, color: '#5B7FA6', textAlign: 'center' }}>
                  Auto-revoke in 30 min if no action taken
                </div>
              </div>
            </div>

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

      {/* ── DEFENDER VULNERABILITY SECTION ── */}
      <section style={{ padding: '0 24px 100px' }}>
        <div style={{ maxWidth: 980, margin: '0 auto' }}>

          {/* Header */}
          <div style={{ textAlign: 'center', marginBottom: 56 }}>
            <Badge>🛡️ Microsoft Defender Integration</Badge>
            <h2 style={{ fontSize: 'clamp(24px, 4vw, 36px)', fontWeight: 800, margin: '20px 0 14px', letterSpacing: -0.5 }}>
              Endpoint vulnerability management — built in
            </h2>
            <p style={{ fontSize: 15, color: 'rgba(255,255,255,0.45)', maxWidth: 560, margin: '0 auto', lineHeight: 1.7 }}>
              Connect Microsoft Defender and see every open CVE across your fleet — prioritised by severity, exploit probability, and number of affected devices. Fix in one click.
            </p>
          </div>

          {/* Two-col layout: CVE list mock + remediation panel */}
          <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap', alignItems: 'flex-start' }}>

            {/* Left: CVE list mock */}
            <div style={{
              flex: '1 1 340px',
              background: '#0f0f17', borderRadius: 18,
              border: '1px solid rgba(255,255,255,0.07)',
              overflow: 'hidden',
            }}>
              {/* Header bar */}
              <div style={{ padding: '14px 20px', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ fontSize: 12, fontWeight: 700, color: 'rgba(255,255,255,0.4)', letterSpacing: 0.8 }}>DEFENDER · VULNERABILITIES</div>
                <div style={{ fontSize: 11, padding: '3px 10px', borderRadius: 99, background: 'rgba(232,120,74,0.12)', color: '#E8784A', fontWeight: 700 }}>24 open</div>
              </div>
              {/* CVE rows */}
              {[
                { cve: 'CVE-2024-43461', product: 'Windows MSHTML Platform', severity: 'Critical', cvss: '9.8', devices: 12, exploit: true,  type: 'windows-update' },
                { cve: 'CVE-2024-38189', product: 'Microsoft Office Project',  severity: 'High',     cvss: '8.8', devices: 7,  exploit: true,  type: 'application'    },
                { cve: 'CVE-2024-38213', product: 'Windows SmartScreen',       severity: 'High',     cvss: '6.5', devices: 15, exploit: false, type: 'windows-update' },
                { cve: 'CVE-2024-21447', product: 'Google Chrome',             severity: 'Medium',   cvss: '5.9', devices: 9,  exploit: false, type: 'application'    },
              ].map((row, i) => {
                const severityColor = row.severity === 'Critical' ? '#FF3D6B' : row.severity === 'High' ? '#FF7A3D' : '#F5C543';
                const typeColor     = row.type === 'windows-update' ? '#5B9BD5' : '#A78BFA';
                const typeLabel     = row.type === 'windows-update' ? '⊞ Windows Update' : '📦 App patch';
                return (
                  <div key={row.cve} style={{
                    padding: '13px 20px',
                    borderBottom: i < 3 ? '1px solid rgba(255,255,255,0.05)' : 'none',
                    display: 'flex', alignItems: 'center', gap: 12,
                    background: i === 0 ? 'rgba(255,61,107,0.04)' : 'transparent',
                    cursor: 'pointer',
                  }}>
                    {/* Severity dot */}
                    <div style={{ width: 9, height: 9, borderRadius: '50%', background: severityColor, flexShrink: 0, boxShadow: `0 0 6px ${severityColor}88` }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 3 }}>
                        <span style={{ fontSize: 12, fontWeight: 700, color: '#fff', fontFamily: 'monospace' }}>{row.cve}</span>
                        {row.exploit && <span style={{ fontSize: 10, padding: '1px 7px', borderRadius: 4, background: 'rgba(255,61,107,0.15)', color: '#FF3D6B', fontWeight: 700 }}>EXPLOIT</span>}
                      </div>
                      <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.45)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row.product}</div>
                    </div>
                    <div style={{ textAlign: 'right', flexShrink: 0 }}>
                      <div style={{ fontSize: 11, fontWeight: 700, color: severityColor }}>{row.severity}</div>
                      <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.30)' }}>CVSS {row.cvss} · {row.devices} devices</div>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Right: Remediation panel mock */}
            <div style={{ flex: '1 1 300px', display: 'flex', flexDirection: 'column', gap: 16 }}>

              {/* Active CVE detail */}
              <div style={{ background: '#0f0f17', borderRadius: 18, border: '1px solid rgba(255,61,107,0.18)', padding: '20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 14 }}>
                  <div>
                    <div style={{ fontSize: 11, fontFamily: 'monospace', color: '#FF3D6B', fontWeight: 700, marginBottom: 4 }}>CVE-2024-43461</div>
                    <div style={{ fontSize: 14, fontWeight: 700, color: '#fff', lineHeight: 1.3 }}>Windows MSHTML Platform</div>
                  </div>
                  <div style={{ padding: '4px 12px', borderRadius: 99, background: 'rgba(255,61,107,0.12)', color: '#FF3D6B', fontSize: 11, fontWeight: 800 }}>CRITICAL 9.8</div>
                </div>
                <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.45)', lineHeight: 1.6, marginBottom: 16 }}>
                  Remote code execution via crafted HTML file. Active exploit in the wild. <span style={{ color: '#FF3D6B' }}>12 devices exposed.</span>
                </div>

                {/* Remediation type badge */}
                <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
                  <span style={{ fontSize: 11, padding: '4px 12px', borderRadius: 6, background: 'rgba(91,155,213,0.12)', color: '#5B9BD5', fontWeight: 700, border: '1px solid rgba(91,155,213,0.20)' }}>⊞ Windows Update</span>
                  <span style={{ fontSize: 11, padding: '4px 12px', borderRadius: 6, background: 'rgba(255,61,107,0.10)', color: '#FF3D6B', fontWeight: 700, border: '1px solid rgba(255,61,107,0.18)' }}>🔴 Exploit in wild</span>
                </div>

                {/* Action buttons — match real app btn styles */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
                  {/* btn-primary */}
                  <div style={{
                    padding: '9px 16px', borderRadius: 8, cursor: 'default', fontWeight: 600, fontSize: 12,
                    background: 'linear-gradient(135deg, #E8784A, #F5A462)', color: '#fff',
                    boxShadow: '0 4px 16px rgba(232,120,74,0.35)',
                  }}>
                    ⊞ Trigger Windows Update on all 12 devices
                  </div>
                  {/* btn-ghost */}
                  <div style={{
                    padding: '9px 16px', borderRadius: 8, cursor: 'default', fontWeight: 600, fontSize: 12,
                    background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.14)',
                    color: 'rgba(255,255,255,0.60)',
                  }}>
                    🔄 Reset Windows Update components (script)
                  </div>
                  {/* btn-ghost */}
                  <div style={{
                    padding: '9px 16px', borderRadius: 8, cursor: 'default', fontWeight: 600, fontSize: 12,
                    background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.14)',
                    color: 'rgba(255,255,255,0.60)',
                  }}>
                    🔍 View all 12 affected devices
                  </div>
                </div>
              </div>

              {/* Stats row */}
              <div style={{ display: 'flex', gap: 12 }}>
                {[
                  { label: 'Critical CVEs', value: '3',  color: '#FF3D6B' },
                  { label: 'Devices at risk', value: '15', color: ORANGE },
                  { label: 'With exploit', value: '2',  color: '#F5C543' },
                ].map(s => (
                  <div key={s.label} style={{
                    flex: 1, background: '#0f0f17', borderRadius: 12,
                    border: '1px solid rgba(255,255,255,0.07)', padding: '14px 12px', textAlign: 'center',
                  }}>
                    <div style={{ fontSize: 22, fontWeight: 900, color: s.color, marginBottom: 4 }}>{s.value}</div>
                    <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.35)', fontWeight: 600 }}>{s.label}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Remediation type pills */}
          <div style={{ marginTop: 40, textAlign: 'center' }}>
            <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.30)', marginBottom: 16, letterSpacing: 0.8, fontWeight: 700, textTransform: 'uppercase' }}>Remediation types supported</div>
            <div style={{ display: 'flex', gap: 10, justifyContent: 'center', flexWrap: 'wrap' }}>
              {[
                { label: '⊞ Windows Update', color: '#5B9BD5' },
                { label: '📦 Application patch', color: '#A78BFA' },
                { label: '⚡ PowerShell script', color: ORANGE },
                { label: '📋 Intune policy', color: '#00C98B' },
                { label: '🔍 Affected device drill-down', color: 'rgba(255,255,255,0.45)' },
                { label: '🧬 CVSS + EPSS scoring', color: 'rgba(255,255,255,0.45)' },
              ].map(p => (
                <span key={p.label} style={{
                  padding: '7px 16px', borderRadius: 99, fontSize: 12, fontWeight: 600,
                  background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.09)',
                  color: p.color,
                }}>
                  {p.label}
                </span>
              ))}
            </div>
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
              {['Everything in Free', 'Telegram alerts + action buttons', 'Email notifications', 'Auto session revoke', 'Conditional Access + PIM', 'Defender vulnerability management'].map(f => (
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
          <img src="/logo.svg" alt="" style={{ width: 24, height: 24 }} />
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
