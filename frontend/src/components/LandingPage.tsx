import React, { useState } from 'react';

const ORANGE = '#E8784A';
const BG     = '#0C0C11';
const RED    = '#ef4444';

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

function Btn({ href, children, primary, large }: { href: string; children: React.ReactNode; primary?: boolean; large?: boolean }) {
  return (
    <a href={href} style={{
      display: 'inline-flex', alignItems: 'center', gap: 8,
      padding: large ? '15px 34px' : '13px 28px',
      borderRadius: 11, textDecoration: 'none',
      fontWeight: 700, fontSize: large ? 15 : 14, letterSpacing: 0.2, cursor: 'pointer',
      background: primary ? `linear-gradient(135deg, ${ORANGE}, #F5A462)` : 'rgba(255,255,255,0.07)',
      color: primary ? '#fff' : 'rgba(255,255,255,0.85)',
      border: primary ? 'none' : '1px solid rgba(255,255,255,0.12)',
      boxShadow: primary ? '0 4px 28px rgba(232,120,74,0.35)' : 'none',
    }}>
      {children}
    </a>
  );
}

// ── Data ─────────────────────────────────────────────────────────────────────

const DETECTIONS = [
  'Impossible Travel',
  'New country sign-in',
  'Unknown device',
  'MFA failure spike',
  'High-risk user (Entra ID Risk)',
  'Off-hours privileged access',
  'New IP address',
  'Leaked credentials',
];

const ACTIONS = [
  'Revoke active sessions',
  'Disable compromised user',
  'Patch CVE via Windows Update',
  'Run PowerShell remediation script',
  'Push Intune compliance policy',
  'Update apps (Chrome, Edge, Office…)',
  'Telegram one-tap action buttons',
  'Auto-remediate on trigger',
];

const STEPS = [
  {
    n: '1',
    title: 'Connect in 2 minutes',
    desc: 'Sign in with your Microsoft 365 Global Admin account. Approve standard Microsoft OAuth scopes. No agents, no firewall rules, no IT ticket.',
    detail: 'Read-only Graph API permissions',
  },
  {
    n: '2',
    title: 'Scanning starts immediately',
    desc: 'The engine checks every privileged user every 60 seconds. Baselines are built automatically. Zero configuration required.',
    detail: '60-second scan cycle, all privileged users',
  },
  {
    n: '3',
    title: 'Alert fires — you act in one tap',
    desc: 'Threats trigger a Telegram message with full context and action buttons: Revoke / Disable / Investigate. Or configure auto-response for critical severity.',
    detail: 'Telegram + Email · Auto-response available',
  },
];

const FAQ = [
  {
    q: 'What permissions does it need?',
    a: 'Read-only Microsoft Graph API permissions: AuditLog.Read.All, User.Read.All, IdentityRiskEvent.Read.All, and Directory.Read.All. We never write to your tenant unless you explicitly trigger a remediation action.',
  },
  {
    q: 'Can it actually break anything in my tenant?',
    a: 'No. Monitoring is completely read-only. Remediation actions (session revoke, disable user) only execute when you tap a button in Telegram or the dashboard — and every action is logged in the Audit Center.',
  },
  {
    q: 'Why not use Microsoft Sentinel or Defender for Identity?',
    a: 'Sentinel costs $100–$500+/mo and requires a security analyst to build rules and triage alerts. Defender for Identity is P2 licensed ($9/user/mo across your entire tenant). IdentityMonitor is purpose-built, pre-configured, and includes one-tap remediation — for $15/mo flat.',
  },
  {
    q: 'Where is my data stored?',
    a: 'Alert metadata and audit logs are stored in Azure Table Storage in your region. We do not store your users\' email content, files, or Microsoft 365 data — only sign-in events and alert records.',
  },
  {
    q: 'What if I want to cancel?',
    a: 'Cancel any time in Gumroad — no questions asked. Your free tier access continues with detection and the dashboard. Telegram alerts and auto-remediation pause until you resubscribe.',
  },
];

// ── Main component ────────────────────────────────────────────────────────────

export default function LandingPage() {
  const [openFaq, setOpenFaq] = useState<number | null>(null);

  return (
    <div style={{ background: BG, color: '#e8e8f0', fontFamily: 'system-ui, -apple-system, sans-serif', minHeight: '100vh' }}>

      {/* ── NAV ── */}
      <nav style={{
        position: 'sticky', top: 0, zIndex: 100,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '0 24px', height: 60,
        background: 'rgba(12,12,17,0.92)', backdropFilter: 'blur(14px)',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
      }}>
        <a href="/" style={{ display: 'flex', alignItems: 'center', gap: 10, textDecoration: 'none' }}>
          <img src="/logo.svg" alt="IdentityMonitor logo" style={{ width: 34, height: 34, filter: 'drop-shadow(0 0 8px rgba(232,120,74,0.40))' }} />
          <span style={{ fontWeight: 800, fontSize: 15, color: '#fff', letterSpacing: -0.2 }}>IdentityMonitor</span>
        </a>
        <div style={{ display: 'flex', gap: 20, alignItems: 'center' }}>
          <a href="#how" style={{ fontSize: 13, color: 'rgba(255,255,255,0.55)', textDecoration: 'none', fontWeight: 500 }}>How it works</a>
          <a href="/pricing" style={{ fontSize: 13, color: 'rgba(255,255,255,0.55)', textDecoration: 'none', fontWeight: 500 }}>Pricing</a>
          <a href="/api/auth/login" style={{
            fontSize: 13, fontWeight: 700, padding: '7px 18px', borderRadius: 8,
            background: `linear-gradient(135deg, ${ORANGE}, #F5A462)`,
            color: '#fff', textDecoration: 'none',
            boxShadow: '0 2px 12px rgba(232,120,74,0.28)',
          }}>
            Sign in →
          </a>
        </div>
      </nav>

      {/* ── HERO ── */}
      <section style={{
        textAlign: 'center', padding: '96px 24px 72px',
        background: 'radial-gradient(ellipse at 50% 0%, rgba(232,120,74,0.09) 0%, transparent 65%)',
      }}>
        <div style={{ marginBottom: 20 }}>
          <Badge>🔴 Live · Detect · Contain · Remediate</Badge>
        </div>

        <h1 style={{
          fontSize: 'clamp(34px, 6vw, 62px)', fontWeight: 900,
          letterSpacing: -2, lineHeight: 1.08,
          maxWidth: 860, margin: '0 auto 22px',
        }}>
          Your Microsoft 365 is being{' '}
          <span style={{ color: ORANGE }}>attacked right now.</span>
          <br />
          <span style={{ color: 'rgba(255,255,255,0.92)' }}>Are you the first to know?</span>
        </h1>

        <p style={{
          fontSize: 18, color: 'rgba(255,255,255,0.50)', maxWidth: 580,
          margin: '0 auto 36px', lineHeight: 1.75,
        }}>
          IdentityMonitor scans every privileged account every <strong style={{ color: 'rgba(255,255,255,0.82)' }}>60 seconds</strong> — and when a threat fires, you
          {' '}<strong style={{ color: 'rgba(255,255,255,0.82)' }}>revoke sessions, patch CVEs, and disable accounts</strong> in one tap. No Azure Portal, no analyst, no delay.
        </p>

        <div style={{ display: 'flex', gap: 14, justifyContent: 'center', flexWrap: 'wrap', marginBottom: 24 }}>
          <Btn href="/api/auth/login" primary large>Start monitoring free →</Btn>
          <Btn href="/pricing">See pricing</Btn>
        </div>

        <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.28)', display: 'flex', gap: 24, justifyContent: 'center', flexWrap: 'wrap' }}>
          <span>✓ Free tier — forever</span>
          <span>✓ No credit card</span>
          <span>✓ 2-minute setup</span>
          <span>✓ Read-only permissions</span>
        </div>
      </section>

      {/* ── SOCIAL PROOF BAR ── */}
      <section style={{ padding: '0 24px 72px' }}>
        <div style={{
          maxWidth: 820, margin: '0 auto',
          background: 'rgba(255,255,255,0.025)', borderRadius: 16,
          border: '1px solid rgba(255,255,255,0.07)',
          display: 'flex', flexWrap: 'wrap', justifyContent: 'center',
        }}>
          {[
            { value: '60s',    label: 'Scan cycle' },
            { value: '$15',    label: 'Per month, flat' },
            { value: '1-tap',  label: 'Remediation' },
            { value: '100%',   label: 'Microsoft Graph API' },
            { value: '$0',     label: 'Free tier forever' },
          ].map((s, i, arr) => (
            <div key={s.value} style={{
              flex: '1 1 120px', padding: '20px 16px', textAlign: 'center',
              borderRight: i < arr.length - 1 ? '1px solid rgba(255,255,255,0.06)' : 'none',
            }}>
              <div style={{ fontSize: 24, fontWeight: 900, color: ORANGE, marginBottom: 4 }}>{s.value}</div>
              <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.35)', fontWeight: 600, letterSpacing: 0.3 }}>{s.label}</div>
            </div>
          ))}
        </div>
      </section>

      {/* ── PROBLEM SECTION ── */}
      <section style={{ padding: '0 24px 96px' }}>
        <div style={{ maxWidth: 880, margin: '0 auto' }}>
          <div style={{ textAlign: 'center', marginBottom: 52 }}>
            <h2 style={{ fontSize: 'clamp(22px, 4vw, 34px)', fontWeight: 800, letterSpacing: -0.5, marginBottom: 12 }}>
              The attack you don't see — until it's too late
            </h2>
            <p style={{ fontSize: 15, color: 'rgba(255,255,255,0.40)', maxWidth: 540, margin: '0 auto', lineHeight: 1.7 }}>
              Credential theft in Microsoft 365 is the most common attack vector. Here's what a typical compromise looks like — and how fast it moves.
            </p>
          </div>

          <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap' }}>
            {/* Without IdentityMonitor */}
            <div style={{
              flex: '1 1 320px',
              background: 'rgba(239,68,68,0.05)', border: '1px solid rgba(239,68,68,0.15)',
              borderRadius: 18, padding: '24px',
            }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: RED, letterSpacing: 0.8, marginBottom: 20, textTransform: 'uppercase' }}>
                🔴 Without IdentityMonitor
              </div>
              {[
                { time: 'T+0:00',  text: 'Attacker steals credentials via phishing' },
                { time: 'T+0:03',  text: 'Signs in from another country — no alert' },
                { time: 'T+0:07',  text: 'Accesses SharePoint, downloads files' },
                { time: 'T+0:15',  text: 'Creates forwarding rule on exec mailbox' },
                { time: 'T+2 days', text: 'IT notices something wrong. Breach confirmed.' },
              ].map((e) => (
                <div key={e.time} style={{ display: 'flex', gap: 14, marginBottom: 14, alignItems: 'flex-start' }}>
                  <div style={{ fontSize: 10, fontFamily: 'monospace', color: RED, fontWeight: 700, flexShrink: 0, paddingTop: 2, width: 60 }}>{e.time}</div>
                  <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.55)', lineHeight: 1.5 }}>{e.text}</div>
                </div>
              ))}
              <div style={{ marginTop: 8, padding: '10px 14px', background: 'rgba(239,68,68,0.08)', borderRadius: 8, fontSize: 12, color: RED, fontWeight: 700 }}>
                Average dwell time: 2+ days. Average breach cost: $4.9M.
              </div>
            </div>

            {/* With IdentityMonitor */}
            <div style={{
              flex: '1 1 320px',
              background: 'rgba(0,201,139,0.04)', border: '1px solid rgba(0,201,139,0.18)',
              borderRadius: 18, padding: '24px',
            }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: '#00C98B', letterSpacing: 0.8, marginBottom: 20, textTransform: 'uppercase' }}>
                🟢 With IdentityMonitor
              </div>
              {[
                { time: 'T+0:00',  text: 'Attacker steals credentials via phishing' },
                { time: 'T+0:03',  text: 'Sign-in from new country — scanner catches it' },
                { time: 'T+0:03',  text: 'Telegram alert fires with full context', highlight: true },
                { time: 'T+0:04',  text: 'You tap ⊘ Revoke Sessions from your phone', highlight: true },
                { time: 'T+0:04',  text: 'Attacker locked out. Audit log created.', highlight: true },
              ].map((e: any) => (
                <div key={e.time + e.text} style={{ display: 'flex', gap: 14, marginBottom: 14, alignItems: 'flex-start' }}>
                  <div style={{ fontSize: 10, fontFamily: 'monospace', color: '#00C98B', fontWeight: 700, flexShrink: 0, paddingTop: 2, width: 60 }}>{e.time}</div>
                  <div style={{ fontSize: 13, color: e.highlight ? 'rgba(255,255,255,0.85)' : 'rgba(255,255,255,0.55)', lineHeight: 1.5, fontWeight: e.highlight ? 600 : 400 }}>{e.text}</div>
                </div>
              ))}
              <div style={{ marginTop: 8, padding: '10px 14px', background: 'rgba(0,201,139,0.08)', borderRadius: 8, fontSize: 12, color: '#00C98B', fontWeight: 700 }}>
                Dwell time: &lt;4 minutes. Damage: zero.
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── DETECT + ACT STRIP ── */}
      <section style={{ padding: '0 24px 88px' }}>
        <div style={{ maxWidth: 940, margin: '0 auto' }}>
          <div style={{ textAlign: 'center', marginBottom: 14, fontSize: 11, fontWeight: 700, letterSpacing: 1, color: 'rgba(255,255,255,0.28)', textTransform: 'uppercase' }}>
            🔍 What we detect
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, justifyContent: 'center', marginBottom: 28 }}>
            {DETECTIONS.map(d => (
              <span key={d} style={{
                padding: '6px 15px', borderRadius: 99, fontSize: 12, fontWeight: 500,
                background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.09)',
                color: 'rgba(255,255,255,0.65)',
              }}>{d}</span>
            ))}
          </div>
          <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', marginBottom: 28 }} />
          <div style={{ textAlign: 'center', marginBottom: 14, fontSize: 11, fontWeight: 700, letterSpacing: 1, color: ORANGE, textTransform: 'uppercase' }}>
            ⚡ What we do about it
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, justifyContent: 'center' }}>
            {ACTIONS.map(a => (
              <span key={a} style={{
                padding: '6px 15px', borderRadius: 99, fontSize: 12, fontWeight: 600,
                background: 'rgba(232,120,74,0.08)', border: '1px solid rgba(232,120,74,0.22)',
                color: '#F5A462',
              }}>{a}</span>
            ))}
          </div>
        </div>
      </section>

      {/* ── REMEDIATION SHOWCASE ── */}
      <section style={{ padding: '0 24px 100px', background: 'rgba(255,255,255,0.012)' }}>
        <div style={{ maxWidth: 960, margin: '0 auto', paddingTop: 80 }}>
          <div style={{ textAlign: 'center', marginBottom: 56 }}>
            <Badge>🔥 Detect → Alert → Contain</Badge>
            <h2 style={{ fontSize: 'clamp(22px, 4vw, 32px)', fontWeight: 800, marginTop: 20, marginBottom: 12, letterSpacing: -0.5 }}>
              From threat detected to session revoked — in under 60 seconds
            </h2>
            <p style={{ fontSize: 15, color: 'rgba(255,255,255,0.40)', maxWidth: 520, margin: '0 auto' }}>
              Most tools just tell you something happened. IdentityMonitor lets you stop it — from your phone, right now.
            </p>
          </div>

          <div style={{ display: 'flex', gap: 32, flexWrap: 'wrap', alignItems: 'stretch' }}>
            {/* Left: Timeline */}
            <div style={{ flex: '1 1 300px', display: 'flex', flexDirection: 'column', gap: 0 }}>
              {[
                { icon: '🔍', color: '#888',    label: 'Detected',  text: 'Impossible travel — Tel Aviv → New York in 90 min' },
                { icon: '📱', color: ORANGE,    label: 'Alerted',   text: 'Telegram message with full context fires in &lt;60 seconds' },
                { icon: '👆', color: '#9B8AFB', label: 'Responded', text: 'You tap Revoke — or it triggers automatically on critical' },
                { icon: '✅', color: '#00C98B', label: 'Contained', text: 'Session revoked. Attacker locked out. Logged in Audit Center.' },
              ].map((step, i, arr) => (
                <div key={step.label} style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0 }}>
                    <div style={{
                      width: 42, height: 42, borderRadius: '50%', flexShrink: 0,
                      background: `${step.color}22`, border: `2px solid ${step.color}55`,
                      display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 18,
                    }}>{step.icon}</div>
                    {i < arr.length - 1 && <div style={{ width: 2, height: 36, background: 'rgba(255,255,255,0.07)', margin: '4px 0' }} />}
                  </div>
                  <div style={{ paddingTop: 8 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.8, color: step.color, marginBottom: 2 }}>{step.label}</div>
                    <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.60)', lineHeight: 1.55, marginBottom: 20 }} dangerouslySetInnerHTML={{ __html: step.text }} />
                  </div>
                </div>
              ))}
            </div>

            {/* Right: Telegram mockup */}
            <div style={{ flex: '1 1 320px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <div style={{
                background: '#17212B', borderRadius: 18, padding: '20px 18px',
                width: '100%', maxWidth: 380,
                boxShadow: '0 24px 64px rgba(0,0,0,0.55)',
                border: '1px solid rgba(255,255,255,0.07)',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16, paddingBottom: 12, borderBottom: '1px solid rgba(255,255,255,0.07)' }}>
                  <img src="/logo.svg" alt="" style={{ width: 36, height: 36, borderRadius: '50%', objectFit: 'cover' }} />
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 700, color: '#fff' }}>IdentityMonitor</div>
                    <div style={{ fontSize: 11, color: '#5B7FA6' }}>bot · online</div>
                  </div>
                </div>

                <div style={{ background: '#1E2D3D', borderRadius: 10, padding: '12px 14px', marginBottom: 10 }}>
                  <div style={{ fontSize: 13, fontWeight: 700, color: '#FF4455', marginBottom: 8 }}>🚨 CRITICAL ALERT</div>
                  <div style={{ fontSize: 12, color: '#aaa', lineHeight: 1.7 }}>
                    <div><span style={{ color: '#fff', fontWeight: 600 }}>User:</span> john.doe@contoso.com</div>
                    <div><span style={{ color: '#fff', fontWeight: 600 }}>Threat:</span> Impossible Travel</div>
                    <div><span style={{ color: '#fff', fontWeight: 600 }}>Route:</span> 🇮🇱 Tel Aviv → 🇺🇸 New York</div>
                    <div><span style={{ color: '#fff', fontWeight: 600 }}>Time gap:</span> 90 min (physically impossible)</div>
                    <div><span style={{ color: '#fff', fontWeight: 600 }}>App:</span> Microsoft Azure Portal</div>
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
                  <div style={{ padding: '8px 6px', borderRadius: 8, textAlign: 'center', background: 'rgba(239,68,68,0.10)', border: '1px solid rgba(239,68,68,0.25)', fontSize: 11, fontWeight: 600, color: '#ef4444' }}>⊘ Revoke Sessions</div>
                  <div style={{ padding: '8px 6px', borderRadius: 8, textAlign: 'center', background: 'rgba(232,120,74,0.10)', border: '1px solid rgba(232,120,74,0.25)', fontSize: 11, fontWeight: 600, color: '#E8784A' }}>⊘ Disable User</div>
                  <div style={{ padding: '8px 6px', borderRadius: 8, textAlign: 'center', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.14)', fontSize: 11, fontWeight: 600, color: 'rgba(255,255,255,0.60)' }}>🔍 Investigate</div>
                  <div style={{ padding: '8px 6px', borderRadius: 8, textAlign: 'center', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.14)', fontSize: 11, fontWeight: 600, color: 'rgba(255,255,255,0.60)' }}>✓ Dismiss</div>
                </div>
                <div style={{ marginTop: 10, fontSize: 10, color: '#5B7FA6', textAlign: 'center' }}>
                  Auto-revoke in 30 min if no action taken
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── DEFENDER VULNERABILITY SECTION ── */}
      <section style={{ padding: '80px 24px 100px' }}>
        <div style={{ maxWidth: 980, margin: '0 auto' }}>
          <div style={{ textAlign: 'center', marginBottom: 56 }}>
            <Badge>🛡️ Microsoft Defender Integration</Badge>
            <h2 style={{ fontSize: 'clamp(22px, 4vw, 34px)', fontWeight: 800, margin: '20px 0 14px', letterSpacing: -0.5 }}>
              Endpoint vulnerability management — built in
            </h2>
            <p style={{ fontSize: 15, color: 'rgba(255,255,255,0.40)', maxWidth: 560, margin: '0 auto', lineHeight: 1.7 }}>
              Connect Microsoft Defender and see every open CVE across your fleet — prioritised by severity, exploit probability, and affected device count. Fix in one click.
            </p>
          </div>

          <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap', alignItems: 'flex-start' }}>
            {/* CVE list */}
            <div style={{ flex: '1 1 340px', background: '#0f0f17', borderRadius: 18, border: '1px solid rgba(255,255,255,0.07)', overflow: 'hidden' }}>
              <div style={{ padding: '14px 20px', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ fontSize: 12, fontWeight: 700, color: 'rgba(255,255,255,0.4)', letterSpacing: 0.8 }}>DEFENDER · VULNERABILITIES</div>
                <div style={{ fontSize: 11, padding: '3px 10px', borderRadius: 99, background: 'rgba(232,120,74,0.12)', color: '#E8784A', fontWeight: 700 }}>24 open</div>
              </div>
              {[
                { cve: 'CVE-2024-43461', product: 'Windows MSHTML Platform',  severity: 'Critical', cvss: '9.8', devices: 12, exploit: true  },
                { cve: 'CVE-2024-38189', product: 'Microsoft Office Project',  severity: 'High',     cvss: '8.8', devices: 7,  exploit: true  },
                { cve: 'CVE-2024-38213', product: 'Windows SmartScreen',       severity: 'High',     cvss: '6.5', devices: 15, exploit: false },
                { cve: 'CVE-2024-21447', product: 'Google Chrome',             severity: 'Medium',   cvss: '5.9', devices: 9,  exploit: false },
              ].map((row, i) => {
                const sc = row.severity === 'Critical' ? '#FF3D6B' : row.severity === 'High' ? '#FF7A3D' : '#F5C543';
                return (
                  <div key={row.cve} style={{ padding: '13px 20px', borderBottom: i < 3 ? '1px solid rgba(255,255,255,0.05)' : 'none', display: 'flex', alignItems: 'center', gap: 12, background: i === 0 ? 'rgba(255,61,107,0.04)' : 'transparent' }}>
                    <div style={{ width: 9, height: 9, borderRadius: '50%', background: sc, flexShrink: 0, boxShadow: `0 0 6px ${sc}88` }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
                        <span style={{ fontSize: 12, fontWeight: 700, color: '#fff', fontFamily: 'monospace' }}>{row.cve}</span>
                        {row.exploit && <span style={{ fontSize: 10, padding: '1px 7px', borderRadius: 4, background: 'rgba(255,61,107,0.15)', color: '#FF3D6B', fontWeight: 700 }}>EXPLOIT</span>}
                      </div>
                      <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.45)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row.product}</div>
                    </div>
                    <div style={{ textAlign: 'right', flexShrink: 0 }}>
                      <div style={{ fontSize: 11, fontWeight: 700, color: sc }}>{row.severity}</div>
                      <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.30)' }}>CVSS {row.cvss} · {row.devices} devices</div>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Remediation panel */}
            <div style={{ flex: '1 1 300px', display: 'flex', flexDirection: 'column', gap: 16 }}>
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
                <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
                  <span style={{ fontSize: 11, padding: '4px 12px', borderRadius: 6, background: 'rgba(91,155,213,0.12)', color: '#5B9BD5', fontWeight: 700, border: '1px solid rgba(91,155,213,0.20)' }}>⊞ Windows Update</span>
                  <span style={{ fontSize: 11, padding: '4px 12px', borderRadius: 6, background: 'rgba(255,61,107,0.10)', color: '#FF3D6B', fontWeight: 700, border: '1px solid rgba(255,61,107,0.18)' }}>🔴 Exploit in wild</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
                  <div style={{ padding: '9px 16px', borderRadius: 8, cursor: 'default', fontWeight: 600, fontSize: 12, background: 'linear-gradient(135deg, #E8784A, #F5A462)', color: '#fff', boxShadow: '0 4px 16px rgba(232,120,74,0.35)' }}>
                    ⊞ Trigger Windows Update on all 12 devices
                  </div>
                  <div style={{ padding: '9px 16px', borderRadius: 8, cursor: 'default', fontWeight: 600, fontSize: 12, background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.14)', color: 'rgba(255,255,255,0.60)' }}>
                    🔄 Reset Windows Update components (script)
                  </div>
                  <div style={{ padding: '9px 16px', borderRadius: 8, cursor: 'default', fontWeight: 600, fontSize: 12, background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.14)', color: 'rgba(255,255,255,0.60)' }}>
                    🔍 View all 12 affected devices
                  </div>
                </div>
              </div>
              <div style={{ display: 'flex', gap: 12 }}>
                {[{ label: 'Critical CVEs', value: '3', color: '#FF3D6B' }, { label: 'Devices at risk', value: '15', color: ORANGE }, { label: 'With exploit', value: '2', color: '#F5C543' }].map(s => (
                  <div key={s.label} style={{ flex: 1, background: '#0f0f17', borderRadius: 12, border: '1px solid rgba(255,255,255,0.07)', padding: '14px 12px', textAlign: 'center' }}>
                    <div style={{ fontSize: 22, fontWeight: 900, color: s.color, marginBottom: 4 }}>{s.value}</div>
                    <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.35)', fontWeight: 600 }}>{s.label}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div style={{ marginTop: 40, textAlign: 'center' }}>
            <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.28)', marginBottom: 16, letterSpacing: 0.8, fontWeight: 700, textTransform: 'uppercase' }}>Remediation types supported</div>
            <div style={{ display: 'flex', gap: 10, justifyContent: 'center', flexWrap: 'wrap' }}>
              {[
                { label: '⊞ Windows Update', color: '#5B9BD5' },
                { label: '📦 Application patch', color: '#A78BFA' },
                { label: '⚡ PowerShell script', color: ORANGE },
                { label: '📋 Intune policy', color: '#00C98B' },
                { label: '🔍 Device drill-down', color: 'rgba(255,255,255,0.45)' },
                { label: '🧬 CVSS + EPSS scoring', color: 'rgba(255,255,255,0.45)' },
              ].map(p => (
                <span key={p.label} style={{ padding: '7px 16px', borderRadius: 99, fontSize: 12, fontWeight: 600, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.09)', color: p.color }}>
                  {p.label}
                </span>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ── HOW IT WORKS ── */}
      <section id="how" style={{ padding: '80px 24px 100px', background: 'rgba(255,255,255,0.015)' }}>
        <div style={{ maxWidth: 800, margin: '0 auto' }}>
          <h2 style={{ textAlign: 'center', fontSize: 'clamp(22px, 4vw, 32px)', fontWeight: 800, marginBottom: 56, letterSpacing: -0.5 }}>
            Up and running in 5 minutes
          </h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 36 }}>
            {STEPS.map((s, i) => (
              <div key={s.n} style={{ display: 'flex', gap: 24, alignItems: 'flex-start' }}>
                <div style={{
                  flexShrink: 0, width: 46, height: 46, borderRadius: '50%',
                  background: `linear-gradient(135deg, ${ORANGE}, #F5A462)`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontWeight: 900, fontSize: 18, color: '#fff',
                  boxShadow: '0 4px 20px rgba(232,120,74,0.35)',
                }}>{s.n}</div>
                <div>
                  <div style={{ fontSize: 17, fontWeight: 700, marginBottom: 6 }}>{s.title}</div>
                  <div style={{ fontSize: 14, color: 'rgba(255,255,255,0.50)', lineHeight: 1.7, marginBottom: 8 }}>{s.desc}</div>
                  <div style={{ fontSize: 11, fontWeight: 700, color: ORANGE, letterSpacing: 0.3 }}>→ {s.detail}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── WHY NOT SENTINEL ── */}
      <section style={{ padding: '80px 24px 100px' }}>
        <div style={{ maxWidth: 860, margin: '0 auto' }}>
          <h2 style={{ textAlign: 'center', fontSize: 'clamp(22px, 4vw, 32px)', fontWeight: 800, marginBottom: 12, letterSpacing: -0.5 }}>
            Why not Microsoft Sentinel or Defender for Identity?
          </h2>
          <p style={{ textAlign: 'center', fontSize: 15, color: 'rgba(255,255,255,0.40)', marginBottom: 48, maxWidth: 540, margin: '0 auto 48px' }}>
            Great tools — but built for enterprise security teams with $10k/month budgets and full-time analysts. IdentityMonitor is built for MSPs and IT admins who need results without the complexity.
          </p>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr>
                  {['', 'Microsoft Sentinel', 'Defender for Identity', 'IdentityMonitor'].map((h, i) => (
                    <th key={h} style={{
                      padding: '12px 16px', textAlign: 'left', fontWeight: 700, fontSize: 12,
                      color: i === 3 ? ORANGE : 'rgba(255,255,255,0.45)',
                      borderBottom: `2px solid ${i === 3 ? ORANGE : 'rgba(255,255,255,0.08)'}`,
                      background: i === 3 ? 'rgba(232,120,74,0.04)' : 'transparent',
                      letterSpacing: 0.3,
                    }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {[
                  ['Price', '$100–$500+/mo', '$9/user/mo', '$15/mo flat'],
                  ['Setup time', 'Weeks', 'Days', '2 minutes'],
                  ['Requires analyst', '✓ Yes', '✓ Yes', '✗ No'],
                  ['One-tap remediation', '✗ No', '✗ No', '✓ Yes'],
                  ['Telegram action alerts', '✗ No', '✗ No', '✓ Yes'],
                  ['Defender CVE + remediation', '✗ Separate module', '✗ No', '✓ Built in'],
                  ['Auto session revoke', '✗ SOAR add-on', '✗ No', '✓ Built in'],
                  ['Multi-tenant (MSP)', '✓ Complex', '✓ Complex', '✓ Built in'],
                ].map((row, ri) => (
                  <tr key={ri} style={{ background: ri % 2 === 0 ? 'rgba(255,255,255,0.015)' : 'transparent' }}>
                    {row.map((cell, ci) => (
                      <td key={ci} style={{
                        padding: '11px 16px',
                        color: ci === 0 ? 'rgba(255,255,255,0.55)' : ci === 3 ? (cell.startsWith('✓') ? '#00C98B' : cell.startsWith('✗') ? 'rgba(255,255,255,0.35)' : '#fff') : 'rgba(255,255,255,0.40)',
                        fontWeight: ci === 3 ? 600 : ci === 0 ? 500 : 400,
                        background: ci === 3 ? 'rgba(232,120,74,0.03)' : 'transparent',
                        borderBottom: '1px solid rgba(255,255,255,0.05)',
                        fontSize: ci === 0 ? 13 : 12,
                      }}>{cell}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* ── PRICING ── */}
      <section style={{ padding: '0 24px 100px', background: 'rgba(255,255,255,0.012)' }}>
        <div style={{ maxWidth: 720, margin: '0 auto', paddingTop: 80, textAlign: 'center' }}>
          <h2 style={{ fontSize: 'clamp(22px, 4vw, 32px)', fontWeight: 800, marginBottom: 10, letterSpacing: -0.5 }}>
            Simple, honest pricing
          </h2>
          <p style={{ fontSize: 15, color: 'rgba(255,255,255,0.40)', marginBottom: 48 }}>
            Start free today. Upgrade when you're ready to act on threats — not just see them.
          </p>

          <div style={{ display: 'flex', gap: 20, flexWrap: 'wrap', justifyContent: 'center' }}>
            {/* Free */}
            <div style={{
              flex: '1 1 270px', maxWidth: 320,
              background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.09)',
              borderRadius: 20, padding: '28px 24px', textAlign: 'left',
            }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: 'rgba(255,255,255,0.35)', marginBottom: 14, letterSpacing: 1 }}>FREE</div>
              <div style={{ fontSize: 40, fontWeight: 900, marginBottom: 6 }}>$0<span style={{ fontSize: 14, fontWeight: 400, color: 'rgba(255,255,255,0.35)' }}>/mo</span></div>
              <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.35)', marginBottom: 20 }}>Forever. No credit card needed.</div>
              {[
                'Anomaly detection (60s scan)',
                'Alert dashboard',
                'User risk overview',
                'Defender CVE list (read-only)',
                'Multi-tenant support',
              ].map(f => (
                <div key={f} style={{ fontSize: 13, color: 'rgba(255,255,255,0.55)', marginBottom: 9, display: 'flex', gap: 9, alignItems: 'flex-start' }}>
                  <span style={{ color: '#00C98B', flexShrink: 0, marginTop: 1 }}>✓</span> {f}
                </div>
              ))}
              <a href="/api/auth/login" style={{
                display: 'block', marginTop: 24, padding: '12px 0', borderRadius: 10, textAlign: 'center',
                background: 'rgba(255,255,255,0.07)', border: '1px solid rgba(255,255,255,0.12)',
                color: '#fff', textDecoration: 'none', fontSize: 13, fontWeight: 700,
              }}>Get started free</a>
            </div>

            {/* Pro */}
            <div style={{
              flex: '1 1 270px', maxWidth: 320,
              background: 'rgba(232,120,74,0.07)', border: '2px solid rgba(232,120,74,0.35)',
              borderRadius: 20, padding: '28px 24px', textAlign: 'left',
              boxShadow: '0 0 48px rgba(232,120,74,0.12)',
              position: 'relative', overflow: 'hidden',
            }}>
              <div style={{ position: 'absolute', top: 16, right: 16, fontSize: 10, padding: '3px 10px', borderRadius: 99, background: ORANGE, color: '#fff', fontWeight: 800, letterSpacing: 0.5 }}>MOST POPULAR</div>
              <div style={{ fontSize: 12, fontWeight: 700, color: ORANGE, marginBottom: 14, letterSpacing: 1 }}>PRO</div>
              <div style={{ fontSize: 40, fontWeight: 900, color: '#fff', marginBottom: 6 }}>$15<span style={{ fontSize: 14, fontWeight: 400, color: 'rgba(255,255,255,0.40)' }}>/mo</span></div>
              <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.40)', marginBottom: 20 }}>Per tenant · Cancel any time</div>
              {[
                'Everything in Free',
                'Telegram alerts + action buttons',
                'Email notifications',
                'Auto session revoke',
                'Auto disable on critical severity',
                'CVE one-click remediation',
                'Conditional Access + PIM monitoring',
                '180-day alert retention',
              ].map(f => (
                <div key={f} style={{ fontSize: 13, color: 'rgba(255,255,255,0.75)', marginBottom: 9, display: 'flex', gap: 9, alignItems: 'flex-start' }}>
                  <span style={{ color: ORANGE, flexShrink: 0, marginTop: 1 }}>✓</span> {f}
                </div>
              ))}
              <a href="/pricing" style={{
                display: 'block', marginTop: 24, padding: '12px 0', borderRadius: 10, textAlign: 'center',
                background: `linear-gradient(135deg, ${ORANGE}, #F5A462)`,
                color: '#fff', textDecoration: 'none', fontSize: 13, fontWeight: 700,
                boxShadow: '0 4px 20px rgba(232,120,74,0.35)',
              }}>Start Pro — $15/mo</a>
            </div>
          </div>
        </div>
      </section>

      {/* ── FAQ ── */}
      <section style={{ padding: '80px 24px 100px' }}>
        <div style={{ maxWidth: 680, margin: '0 auto' }}>
          <h2 style={{ textAlign: 'center', fontSize: 'clamp(22px, 4vw, 30px)', fontWeight: 800, marginBottom: 48, letterSpacing: -0.4 }}>
            Common questions
          </h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {FAQ.map((item, i) => (
              <div key={i} style={{
                background: 'rgba(255,255,255,0.03)', borderRadius: 14,
                border: `1px solid ${openFaq === i ? 'rgba(232,120,74,0.30)' : 'rgba(255,255,255,0.08)'}`,
                overflow: 'hidden', cursor: 'pointer',
              }} onClick={() => setOpenFaq(openFaq === i ? null : i)}>
                <div style={{ padding: '16px 20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 16 }}>
                  <div style={{ fontSize: 14, fontWeight: 600, color: openFaq === i ? '#fff' : 'rgba(255,255,255,0.80)' }}>{item.q}</div>
                  <div style={{ fontSize: 18, color: ORANGE, flexShrink: 0, transform: openFaq === i ? 'rotate(45deg)' : 'none', transition: 'transform 200ms' }}>+</div>
                </div>
                {openFaq === i && (
                  <div style={{ padding: '0 20px 18px', fontSize: 13, color: 'rgba(255,255,255,0.55)', lineHeight: 1.75 }}>
                    {item.a}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA BANNER ── */}
      <section style={{
        margin: '0 24px 80px', borderRadius: 22,
        background: `linear-gradient(135deg, rgba(232,120,74,0.13), rgba(232,120,74,0.04))`,
        border: '1px solid rgba(232,120,74,0.25)',
        padding: '60px 32px', textAlign: 'center',
        maxWidth: 860, marginLeft: 'auto', marginRight: 'auto',
      }}>
        <div style={{ fontSize: 13, fontWeight: 700, color: ORANGE, letterSpacing: 1, marginBottom: 16, textTransform: 'uppercase' }}>
          Right now, someone might be in your tenant
        </div>
        <h2 style={{ fontSize: 'clamp(24px, 4vw, 36px)', fontWeight: 800, marginBottom: 14, letterSpacing: -0.5 }}>
          Find out in the next 60 seconds.
        </h2>
        <p style={{ fontSize: 15, color: 'rgba(255,255,255,0.45)', marginBottom: 36, maxWidth: 480, margin: '0 auto 36px' }}>
          Connect your Microsoft 365 tenant for free. No credit card, no commit, no install. The first scan runs immediately.
        </p>
        <div style={{ display: 'flex', gap: 14, justifyContent: 'center', flexWrap: 'wrap' }}>
          <Btn href="/api/auth/login" primary large>Scan my tenant now — free →</Btn>
          <Btn href="/pricing">See Pro features</Btn>
        </div>
        <div style={{ marginTop: 20, fontSize: 12, color: 'rgba(255,255,255,0.25)' }}>
          ✓ Read-only permissions &nbsp;·&nbsp; ✓ Setup in 2 minutes &nbsp;·&nbsp; ✓ Cancel any time
        </div>
      </section>

      {/* ── FOOTER ── */}
      <footer style={{ borderTop: '1px solid rgba(255,255,255,0.06)', padding: '32px 24px', textAlign: 'center' }}>
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
