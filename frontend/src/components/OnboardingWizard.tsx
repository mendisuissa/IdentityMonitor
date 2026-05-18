import React, { useEffect, useRef, useState } from 'react';
import { api } from '../services/api';

// ─── Types ────────────────────────────────────────────────────────────────────

interface Props {
  tenantId: string;
  tenantName: string;
  onComplete: () => void;
}

interface PostureData {
  health?: {
    graphPermissionsOk?: boolean;
    signInLogsAvailable?: boolean;
  };
  privilegedUsers?: { total?: number; count?: number } | any[];
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const TOTAL_STEPS = 6;

function privilegedCount(posture: PostureData | null): number {
  if (!posture) return 0;
  if (Array.isArray(posture.privilegedUsers)) return posture.privilegedUsers.length;
  if (posture.privilegedUsers && typeof posture.privilegedUsers === 'object') {
    return (posture.privilegedUsers as any).total ?? (posture.privilegedUsers as any).count ?? 0;
  }
  return 0;
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function ProgressBar({ step }: { step: number }) {
  const pct = ((step - 1) / (TOTAL_STEPS - 1)) * 100;
  return (
    <div style={{
      height: 4,
      background: 'rgba(255,255,255,0.08)',
      borderRadius: 99,
      overflow: 'hidden',
      marginBottom: 28,
    }}>
      <div style={{
        height: '100%',
        width: `${pct}%`,
        background: 'linear-gradient(90deg, #E8784A, #F5A462)',
        borderRadius: 99,
        transition: 'width 400ms cubic-bezier(0.4,0,0.2,1)',
        boxShadow: '0 0 10px rgba(232,120,74,0.55)',
      }} />
    </div>
  );
}

function StepLabel({ step }: { step: number }) {
  return (
    <div style={{
      fontSize: 11,
      fontWeight: 600,
      letterSpacing: '0.6px',
      textTransform: 'uppercase',
      color: 'var(--text-muted)',
      marginBottom: 8,
    }}>
      Step {step} of {TOTAL_STEPS}
    </div>
  );
}

function CheckRow({ ok, label, sub }: { ok: boolean | null; label: string; sub?: string }) {
  const pending = ok === null;
  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      gap: 12,
      padding: '11px 14px',
      borderRadius: 10,
      background: pending
        ? 'rgba(255,255,255,0.03)'
        : ok
          ? 'rgba(0,201,139,0.07)'
          : 'rgba(255,68,85,0.07)',
      border: `1px solid ${pending ? 'rgba(255,255,255,0.07)' : ok ? 'rgba(0,201,139,0.2)' : 'rgba(255,68,85,0.2)'}`,
      transition: 'all 300ms ease',
    }}>
      <span style={{ fontSize: 18, lineHeight: 1, flexShrink: 0 }}>
        {pending ? (
          <span style={{ display: 'inline-block', width: 18, height: 18, border: '2px solid rgba(255,255,255,0.15)', borderTopColor: '#E8784A', borderRadius: '50%', animation: 'spin 0.8s linear infinite', verticalAlign: 'middle' }} />
        ) : ok ? '✅' : '❌'}
      </span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>{label}</div>
        {sub && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 1 }}>{sub}</div>}
      </div>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function OnboardingWizard({ tenantId, tenantName, onComplete }: Props) {
  // ── Navigation ──
  const [step, setStep] = useState(1);

  // ── Step 2: Permissions ──
  const [posture, setPosture] = useState<PostureData | null>(null);
  const [postureLoading, setPostureLoading] = useState(false);
  const [postureError, setPostureError] = useState('');
  const postureCheckedRef = useRef(false);
  const [defenderScope, setDefenderScope] = useState<any>(null);

  // ── Step 3: Remediation service (webapp consent) ──
  const [onboardingStatus, setOnboardingStatus] = useState<any>(null);
  const onboardingStatusLoadedRef = useRef(false);

  // ── Step 4: Telegram ──
  const [telegramToken, setTelegramToken] = useState('');
  const [telegramChatId, setTelegramChatId] = useState('');
  const [telegramSaving, setTelegramSaving] = useState(false);
  const [telegramTested, setTelegramTested] = useState(false);
  const [telegramSkipped, setTelegramSkipped] = useState(false);
  const [telegramMsg, setTelegramMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const telegramLoadedRef = useRef(false);

  // ── Step 5: Admins ──
  const [admins, setAdmins] = useState<any[]>([]);
  const [adminEmail, setAdminEmail] = useState('');
  const [adminRole, setAdminRole] = useState<'owner' | 'admin' | 'analyst'>('admin');
  const [adminAdding, setAdminAdding] = useState(false);
  const [adminMsg, setAdminMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [adminSkipped, setAdminSkipped] = useState(false);
  const adminsLoadedRef = useRef(false);

  // ── Step 6: First Scan ──
  const [scanRunning, setScanRunning] = useState(false);
  const [scanResult, setScanResult] = useState<{ newAlerts: number } | null>(null);
  const [scanError, setScanError] = useState('');
  const [completing, setCompleting] = useState(false);
  const scanFiredRef = useRef(false);

  // ── Step 2: auto-run permissions check ──────────────────────────────────────
  useEffect(() => {
    if (step === 2 && !postureCheckedRef.current) {
      postureCheckedRef.current = true;
      runPermissionsCheck();
    }
  }, [step]); // eslint-disable-line react-hooks/exhaustive-deps

  const runPermissionsCheck = async () => {
    setPostureLoading(true);
    setPostureError('');
    setPosture(null);
    try {
      const [data, scopes] = await Promise.allSettled([
        api.getPosture(),
        api.getDefenderScopes(),
      ]);
      if (data.status === 'fulfilled') setPosture(data.value);
      else throw data.reason;
      if (scopes.status === 'fulfilled') setDefenderScope(scopes.value);
    } catch (e: any) {
      setPostureError(e?.message || 'Failed to check permissions');
    } finally {
      setPostureLoading(false);
    }
  };

  const recheck = () => {
    postureCheckedRef.current = true;
    runPermissionsCheck();
  };

  // ── Step 3: load onboarding status (webapp consent) ─────────────────────────
  useEffect(() => {
    if (step === 3 && !onboardingStatusLoadedRef.current) {
      onboardingStatusLoadedRef.current = true;
      api.getOnboardingStatus().then(setOnboardingStatus).catch(() => {});
    }
  }, [step]);

  // ── Step 4: pre-fill Telegram settings ──────────────────────────────────────
  useEffect(() => {
    if (step === 4 && !telegramLoadedRef.current) {
      telegramLoadedRef.current = true;
      api.getTelegramSettings()
        .then((d: any) => {
          if (d?.telegramBotToken) setTelegramToken(d.telegramBotToken);
          if (d?.telegramChatId) setTelegramChatId(d.telegramChatId);
        })
        .catch(() => {});
    }
  }, [step]);

  const handleTelegramSaveTest = async () => {
    if (!telegramToken.trim() || !telegramChatId.trim()) {
      setTelegramMsg({ ok: false, text: 'Both Bot Token and Chat ID are required.' });
      return;
    }
    setTelegramSaving(true);
    setTelegramMsg(null);
    try {
      await api.saveTelegramSettings({
        telegramBotToken: telegramToken.trim(),
        telegramChatId: telegramChatId.trim(),
      });
      await api.testTelegram();
      setTelegramTested(true);
      setTelegramMsg({ ok: true, text: '✅ Test message sent successfully!' });
    } catch (e: any) {
      setTelegramMsg({ ok: false, text: e?.message || 'Save or test failed. Check your credentials.' });
    } finally {
      setTelegramSaving(false);
    }
  };

  // ── Step 5: load admins ──────────────────────────────────────────────────────
  useEffect(() => {
    if (step === 5 && !adminsLoadedRef.current) {
      adminsLoadedRef.current = true;
      api.getAdmins()
        .then((d: any) => setAdmins(Array.isArray(d) ? d : d?.admins || []))
        .catch(() => {});
    }
  }, [step]);

  const handleAddAdmin = async () => {
    if (!adminEmail.trim()) {
      setAdminMsg({ ok: false, text: 'Email is required.' });
      return;
    }
    setAdminAdding(true);
    setAdminMsg(null);
    try {
      await api.addAdmin({ email: adminEmail.trim(), role: adminRole });
      const refreshed = await api.getAdmins().catch(() => null);
      if (refreshed) setAdmins(Array.isArray(refreshed) ? refreshed : refreshed?.admins || []);
      else setAdmins(prev => [...prev, { email: adminEmail.trim(), role: adminRole }]);
      setAdminEmail('');
      setAdminMsg({ ok: true, text: `✅ ${adminEmail.trim()} added.` });
    } catch (e: any) {
      setAdminMsg({ ok: false, text: e?.message || 'Failed to add admin.' });
    } finally {
      setAdminAdding(false);
    }
  };

  // ── Step 6: auto-run first scan ──────────────────────────────────────────────
  useEffect(() => {
    if (step === 6 && !scanFiredRef.current) {
      scanFiredRef.current = true;
      setScanRunning(true);
      setScanError('');
      setScanResult(null);
      api.triggerScan()
        .then((r: any) => setScanResult({ newAlerts: r?.newAlerts ?? r?.alertsCreated ?? 0 }))
        .catch((e: any) => setScanError(e?.message || 'Scan failed — check backend connection'))
        .finally(() => setScanRunning(false));
    }
  }, [step]);

  const handleComplete = async () => {
    setCompleting(true);
    try {
      await api.patchSettings({ onboarding: { wizardCompleted: true } });
    } catch {
      // non-fatal — proceed anyway
    } finally {
      setCompleting(false);
      onComplete();
    }
  };

  // ── Navigation helpers ───────────────────────────────────────────────────────
  const goNext = () => setStep(s => Math.min(s + 1, TOTAL_STEPS));
  const goBack = () => setStep(s => Math.max(s - 1, 1));

  // Step 2 readiness
  const permissionsAllGreen =
    posture !== null &&
    posture.health?.graphPermissionsOk === true &&
    posture.health?.signInLogsAvailable === true &&
    privilegedCount(posture) > 0;

  // Step 3 readiness — webapp consent
  const webappReady = !onboardingStatus?.webappClientId || !!onboardingStatus?.webappConsent;

  // Step 4 readiness
  const telegramReady = telegramTested || telegramSkipped;

  // Step 5 readiness
  const adminsReady = admins.length > 0 || adminSkipped;

  // ── Shared input style ───────────────────────────────────────────────────────
  const inputStyle: React.CSSProperties = {
    width: '100%',
    padding: '10px 13px',
    background: 'rgba(255,255,255,0.05)',
    border: '1px solid rgba(255,255,255,0.1)',
    borderRadius: 9,
    color: 'var(--text-primary)',
    fontSize: 13,
    fontFamily: 'var(--font-sans)',
    outline: 'none',
    boxSizing: 'border-box',
    transition: 'border-color 180ms ease, box-shadow 180ms ease',
  };

  const labelStyle: React.CSSProperties = {
    fontSize: 11,
    fontWeight: 600,
    letterSpacing: '0.4px',
    color: 'var(--text-muted)',
    textTransform: 'uppercase',
    marginBottom: 5,
    display: 'block',
  };

  // ─── Render ─────────────────────────────────────────────────────────────────
  return (
    <>
      {/* ── Backdrop ── */}
      <div style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.85)',
        backdropFilter: 'blur(6px)',
        zIndex: 1000,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '20px 16px',
      }}>
        {/* ── Wizard Card ── */}
        <div style={{
          width: '100%',
          maxWidth: 560,
          background: '#1A1A24',
          border: '1px solid rgba(255,255,255,0.1)',
          borderRadius: 20,
          padding: '32px 36px 30px',
          boxShadow: '0 32px 80px rgba(0,0,0,0.6), 0 0 0 1px rgba(232,120,74,0.08)',
          animation: 'onboardSlideUp 350ms cubic-bezier(0.34,1.56,0.64,1)',
          maxHeight: '90vh',
          overflowY: 'auto',
        }}>
          {/* ── Progress bar ── */}
          <ProgressBar step={step} />

          {/* ── Step label ── */}
          <StepLabel step={step} />

          {/* ── Step content ── */}
          <div style={{ minHeight: 280, display: 'flex', flexDirection: 'column' }}>

            {/* ════════════════════════════════ STEP 1 — Welcome ═══════════════════════════════ */}
            {step === 1 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 20, flex: 1 }}>
                {/* Logo */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 4 }}>
                  <div style={{
                    width: 52,
                    height: 52,
                    borderRadius: 14,
                    background: 'linear-gradient(135deg, #E8784A, #F5A462)',
                    boxShadow: '0 0 24px rgba(232,120,74,0.50)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                    overflow: 'hidden',
                  }}><img src="/logo.svg" alt="" style={{ width: '100%', height: '100%', objectFit: 'cover' }} /></div>
                  <div>
                    <div style={{ fontSize: 22, fontWeight: 800, color: 'var(--text-primary)', lineHeight: 1.2 }}>
                      Welcome to IdentityMonitor
                    </div>
                    <div style={{ fontSize: 14, color: 'var(--text-muted)', marginTop: 4 }}>
                      Let&apos;s get you set up in 4 quick steps
                    </div>
                  </div>
                </div>

                {/* Tenant badge */}
                <div style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 8,
                  alignSelf: 'flex-start',
                  padding: '7px 14px',
                  borderRadius: 99,
                  background: 'rgba(232,120,74,0.10)',
                  border: '1px solid rgba(232,120,74,0.25)',
                  fontSize: 13,
                  fontWeight: 600,
                  color: '#F5A462',
                }}>
                  <span style={{ fontSize: 15 }}>🏢</span>
                  {tenantName}
                </div>

                {/* What's included */}
                <div style={{
                  background: 'rgba(255,255,255,0.03)',
                  border: '1px solid rgba(255,255,255,0.07)',
                  borderRadius: 12,
                  padding: '16px 18px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 10,
                }}>
                  {[
                    { icon: '🔍', text: 'Verify your Microsoft Graph permissions' },
                    { icon: '📲', text: 'Set up Telegram security alerts' },
                    { icon: '👤', text: 'Add your admin team' },
                    { icon: '⚡', text: 'Run your first security scan' },
                  ].map(({ icon, text }) => (
                    <div key={text} style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 13, color: 'var(--text-secondary)' }}>
                      <span style={{ fontSize: 16, flexShrink: 0 }}>{icon}</span>
                      {text}
                    </div>
                  ))}
                </div>

                <button
                  className="btn btn-primary"
                  onClick={goNext}
                  style={{ alignSelf: 'flex-start', fontSize: 14, padding: '11px 24px', marginTop: 'auto' }}
                >
                  Get Started →
                </button>
              </div>
            )}

            {/* ════════════════════════════════ STEP 2 — Permissions ═══════════════════════════ */}
            {step === 2 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 18, flex: 1 }}>
                <div>
                  <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)' }}>
                    Verifying Microsoft Graph permissions
                  </div>
                  <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 5 }}>
                    We&apos;re checking your Azure AD / Entra ID consent
                  </div>
                </div>

                {/* Checklist */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <CheckRow
                    ok={postureLoading ? null : postureError ? false : posture ? (posture.health?.graphPermissionsOk ?? false) : null}
                    label="Graph API connected"
                    sub={!postureLoading && posture?.health?.graphPermissionsOk === false ? 'Admin consent required' : undefined}
                  />
                  <CheckRow
                    ok={postureLoading ? null : postureError ? false : posture ? (posture.health?.signInLogsAvailable ?? false) : null}
                    label="Sign-in logs accessible"
                    sub={!postureLoading && posture?.health?.signInLogsAvailable === false ? 'AuditLog.Read.All permission needed' : undefined}
                  />
                  <CheckRow
                    ok={postureLoading ? null : postureError ? false : posture ? privilegedCount(posture) > 0 : null}
                    label="Privileged users found"
                    sub={!postureLoading && posture ? `${privilegedCount(posture)} privileged account${privilegedCount(posture) !== 1 ? 's' : ''} detected` : undefined}
                  />
                  <CheckRow
                    ok={postureLoading ? null : defenderScope ? defenderScope.liveAccessOk : null}
                    label="Defender for Endpoint API"
                    sub={
                      postureLoading ? undefined :
                      defenderScope?.liveAccessOk ? 'Vulnerability data accessible' :
                      defenderScope?.requiresAdminConsent ? 'Admin consent needed — grant below' :
                      defenderScope?.configured === false ? 'Not configured (optional)' :
                      defenderScope?.error ? 'Access check failed' : undefined
                    }
                  />
                </div>

                {/* Defender consent prompt */}
                {!postureLoading && defenderScope?.requiresAdminConsent && !defenderScope?.liveAccessOk && (
                  <div style={{ padding: '12px 14px', borderRadius: 10, background: 'rgba(245,158,11,0.07)', border: '1px solid rgba(245,158,11,0.22)', fontSize: 13 }}>
                    <div style={{ fontWeight: 700, color: '#fbbf24', marginBottom: 4 }}>⚠️ Defender admin consent missing</div>
                    <div style={{ color: 'var(--text-muted)', marginBottom: 10, lineHeight: 1.55 }}>
                      A Global Administrator must grant consent so the app can read CVE vulnerability data from Microsoft Defender for Endpoint.
                      Required roles: <code style={{ background: 'rgba(255,255,255,0.07)', padding: '1px 5px', borderRadius: 3, fontSize: 12 }}>Vulnerability.Read.All</code>, <code style={{ background: 'rgba(255,255,255,0.07)', padding: '1px 5px', borderRadius: 3, fontSize: 12 }}>Machine.Read.All</code>.
                    </div>
                    <a href={defenderScope.adminConsentUrl || '/api/auth/admin-consent'} className="btn btn-secondary" style={{ fontSize: 12, padding: '7px 14px' }}>
                      Grant Defender Consent →
                    </a>
                  </div>
                )}

                {/* Error / warning */}
                {postureError && (
                  <div style={{
                    padding: '10px 14px',
                    borderRadius: 9,
                    background: 'rgba(255,68,85,0.08)',
                    border: '1px solid rgba(255,68,85,0.2)',
                    fontSize: 13,
                    color: 'var(--red-critical)',
                  }}>
                    {postureError}
                  </div>
                )}

                {!postureLoading && !permissionsAllGreen && posture !== null && (
                  <div style={{
                    padding: '12px 14px',
                    borderRadius: 10,
                    background: 'rgba(245,166,35,0.07)',
                    border: '1px solid rgba(245,166,35,0.2)',
                    fontSize: 13,
                    color: 'var(--amber-400)',
                    lineHeight: 1.5,
                  }}>
                    <strong>Action needed:</strong> Grant admin consent in Azure Entra ID then click Re-check.
                    <br />
                    <a
                      href="https://portal.azure.com/#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade"
                      target="_blank"
                      rel="noreferrer"
                      style={{ color: '#F5A462', textDecoration: 'underline', fontSize: 12, marginTop: 4, display: 'inline-block' }}
                    >
                      Open Azure Portal →
                    </a>
                  </div>
                )}

                {/* Actions */}
                <div style={{ display: 'flex', gap: 10, marginTop: 'auto', flexWrap: 'wrap' }}>
                  {(!posture || !permissionsAllGreen) && (
                    <button
                      className="btn btn-ghost"
                      onClick={recheck}
                      disabled={postureLoading}
                      style={{ fontSize: 13 }}
                    >
                      {postureLoading ? <><span className="spin" style={{ marginRight: 6 }}>⟳</span>Checking...</> : '⟳ Re-check'}
                    </button>
                  )}
                  <button
                    className="btn btn-primary"
                    onClick={goNext}
                    disabled={postureLoading}
                    style={{ fontSize: 13 }}
                  >
                    {permissionsAllGreen ? 'Next →' : 'Continue anyway →'}
                  </button>
                </div>
              </div>
            )}

            {/* ════════════════════════════════ STEP 3 — Remediation Service ════════════════ */}
            {step === 3 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 18, flex: 1 }}>
                <div>
                  <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)' }}>
                    🔧 Intune Remediation Service
                  </div>
                  <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 5 }}>
                    Connect the external remediation engine to enable WinGet app deployments and automated CVE patching via Intune.
                  </div>
                </div>

                {onboardingStatus?.webappConsent ? (
                  <div style={{ padding: '14px 16px', borderRadius: 12, background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.2)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <span style={{ fontSize: 20 }}>✅</span>
                      <div>
                        <div style={{ fontWeight: 700, color: '#22c55e', fontSize: 14 }}>Remediation service connected</div>
                        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>Admin consent was granted — WinGet and Windows Update remediations are enabled.</div>
                      </div>
                    </div>
                  </div>
                ) : onboardingStatus?.webappClientId ? (
                  <div style={{ padding: '14px 16px', borderRadius: 12, background: 'rgba(232,120,74,0.07)', border: '1px solid rgba(232,120,74,0.2)' }}>
                    <div style={{ fontWeight: 700, color: '#E8784A', fontSize: 14, marginBottom: 6 }}>⚠️ Admin consent not yet granted</div>
                    <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 12, lineHeight: 1.6 }}>
                      A <strong>Global Administrator</strong> must grant consent for the Intune remediation service.
                      This is a one-time step — click below to open the Microsoft consent page.
                    </div>
                    <a
                      href="/api/auth/webapp-consent-redirect"
                      className="btn btn-primary"
                      style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontSize: 13, padding: '10px 18px' }}
                    >
                      🪟 Grant Remediation Consent
                    </a>
                  </div>
                ) : (
                  <div style={{ padding: '14px 16px', borderRadius: 12, background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)' }}>
                    <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 6 }}>ℹ️ Not configured</div>
                    <div style={{ fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.6 }}>
                      The remediation service (WEBAPP_CLIENT_ID) is not configured on this instance.
                      Identity monitoring and CVE visibility work without it — automated patching requires it.
                    </div>
                  </div>
                )}

                <div style={{ display: 'flex', gap: 8, marginTop: 'auto', flexWrap: 'wrap' }}>
                  <button className="btn btn-secondary btn-sm" onClick={goBack}>← Back</button>
                  <button
                    className="btn btn-primary"
                    onClick={goNext}
                    style={{ marginLeft: 'auto' }}
                  >
                    {webappReady ? 'Continue →' : 'Skip for now →'}
                  </button>
                </div>
              </div>
            )}

            {/* ════════════════════════════════ STEP 4 — Telegram ═════════════════════════════ */}
            {step === 4 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 18, flex: 1 }}>
                <div>
                  <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)' }}>
                    Set up Telegram alerts
                  </div>
                  <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 5 }}>
                    Get instant security alerts with action buttons on your phone
                  </div>
                </div>

                {/* How-to hint */}
                <div style={{
                  padding: '10px 14px',
                  borderRadius: 9,
                  background: 'rgba(155,138,251,0.07)',
                  border: '1px solid rgba(155,138,251,0.18)',
                  fontSize: 12,
                  color: '#C4BCFF',
                  lineHeight: 1.55,
                }}>
                  <strong>Quick setup:</strong> Message <code style={{ background: 'rgba(255,255,255,0.08)', padding: '1px 5px', borderRadius: 4 }}>@BotFather</code> on Telegram to create a bot and get your token. Then message your bot and use <code style={{ background: 'rgba(255,255,255,0.08)', padding: '1px 5px', borderRadius: 4 }}>@userinfobot</code> to get your Chat ID.
                </div>

                {/* Inputs */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                  <div>
                    <label style={labelStyle}>Bot Token</label>
                    <input
                      type="password"
                      className="input"
                      placeholder="110201543:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"
                      value={telegramToken}
                      onChange={e => setTelegramToken(e.target.value)}
                      style={inputStyle}
                      autoComplete="off"
                    />
                  </div>
                  <div>
                    <label style={labelStyle}>Chat ID</label>
                    <input
                      type="text"
                      className="input"
                      placeholder="-100123456789"
                      value={telegramChatId}
                      onChange={e => setTelegramChatId(e.target.value)}
                      style={inputStyle}
                      autoComplete="off"
                    />
                  </div>
                </div>

                {/* Feedback message */}
                {telegramMsg && (
                  <div style={{
                    padding: '10px 14px',
                    borderRadius: 9,
                    background: telegramMsg.ok ? 'rgba(0,201,139,0.08)' : 'rgba(255,68,85,0.08)',
                    border: `1px solid ${telegramMsg.ok ? 'rgba(0,201,139,0.25)' : 'rgba(255,68,85,0.25)'}`,
                    fontSize: 13,
                    color: telegramMsg.ok ? 'var(--green-clean)' : 'var(--red-critical)',
                  }}>
                    {telegramMsg.text}
                  </div>
                )}

                {/* Actions */}
                <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginTop: 'auto', flexWrap: 'wrap' }}>
                  <button
                    className="btn btn-primary"
                    onClick={handleTelegramSaveTest}
                    disabled={telegramSaving || (!telegramToken.trim() || !telegramChatId.trim())}
                    style={{ fontSize: 13 }}
                  >
                    {telegramSaving ? <><span className="spin" style={{ marginRight: 6 }}>⟳</span>Testing...</> : '💬 Save & Test'}
                  </button>

                  {telegramReady && (
                    <button className="btn btn-primary" onClick={goNext} style={{ fontSize: 13 }}>
                      Next →
                    </button>
                  )}

                  <button
                    onClick={() => { setTelegramSkipped(true); goNext(); }}
                    style={{
                      background: 'none',
                      border: 'none',
                      color: 'var(--text-muted)',
                      fontSize: 13,
                      cursor: 'pointer',
                      textDecoration: 'underline',
                      padding: '4px 0',
                      fontFamily: 'var(--font-sans)',
                    }}
                  >
                    Skip for now
                  </button>
                </div>
              </div>
            )}

            {/* ════════════════════════════════ STEP 5 — Admin Email ══════════════════════════ */}
            {step === 5 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 18, flex: 1 }}>
                <div>
                  <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)' }}>
                    Who should receive alerts?
                  </div>
                  <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 5 }}>
                    Add yourself and your team to get notified
                  </div>
                </div>

                {/* Existing admins list */}
                {admins.length > 0 && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 2 }}>
                      Current admins
                    </div>
                    {admins.map((a: any, i) => (
                      <div key={i} style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 10,
                        padding: '8px 12px',
                        borderRadius: 8,
                        background: 'rgba(255,255,255,0.03)',
                        border: '1px solid rgba(255,255,255,0.07)',
                        fontSize: 13,
                      }}>
                        <div style={{
                          width: 28,
                          height: 28,
                          borderRadius: '50%',
                          background: 'linear-gradient(135deg, #E8784A, #F5A462)',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          fontSize: 12,
                          fontWeight: 700,
                          color: 'white',
                          flexShrink: 0,
                        }}>
                          {(a.email || a.name || '?').charAt(0).toUpperCase()}
                        </div>
                        <span style={{ flex: 1, color: 'var(--text-primary)' }}>{a.email}</span>
                        <span style={{
                          padding: '2px 8px',
                          borderRadius: 99,
                          background: 'rgba(255,255,255,0.06)',
                          border: '1px solid rgba(255,255,255,0.1)',
                          fontSize: 10,
                          fontWeight: 700,
                          textTransform: 'uppercase',
                          letterSpacing: '0.5px',
                          color: 'var(--text-muted)',
                        }}>
                          {a.role}
                        </span>
                      </div>
                    ))}
                  </div>
                )}

                {/* Add form */}
                <div style={{
                  padding: '14px 16px',
                  borderRadius: 10,
                  background: 'rgba(255,255,255,0.025)',
                  border: '1px solid rgba(255,255,255,0.07)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 10,
                }}>
                  <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)' }}>Add admin</div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 8 }}>
                    <input
                      type="email"
                      className="input"
                      placeholder="admin@company.com"
                      value={adminEmail}
                      onChange={e => { setAdminEmail(e.target.value); setAdminMsg(null); }}
                      style={inputStyle}
                      onKeyDown={e => { if (e.key === 'Enter') handleAddAdmin(); }}
                      autoComplete="off"
                    />
                    <select
                      className="input"
                      value={adminRole}
                      onChange={e => setAdminRole(e.target.value as any)}
                      style={{ ...inputStyle, width: 'auto', minWidth: 100 }}
                    >
                      <option value="owner">Owner</option>
                      <option value="admin">Admin</option>
                      <option value="analyst">Analyst</option>
                    </select>
                  </div>
                  <button
                    className="btn btn-ghost"
                    onClick={handleAddAdmin}
                    disabled={adminAdding || !adminEmail.trim()}
                    style={{ alignSelf: 'flex-start', fontSize: 12 }}
                  >
                    {adminAdding ? <><span className="spin" style={{ marginRight: 5 }}>⟳</span>Adding...</> : '+ Add'}
                  </button>
                </div>

                {/* Feedback */}
                {adminMsg && (
                  <div style={{
                    padding: '9px 13px',
                    borderRadius: 8,
                    background: adminMsg.ok ? 'rgba(0,201,139,0.08)' : 'rgba(255,68,85,0.08)',
                    border: `1px solid ${adminMsg.ok ? 'rgba(0,201,139,0.2)' : 'rgba(255,68,85,0.2)'}`,
                    fontSize: 13,
                    color: adminMsg.ok ? 'var(--green-clean)' : 'var(--red-critical)',
                  }}>
                    {adminMsg.text}
                  </div>
                )}

                {/* Actions */}
                <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginTop: 'auto', flexWrap: 'wrap' }}>
                  <button
                    className="btn btn-primary"
                    onClick={goNext}
                    disabled={!adminsReady}
                    style={{ fontSize: 13 }}
                  >
                    Next →
                  </button>
                  {!adminSkipped && admins.length === 0 && (
                    <button
                      onClick={() => { setAdminSkipped(true); }}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: 'var(--text-muted)',
                        fontSize: 13,
                        cursor: 'pointer',
                        textDecoration: 'underline',
                        padding: '4px 0',
                        fontFamily: 'var(--font-sans)',
                      }}
                    >
                      Skip
                    </button>
                  )}
                </div>
              </div>
            )}

            {/* ════════════════════════════════ STEP 6 — First Scan ═══════════════════════════ */}
            {step === 6 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 20, flex: 1, alignItems: 'center', textAlign: 'center' }}>
                <div style={{ marginTop: 8 }}>
                  <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)' }}>
                    {scanRunning ? 'Running your first scan...' : scanError ? 'Scan failed' : 'Scan complete!'}
                  </div>
                  <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 5 }}>
                    {scanRunning
                      ? 'Analyzing sign-in logs and privileged accounts...'
                      : scanError
                        ? 'You can retry or proceed to the dashboard.'
                        : 'Your environment has been analyzed.'}
                  </div>
                </div>

                {/* Visual state */}
                {scanRunning && (
                  <div style={{ padding: '24px 0', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16 }}>
                    <div style={{
                      width: 64,
                      height: 64,
                      border: '3px solid rgba(255,255,255,0.07)',
                      borderTopColor: '#E8784A',
                      borderRadius: '50%',
                      animation: 'spin 0.8s linear infinite',
                    }} />
                    <div style={{ fontSize: 12, color: 'var(--text-muted)', letterSpacing: '0.3px' }}>
                      Scanning identity threats...
                    </div>
                  </div>
                )}

                {!scanRunning && !scanError && scanResult !== null && (
                  <div style={{
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    gap: 12,
                    padding: '20px 24px',
                    borderRadius: 14,
                    background: scanResult.newAlerts > 0
                      ? 'rgba(255,68,85,0.07)'
                      : 'rgba(0,201,139,0.07)',
                    border: `1px solid ${scanResult.newAlerts > 0 ? 'rgba(255,68,85,0.2)' : 'rgba(0,201,139,0.2)'}`,
                    width: '100%',
                  }}>
                    <span style={{ fontSize: 40 }}>{scanResult.newAlerts > 0 ? '⚠️' : '✅'}</span>
                    <div style={{
                      fontSize: 15,
                      fontWeight: 700,
                      color: scanResult.newAlerts > 0 ? 'var(--red-critical)' : 'var(--green-clean)',
                      lineHeight: 1.4,
                    }}>
                      {scanResult.newAlerts > 0
                        ? `${scanResult.newAlerts} new alert${scanResult.newAlerts !== 1 ? 's' : ''} detected`
                        : 'No anomalies detected — your environment looks clean'}
                    </div>
                    {scanResult.newAlerts > 0 && (
                      <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                        Review these in the Alerts section after setup.
                      </div>
                    )}
                  </div>
                )}

                {!scanRunning && scanError && (
                  <div style={{
                    padding: '14px 18px',
                    borderRadius: 10,
                    background: 'rgba(255,68,85,0.08)',
                    border: '1px solid rgba(255,68,85,0.2)',
                    fontSize: 13,
                    color: 'var(--red-critical)',
                    width: '100%',
                    textAlign: 'left',
                  }}>
                    {scanError}
                  </div>
                )}

                {/* Success summary */}
                {!scanRunning && !scanError && (
                  <div style={{
                    width: '100%',
                    padding: '12px 16px',
                    borderRadius: 10,
                    background: 'rgba(255,255,255,0.03)',
                    border: '1px solid rgba(255,255,255,0.07)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 8,
                    textAlign: 'left',
                  }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Setup summary</div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                      {[
                        { icon: '🔗', label: 'Microsoft Graph', ok: posture?.health?.graphPermissionsOk !== false },
                        { icon: '📲', label: 'Telegram alerts', ok: telegramTested, skip: telegramSkipped },
                        { icon: '👤', label: 'Admin team', ok: admins.length > 0, skip: adminSkipped },
                        { icon: '⚡', label: 'First scan', ok: true },
                      ].map(({ icon, label, ok, skip }) => (
                        <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text-secondary)' }}>
                          <span>{icon}</span>
                          <span style={{ flex: 1 }}>{label}</span>
                          <span style={{
                            fontSize: 11,
                            fontWeight: 600,
                            color: skip ? 'var(--text-muted)' : ok ? 'var(--green-clean)' : 'var(--amber-400)',
                          }}>
                            {skip ? 'skipped' : ok ? '✓ done' : '⚠ needs attention'}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* CTA */}
                {!scanRunning && (
                  <button
                    className="btn btn-primary"
                    onClick={handleComplete}
                    disabled={completing}
                    style={{ fontSize: 14, padding: '12px 28px', marginTop: 4 }}
                  >
                    {completing
                      ? <><span className="spin" style={{ marginRight: 6 }}>⟳</span>Finishing...</>
                      : 'Go to Dashboard →'}
                  </button>
                )}
              </div>
            )}
          </div>

          {/* ── Footer nav (Back + step dots) ── */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginTop: 28,
            paddingTop: 20,
            borderTop: '1px solid rgba(255,255,255,0.07)',
          }}>
            {/* Back button */}
            <div>
              {step > 1 && step < 5 && (
                <button
                  className="btn btn-ghost btn-sm"
                  onClick={goBack}
                  style={{ fontSize: 12 }}
                >
                  ← Back
                </button>
              )}
            </div>

            {/* Step dots */}
            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              {Array.from({ length: TOTAL_STEPS }, (_, i) => i + 1).map(s => (
                <div
                  key={s}
                  style={{
                    width: s === step ? 20 : 7,
                    height: 7,
                    borderRadius: 99,
                    background: s === step
                      ? 'linear-gradient(90deg, #E8784A, #F5A462)'
                      : s < step
                        ? 'rgba(232,120,74,0.45)'
                        : 'rgba(255,255,255,0.1)',
                    transition: 'all 300ms ease',
                    boxShadow: s === step ? '0 0 8px rgba(232,120,74,0.5)' : 'none',
                  }}
                />
              ))}
            </div>

            {/* Spacer to balance layout */}
            <div style={{ width: 70 }} />
          </div>
        </div>
      </div>

      {/* ── Keyframe injection ── */}
      <style>{`
        @keyframes onboardSlideUp {
          from { opacity: 0; transform: translateY(24px) scale(0.97); }
          to   { opacity: 1; transform: translateY(0)    scale(1); }
        }
      `}</style>
    </>
  );
}
