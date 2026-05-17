import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';

interface Props {
  webappConnected: boolean;
  onClose: () => void;
}

const STEP_DELAY_MS = 350;

export default function WelcomeModal({ webappConnected, onClose }: Props) {
  const navigate = useNavigate();
  const [status, setStatus] = useState<any>(null);
  const [visibleSteps, setVisibleSteps] = useState(0);

  useEffect(() => {
    api.getOnboardingStatus().then(setStatus).catch(() => {});
  }, []);

  const steps = [
    { icon: '🔐', label: 'Microsoft Entra ID connected',      done: true },
    { icon: '🛡️', label: 'Defender TVM access granted',        done: true },
    { icon: '🔧', label: 'Intune remediation service linked',  done: webappConnected || !!status?.webappConsent },
    { icon: '🤖', label: 'Auto-remediation engine ready',      done: !!status?.autoRemediation },
    { icon: '📣', label: 'Telegram notifications',             done: !!status?.telegramEnabled },
  ];

  // Animate steps appearing one by one
  useEffect(() => {
    if (visibleSteps >= steps.length) return;
    const t = setTimeout(() => setVisibleSteps(s => s + 1), STEP_DELAY_MS);
    return () => clearTimeout(t);
  }, [visibleSteps, steps.length]);

  const allConnected = steps.filter(s => s.done).length;
  const needsWebapp  = !webappConnected && !status?.webappConsent && !!status?.webappClientId;
  const needsTelegram = !status?.telegramEnabled;

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      background: 'rgba(0,0,0,0.85)',
      backdropFilter: 'blur(8px)',
      zIndex: 2000,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '20px 16px',
    }}>
      <div style={{
        width: '100%',
        maxWidth: 500,
        background: '#1A1A24',
        border: '1px solid rgba(232,120,74,0.25)',
        borderRadius: 24,
        boxShadow: '0 32px 80px rgba(0,0,0,0.6)',
        padding: '36px 32px',
        color: '#f1f1f3',
      }}>
        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: 28 }}>
          <div style={{ fontSize: 48, marginBottom: 12, lineHeight: 1 }}>🎉</div>
          <h2 style={{ margin: '0 0 6px', fontSize: 24, fontWeight: 800, letterSpacing: '-0.02em' }}>
            You're connected!
          </h2>
          <div style={{ fontSize: 14, color: 'rgba(241,241,243,0.5)', lineHeight: 1.6 }}>
            IdentityMonitor is set up and ready to protect your tenant.
            {allConnected > 0 && ` ${allConnected} of ${steps.length} services active.`}
          </div>
        </div>

        {/* Steps */}
        <div style={{
          background: 'rgba(255,255,255,0.03)',
          border: '1px solid rgba(255,255,255,0.06)',
          borderRadius: 14,
          overflow: 'hidden',
          marginBottom: 24,
        }}>
          {steps.map((s, i) => (
            <div
              key={i}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 14,
                padding: '12px 16px',
                borderBottom: i < steps.length - 1 ? '1px solid rgba(255,255,255,0.05)' : 'none',
                opacity: i < visibleSteps ? 1 : 0,
                transform: i < visibleSteps ? 'translateY(0)' : 'translateY(6px)',
                transition: 'opacity 0.35s ease, transform 0.35s ease',
              }}
            >
              <span style={{ fontSize: 18, width: 24, textAlign: 'center', flexShrink: 0 }}>
                {s.done ? '✅' : '⚠️'}
              </span>
              <div style={{ flex: 1 }}>
                <div style={{
                  fontSize: 13,
                  fontWeight: 600,
                  color: s.done ? '#f1f1f3' : 'rgba(241,241,243,0.45)',
                }}>
                  {s.label}
                </div>
                {!s.done && (
                  <div style={{ fontSize: 11, color: 'rgba(232,120,74,0.7)', marginTop: 2 }}>
                    Not configured — set up in Settings
                  </div>
                )}
              </div>
              <span style={{
                fontSize: 11,
                fontWeight: 700,
                padding: '3px 8px',
                borderRadius: 99,
                background: s.done ? 'rgba(34,197,94,0.12)' : 'rgba(232,120,74,0.1)',
                color: s.done ? '#22c55e' : 'rgba(232,120,74,0.7)',
                whiteSpace: 'nowrap',
              }}>
                {s.done ? 'Active' : 'Pending'}
              </span>
            </div>
          ))}
        </div>

        {/* Pending actions */}
        {(needsWebapp || needsTelegram) && (
          <div style={{
            padding: '12px 16px',
            borderRadius: 10,
            background: 'rgba(232,120,74,0.07)',
            border: '1px solid rgba(232,120,74,0.18)',
            marginBottom: 20,
            fontSize: 13,
            color: 'rgba(241,241,243,0.65)',
            lineHeight: 1.6,
          }}>
            <strong style={{ color: '#E8784A' }}>Optional next steps:</strong>
            {needsWebapp && (
              <div style={{ marginTop: 6 }}>
                🔧 <strong>Intune remediation</strong> — the admin needs to grant consent for the
                remediation service. Go to Settings → Remediation Service to connect.
              </div>
            )}
            {needsTelegram && (
              <div style={{ marginTop: 6 }}>
                📣 <strong>Telegram alerts</strong> — configure your bot token in Settings → Notifications
                to receive real-time CVE and threat alerts.
              </div>
            )}
          </div>
        )}

        {/* CTA buttons */}
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          <button
            style={{
              flex: 1,
              padding: '13px 18px',
              background: '#E8784A',
              color: '#fff',
              border: 'none',
              borderRadius: 12,
              fontSize: 14,
              fontWeight: 700,
              cursor: 'pointer',
              boxShadow: '0 4px 16px rgba(232,120,74,0.3)',
            }}
            onClick={() => { onClose(); navigate('/remediation'); }}
          >
            🛡️ Go to Remediation
          </button>
          <button
            style={{
              flex: 1,
              padding: '13px 18px',
              background: 'rgba(255,255,255,0.06)',
              color: 'rgba(241,241,243,0.7)',
              border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: 12,
              fontSize: 14,
              fontWeight: 600,
              cursor: 'pointer',
            }}
            onClick={() => { onClose(); navigate('/'); }}
          >
            Dashboard
          </button>
        </div>

        {/* Dismiss */}
        <div style={{ textAlign: 'center', marginTop: 14 }}>
          <button
            style={{ background: 'none', border: 'none', color: 'rgba(241,241,243,0.3)', fontSize: 12, cursor: 'pointer' }}
            onClick={onClose}
          >
            Dismiss
          </button>
        </div>
      </div>
    </div>
  );
}
