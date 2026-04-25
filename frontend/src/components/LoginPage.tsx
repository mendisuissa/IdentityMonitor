import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

interface Props {
  onLogin: (tenantId: string) => void;
}

// What the app reads — friendly language, not raw API scope names
const WHAT_WE_READ = [
  { icon: '🔍', label: 'Sign-in history', desc: 'Detect impossible travel, new countries, unusual hours' },
  { icon: '👥', label: 'Privileged accounts', desc: 'Global Admins, Role Admins, Intune Admins and similar' },
  { icon: '🔑', label: 'Role assignments', desc: 'Who has what privilege — permanent or just-in-time' },
  { icon: '📋', label: 'Audit events', desc: 'Role changes, consent grants, policy modifications' },
  { icon: '✉️', label: 'Alert emails', desc: 'Send notifications when threats are detected' },
];

export default function LoginPage({ onLogin }: Props) {
  const [searchParams] = useSearchParams();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showDetails, setShowDetails] = useState(false);

  useEffect(() => {
    const err = searchParams.get('error');
    if (err) setError(decodeURIComponent(err));
  }, [searchParams]);

  const handleConnect = () => {
    setLoading(true);
    setError('');
    window.location.href = '/api/auth/login';
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '32px 16px',
      background: 'radial-gradient(ellipse at 50% 0%, rgba(232,120,74,0.07) 0%, transparent 60%), #0C0C11',
    }}>
      <div style={{
        width: '100%',
        maxWidth: 480,
        background: '#14141B',
        border: '1px solid rgba(232,120,74,0.2)',
        borderRadius: 24,
        boxShadow: '0 24px 64px rgba(0,0,0,0.5)',
        padding: '36px 32px',
        color: '#f1f1f3',
      }}>

        {/* Logo */}
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 24 }}>
          <img src="/logo.svg" alt="IdentityMonitor" style={{ width: 72, height: 72, filter: 'drop-shadow(0 0 14px rgba(232,120,74,0.45))' }} />
        </div>

        {/* Title */}
        <h1 style={{ fontSize: 26, fontWeight: 800, textAlign: 'center', margin: '0 0 6px', letterSpacing: '-0.02em' }}>
          IdentityMonitor
        </h1>
        <div style={{ textAlign: 'center', color: 'rgba(241,241,243,0.45)', fontSize: 12, letterSpacing: '0.12em', marginBottom: 28 }}>
          PRIVILEGED IDENTITY · SECURITY OPERATIONS
        </div>

        {/* Value prop */}
        <div style={{
          background: 'rgba(232,120,74,0.06)',
          border: '1px solid rgba(232,120,74,0.15)',
          borderRadius: 14,
          padding: '16px 18px',
          marginBottom: 24,
          fontSize: 14,
          color: 'rgba(241,241,243,0.75)',
          lineHeight: 1.7,
          textAlign: 'center',
        }}>
          Connects to your Microsoft Entra ID tenant and monitors privileged accounts in real time —
          detecting anomalies, impossible travel, and unauthorized role changes.
        </div>

        {/* CTA button */}
        <button
          onClick={handleConnect}
          disabled={loading}
          style={{
            width: '100%',
            padding: '16px 20px',
            background: loading ? 'rgba(232,120,74,0.5)' : '#E8784A',
            color: '#fff',
            border: 'none',
            borderRadius: 14,
            fontSize: 16,
            fontWeight: 700,
            cursor: loading ? 'not-allowed' : 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 10,
            boxShadow: loading ? 'none' : '0 4px 20px rgba(232,120,74,0.35)',
            transition: 'all 0.15s',
            marginBottom: 16,
          }}
        >
          <span style={{ fontSize: 18 }}>🪟</span>
          <span>{loading ? 'Redirecting to Microsoft…' : 'Connect with Microsoft'}</span>
        </button>

        {/* Error */}
        {error && (
          <div style={{
            padding: '12px 16px',
            borderRadius: 12,
            background: 'rgba(239,68,68,0.1)',
            border: '1px solid rgba(239,68,68,0.3)',
            color: '#FCA5A5',
            fontSize: 13,
            lineHeight: 1.6,
            marginBottom: 16,
          }}>
            <strong>Sign-in failed:</strong> {error}
          </div>
        )}

        {/* What we access — collapsed by default */}
        <button
          onClick={() => setShowDetails(d => !d)}
          style={{
            width: '100%',
            background: 'none',
            border: '1px solid rgba(255,255,255,0.08)',
            borderRadius: 10,
            color: 'rgba(241,241,243,0.5)',
            fontSize: 12,
            padding: '10px 14px',
            cursor: 'pointer',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: showDetails ? 0 : 0,
          }}
        >
          <span>What data does this app access?</span>
          <span style={{ fontSize: 10 }}>{showDetails ? '▲ hide' : '▼ show'}</span>
        </button>

        {showDetails && (
          <div style={{
            border: '1px solid rgba(255,255,255,0.08)',
            borderTop: 'none',
            borderRadius: '0 0 10px 10px',
            padding: '4px 14px 14px',
            marginBottom: 0,
          }}>
            {WHAT_WE_READ.map(item => (
              <div key={item.label} style={{
                display: 'flex', gap: 12, padding: '10px 0',
                borderBottom: '1px solid rgba(255,255,255,0.05)',
              }}>
                <span style={{ fontSize: 16, marginTop: 1, flexShrink: 0 }}>{item.icon}</span>
                <div>
                  <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 2 }}>{item.label}</div>
                  <div style={{ color: 'rgba(241,241,243,0.5)', fontSize: 12, lineHeight: 1.5 }}>{item.desc}</div>
                </div>
              </div>
            ))}
            <div style={{
              marginTop: 12, fontSize: 12, color: 'rgba(241,241,243,0.4)', lineHeight: 1.6,
              paddingTop: 10, borderTop: '1px solid rgba(255,255,255,0.05)',
            }}>
              ℹ️ First-time setup requires a <strong style={{ color: 'rgba(241,241,243,0.7)' }}>Global Administrator</strong> to approve access.
              Subsequent logins are one click — no re-approval needed.
            </div>
          </div>
        )}

        {/* Footer */}
        <div style={{
          marginTop: 20,
          textAlign: 'center',
          color: 'rgba(241,241,243,0.3)',
          fontSize: 11,
          lineHeight: 1.8,
        }}>
          <div>Your credentials are never stored · Read-only access to Entra ID</div>
          <div>Session stays active while the app is in use</div>
        </div>
      </div>
    </div>
  );
}
