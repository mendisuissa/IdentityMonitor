import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

interface Props {
  onLogin: (tenantId: string) => void;
}

const PERMISSIONS = [
  { icon: '📋', label: 'AuditLog.Read.All', desc: 'Read sign-in logs' },
  { icon: '👥', label: 'Directory.Read.All', desc: 'List privileged users & roles' },
  { icon: '✉️', label: 'Mail.Send', desc: 'Send alert emails' },
  { icon: '🔑', label: 'RoleManagement.Read', desc: 'Read role assignments' },
  { icon: '👤', label: 'User.Read.All', desc: 'Read user details' }
];

const DEFENDER_REQUIREMENTS = [
  {
    icon: '🛡️',
    label: 'Vulnerability.Read.All',
    desc: 'Read Microsoft Defender vulnerability findings'
  }
];

export default function LoginPage({ onLogin }: Props) {
  const [searchParams] = useSearchParams();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showPerms, setShowPerms] = useState(true);
  const [showDefenderPerms, setShowDefenderPerms] = useState(true);

  useEffect(() => {
    const err = searchParams.get('error');
    if (err) setError(decodeURIComponent(err));
  }, [searchParams]);

  const handleConnect = () => {
    setLoading(true);
    setError('');
    window.location.href = '/api/auth/login';
  };

  const styles: Record<string, React.CSSProperties> = {
    shell: {
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '32px 16px',
      background:
        'radial-gradient(circle at top, rgba(245, 158, 11, 0.08), transparent 28%), linear-gradient(180deg, #02112b 0%, #020b1f 100%)'
    },
    card: {
      width: '100%',
      maxWidth: 560,
      background: 'linear-gradient(180deg, rgba(7,26,58,0.96) 0%, rgba(4,18,43,0.96) 100%)',
      border: '1px solid rgba(59,130,246,0.18)',
      borderRadius: 24,
      boxShadow: '0 20px 60px rgba(0,0,0,0.38)',
      padding: 32,
      color: '#f8fafc'
    },
    logoWrap: {
      display: 'flex',
      justifyContent: 'center',
      marginBottom: 20
    },
    logoBox: {
      width: 76,
      height: 76,
      borderRadius: 18,
      border: '1px solid rgba(245, 158, 11, 0.45)',
      background: 'rgba(245, 158, 11, 0.08)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontSize: 28,
      color: '#f59e0b',
      boxShadow: 'inset 0 0 0 1px rgba(255,255,255,0.03)'
    },
    title: {
      fontSize: 34,
      fontWeight: 800,
      textAlign: 'center',
      margin: 0,
      letterSpacing: '-0.02em'
    },
    subtitle: {
      textAlign: 'center',
      marginTop: 8,
      color: '#7aa2e3',
      fontSize: 13,
      letterSpacing: '0.14em'
    },
    divider: {
      height: 1,
      background: 'linear-gradient(90deg, transparent, rgba(96,165,250,0.35), transparent)',
      margin: '22px 0 24px'
    },
    description: {
      textAlign: 'center',
      color: '#dbeafe',
      fontSize: 18,
      lineHeight: 1.7,
      margin: '0 0 24px'
    },
    panel: {
      background: 'rgba(16, 38, 79, 0.72)',
      border: '1px solid rgba(96,165,250,0.18)',
      borderRadius: 16,
      overflow: 'hidden',
      marginBottom: 16
    },
    panelHeader: {
      width: '100%',
      background: 'rgba(30, 58, 138, 0.22)',
      border: 'none',
      borderBottom: '1px solid rgba(96,165,250,0.12)',
      color: '#dbeafe',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '14px 16px',
      fontSize: 16,
      fontWeight: 700,
      cursor: 'pointer'
    },
    panelBody: {
      padding: 16
    },
    permissionItem: {
      display: 'grid',
      gridTemplateColumns: '28px 1fr',
      gap: 12,
      alignItems: 'start',
      padding: '10px 0'
    },
    permissionIcon: {
      fontSize: 18,
      lineHeight: '24px'
    },
    permissionLabel: {
      fontSize: 20,
      fontWeight: 700,
      color: '#f8fafc'
    },
    permissionDesc: {
      marginTop: 4,
      color: '#9fb6d9',
      fontSize: 15,
      lineHeight: 1.5
    },
    note: {
      marginTop: 14,
      paddingTop: 14,
      borderTop: '1px solid rgba(255,255,255,0.08)',
      color: '#d6e4ff',
      fontSize: 15,
      lineHeight: 1.6
    },
    button: {
      width: '100%',
      marginTop: 24,
      background: '#f8fafc',
      color: '#0f172a',
      border: 'none',
      borderRadius: 16,
      padding: '18px 20px',
      fontSize: 22,
      fontWeight: 700,
      cursor: loading ? 'not-allowed' : 'pointer',
      opacity: loading ? 0.7 : 1,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      gap: 12,
      boxShadow: '0 10px 24px rgba(0,0,0,0.18)'
    },
    error: {
      marginTop: 18,
      padding: 14,
      borderRadius: 14,
      border: '1px solid rgba(248,113,113,0.3)',
      background: 'rgba(127,29,29,0.16)',
      color: '#fecaca',
      fontSize: 14,
      lineHeight: 1.6
    },
    footer: {
      marginTop: 22,
      textAlign: 'center',
      color: '#7aa2e3',
      fontSize: 13,
      lineHeight: 1.8
    }
  };

  return (
    <div style={styles.shell}>
      <div style={styles.card}>
        <div style={styles.logoWrap}>
          <div style={styles.logoBox}>⬡</div>
        </div>

        <h1 style={styles.title}>Privileged Identity Monitor</h1>
        <div style={styles.subtitle}>MODERN ENDPOINT · SECURITY OPERATIONS</div>

        <div style={styles.divider} />

        <p style={styles.description}>
          Connect your Microsoft Entra ID tenant to monitor privileged user sign-in activity
          and detect anomalies in real time.
        </p>

        <div style={styles.panel}>
          <button
            type="button"
            style={styles.panelHeader}
            onClick={() => setShowPerms((p) => !p)}
          >
            <span>🔐 Required permissions</span>
            <span>{showPerms ? 'hide ▲' : 'show ▼'}</span>
          </button>

          {showPerms && (
            <div style={styles.panelBody}>
              {PERMISSIONS.map((p) => (
                <div key={p.label} style={styles.permissionItem}>
                  <div style={styles.permissionIcon}>{p.icon}</div>
                  <div>
                    <div style={styles.permissionLabel}>{p.label}</div>
                    <div style={styles.permissionDesc}>{p.desc}</div>
                  </div>
                </div>
              ))}

              <div style={styles.note}>
                ⚠️ Requires <strong>Global Administrator</strong> or{' '}
                <strong>Privileged Role Administrator</strong> to consent.
              </div>
            </div>
          )}
        </div>

        <div style={styles.panel}>
          <button
            type="button"
            style={styles.panelHeader}
            onClick={() => setShowDefenderPerms((p) => !p)}
          >
            <span>🛡 Defender Vulnerability Integration</span>
            <span>{showDefenderPerms ? 'hide ▲' : 'show ▼'}</span>
          </button>

          {showDefenderPerms && (
            <div style={styles.panelBody}>
              {DEFENDER_REQUIREMENTS.map((p) => (
                <div key={p.label} style={styles.permissionItem}>
                  <div style={styles.permissionIcon}>{p.icon}</div>
                  <div>
                    <div style={styles.permissionLabel}>{p.label}</div>
                    <div style={styles.permissionDesc}>{p.desc}</div>
                  </div>
                </div>
              ))}

              <div style={styles.note}>
                Optional advanced module for live Defender vulnerability ingestion.
              </div>

              <div style={{ ...styles.note, marginTop: 10 }}>
                Requires <strong>WindowsDefenderATP</strong> application permission and admin consent.
              </div>

              <div style={{ ...styles.note, marginTop: 10 }}>
                Requires <strong>Microsoft Defender Vulnerability Management</strong> or eligible TVM entitlement.
              </div>
            </div>
          )}
        </div>

        <button style={styles.button} onClick={handleConnect} disabled={loading}>
          <span style={{ fontSize: 24 }}>🪟</span>
          <span>{loading ? 'Redirecting to Microsoft...' : 'Connect with Microsoft'}</span>
        </button>

        {error ? (
          <div style={styles.error}>
            <strong>Authentication failed:</strong>
            <div>{error}</div>
          </div>
        ) : null}

        <div style={styles.footer}>
          <div>One-time admin consent per tenant</div>
          <div>Your credentials are never stored — session expires after 24 hours of inactivity</div>
        </div>
      </div>
    </div>
  );
}