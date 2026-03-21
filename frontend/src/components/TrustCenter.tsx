import React, { useEffect, useState, useCallback } from 'react';

export default function TrustCenter() {
  const [health, setHealth]       = useState<any>(null);
  const [posture, setPosture]     = useState<any>(null);
  const [loading, setLoading]     = useState(true);
  const [checking, setChecking]   = useState(false);
  const [actionState, setActionState] = useState<Record<string, 'loading' | 'ok' | 'error'>>({});
  const [actionMsg, setActionMsg] = useState<Record<string, string>>({});

  const load = useCallback(async () => {
    try {
      const [h, p] = await Promise.all([
        fetch('/api/health',  { credentials: 'include' }).then(r => r.json()),
        fetch('/api/posture', { credentials: 'include' }).then(r => r.json())
      ]);
      setHealth(h);
      setPosture(p);
    } catch (e) {}
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, []);

  const tenant = posture?.tenant || {};
  const th     = tenant.health  || {};
  const notif  = (posture?.settings || posture?.tenant?.notifications) || {};

  // Read telegram config from settings endpoint
  const [settings, setSettings] = useState<any>(null);
  useEffect(() => {
    fetch('/api/settings', { credentials: 'include' })
      .then(r => r.json()).then(s => setSettings(s)).catch(() => {});
  }, []);

  const telegramConfigured = !!(
    settings?.notifications?.telegramBotToken &&
    settings?.notifications?.telegramChatId
  );

  const runAction = async (key: string, fn: () => Promise<any>) => {
    setActionState(p => ({ ...p, [key]: 'loading' }));
    setActionMsg(p => ({ ...p, [key]: '' }));
    try {
      const result = await fn();
      setActionState(p => ({ ...p, [key]: 'ok' }));
      setActionMsg(p => ({ ...p, [key]: result?.message || result?.msg || 'Done' }));
      // Reload health after action
      setTimeout(load, 2000);
    } catch (err: any) {
      setActionState(p => ({ ...p, [key]: 'error' }));
      setActionMsg(p => ({ ...p, [key]: err.message || 'Failed' }));
    }
  };

  const runScan = () => runAction('scan', async () => {
    const res = await fetch('/api/alerts/scan', { method: 'POST', credentials: 'include' });
    const d   = await res.json();
    if (!res.ok) throw new Error(d.error || 'Scan failed');
    return { message: `Scan complete — ${d.newAlerts} new alert${d.newAlerts !== 1 ? 's' : ''} detected` };
  });

  const testEmail = () => runAction('email', async () => {
    const res = await fetch('/api/mock/test-mail', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    const d = await res.json();
    if (!d.success) throw new Error(d.error || 'Email failed');
    return { message: 'Test email sent to ' + (d.recipient || 'admin') };
  });

  const testTelegram = () => runAction('telegram', async () => {
    const res = await fetch('/api/mock/test-telegram', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' }
    });
    const d = await res.json();
    if (!d.success) throw new Error(d.error || 'Telegram failed');
    return { message: 'Test message sent to Telegram!' };
  });

  const refreshHealth = async () => {
    setChecking(true);
    try {
      // Trigger a health check
      await fetch('/api/alerts/scan', { method: 'POST', credentials: 'include' });
      await load();
    } finally {
      setChecking(false);
    }
  };

  interface Item {
    key: string;
    label: string;
    status: 'ok' | 'warn' | 'error' | 'unknown';
    detail: string;
    actionLabel?: string;
    onAction?: () => void;
    actionHref?: string;
  }

  const items: Item[] = [
    {
      key: 'graph',
      label: 'Graph API Connection',
      status: th.graphPermissionsOk === true ? 'ok' : th.graphPermissionsOk === false ? 'error' : 'unknown',
      detail: th.graphPermissionsOk === true
        ? `Connected · ${th.privilegedUserCount || 0} privileged accounts monitored`
        : th.graphPermissionsOk === false
        ? 'Permission denied — re-consent required'
        : 'Not yet checked — run a scan to verify',
      actionLabel: th.graphPermissionsOk === false ? 'Re-authenticate' : undefined,
      actionHref: th.graphPermissionsOk === false ? '/api/auth/login' : undefined
    },
    {
      key: 'signins',
      label: 'Sign-in Logs Access',
      status: th.signInLogsAvailable === true ? 'ok' : th.signInLogsAvailable === false ? 'warn' : 'unknown',
      detail: th.signInLogsAvailable === true
        ? 'AuditLog.Read.All confirmed — sign-in logs accessible'
        : th.signInLogsAvailable === false
        ? 'Unavailable — requires Entra ID P1/P2 license'
        : 'Not yet verified — run a scan to check',
      actionLabel: th.signInLogsAvailable === false ? 'Check License ↗' : undefined,
      actionHref: 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Licenses'
    },
    {
      key: 'webhook',
      label: 'Real-Time Webhooks',
      status: th.webhookActive ? 'ok' : 'warn',
      detail: th.webhookActive
        ? `Active · Expires ${th.webhookExpiresAt ? new Date(th.webhookExpiresAt).toLocaleDateString() : 'unknown'}`
        : 'Not active — using 15-min polling fallback. Add WEBHOOK_NOTIFICATION_URL to App Service config.',
      actionLabel: !th.webhookActive ? 'How to configure ↗' : undefined,
      actionHref: 'https://docs.microsoft.com/en-us/graph/webhooks'
    },
    {
      key: 'email',
      label: 'Email Alert Delivery',
      status: th.mailDeliveryOk === true ? 'ok'
        : actionState['email'] === 'ok' ? 'ok'
        : actionState['email'] === 'error' ? 'error'
        : 'unknown',
      detail: actionMsg['email'] || (th.mailDeliveryOk === true
        ? 'Last test email delivered successfully'
        : 'Not yet tested — click Send Test to verify'),
      actionLabel: actionState['email'] === 'loading' ? '⟳ Sending...' : 'Send Test Email',
      onAction: actionState['email'] !== 'loading' ? testEmail : undefined
    },
    {
      key: 'telegram',
      label: 'Telegram Bot',
      status: telegramConfigured
        ? (actionState['telegram'] === 'ok' ? 'ok' : actionState['telegram'] === 'error' ? 'error' : 'warn')
        : 'unknown',
      detail: actionMsg['telegram'] || (telegramConfigured
        ? 'Configured — click Send Test to verify delivery'
        : 'Not configured — go to Settings → Telegram to set up'),
      actionLabel: telegramConfigured
        ? (actionState['telegram'] === 'loading' ? '⟳ Sending...' : 'Send Test')
        : 'Configure →',
      onAction: telegramConfigured && actionState['telegram'] !== 'loading' ? testTelegram : undefined,
      actionHref: !telegramConfigured ? '/settings' : undefined
    },
    {
      key: 'scan',
      label: 'Last Successful Scan',
      status: th.lastSuccessfulScan ? 'ok'
        : actionState['scan'] === 'ok' ? 'ok'
        : actionState['scan'] === 'error' ? 'error'
        : 'warn',
      detail: actionMsg['scan'] || (th.lastSuccessfulScan
        ? `Last scan: ${new Date(th.lastSuccessfulScan).toLocaleString()} · ${th.lastScanAlertCount || 0} new alerts found`
        : 'No scan completed yet'),
      actionLabel: actionState['scan'] === 'loading' ? '⟳ Scanning...' : 'Run Scan Now',
      onAction: actionState['scan'] !== 'loading' ? runScan : undefined
    },
    {
      key: 'baseline',
      label: 'Behavioral Baseline',
      status: th.baselineBuilt ? 'ok' : 'warn',
      detail: th.baselineBuilt
        ? 'User baselines established — detection accuracy at full capacity'
        : 'Baseline building — improves after first few scans'
    },
    {
      key: 'storage',
      label: 'Data Storage Mode',
      status: health?.features?.tableStorage ? 'ok' : 'warn',
      detail: health?.features?.tableStorage
        ? 'Azure Table Storage — data persists across restarts'
        : 'In-memory only — data resets on restart. Set AZURE_STORAGE_CONNECTION_STRING for production.',
      actionLabel: !health?.features?.tableStorage ? 'Azure Docs ↗' : undefined,
      actionHref: 'https://portal.azure.com'
    }
  ];

  const sc = {
    ok:      { color: '#2ecc71', bg: 'rgba(46,204,113,0.12)',  border: 'rgba(46,204,113,0.3)',  icon: '✓' },
    warn:    { color: '#f5a623', bg: 'rgba(245,166,35,0.1)',   border: 'rgba(245,166,35,0.3)',  icon: '⚠' },
    error:   { color: '#ff3b3b', bg: 'rgba(255,59,59,0.1)',    border: 'rgba(255,59,59,0.3)',   icon: '✗' },
    unknown: { color: '#4a6490', bg: 'rgba(74,100,144,0.08)',  border: 'rgba(74,100,144,0.2)', icon: '?' }
  };

  const okCount  = items.filter(i => i.status === 'ok').length;
  const warnCount = items.filter(i => i.status === 'warn').length;
  const errCount  = items.filter(i => i.status === 'error').length;

  if (loading) return <div className="loading-state"><div className="loading-spinner" /><div className="loading-text">Loading health status...</div></div>;

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Operational Health</div>
          <div className="page-subtitle">System status · integration health · data freshness</div>
        </div>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <span style={{ fontSize: 12, color: '#2ecc71' }}>✓ {okCount}</span>
          {warnCount > 0 && <span style={{ fontSize: 12, color: '#f5a623' }}>⚠ {warnCount}</span>}
          {errCount > 0  && <span style={{ fontSize: 12, color: '#ff3b3b' }}>✗ {errCount}</span>}
          <button className="btn btn-ghost btn-sm" onClick={refreshHealth} disabled={checking}>
            {checking ? <><span className="spin">⟳</span> Checking...</> : '⟳ Refresh'}
          </button>
        </div>
      </div>

      {/* Health bar */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', height: 8, borderRadius: 4, overflow: 'hidden', marginBottom: 10 }}>
          <div style={{ flex: okCount,   background: '#2ecc71' }} />
          <div style={{ flex: warnCount, background: '#f5a623' }} />
          <div style={{ flex: errCount,  background: '#ff3b3b' }} />
          <div style={{ flex: items.filter(i => i.status === 'unknown').length, background: 'var(--navy-700)' }} />
        </div>
        <div style={{ display: 'flex', gap: 20, fontSize: 12, color: 'var(--text-muted)', flexWrap: 'wrap' }}>
          <span>Mode: <strong style={{ color: health?.mockMode ? '#f5a623' : '#2ecc71' }}>{health?.mockMode ? 'MOCK' : 'LIVE'}</strong></span>
          <span>Active tenants: <strong style={{ color: 'var(--text-primary)' }}>{health?.activeTenants ?? 1}</strong></span>
          <span>Privileged accounts: <strong style={{ color: 'var(--amber-500)' }}>{th.privilegedUserCount ?? '—'}</strong></span>
          <span>Last check: <strong style={{ color: 'var(--text-primary)' }}>{new Date().toLocaleTimeString()}</strong></span>
        </div>
      </div>

      {/* Items */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {items.map(item => {
          const s = sc[item.status];
          const isActing = actionState[item.key] === 'loading';
          return (
            <div key={item.key} className="card" style={{
              padding: '14px 18px', display: 'flex', alignItems: 'center',
              gap: 16, flexWrap: 'wrap',
              borderLeft: item.status !== 'unknown' ? `3px solid ${s.color}` : '3px solid var(--navy-border)'
            }}>
              <div style={{
                width: 32, height: 32, borderRadius: '50%', flexShrink: 0,
                background: s.bg, border: `1px solid ${s.border}`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                color: s.color, fontWeight: 700, fontSize: 14
              }}>
                {isActing ? <span className="spin" style={{ fontSize: 16 }}>⟳</span> : s.icon}
              </div>

              <div style={{ flex: 1, minWidth: 200 }}>
                <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 2 }}>{item.label}</div>
                <div style={{ fontSize: 12, color: actionState[item.key] === 'ok' ? '#2ecc71' : actionState[item.key] === 'error' ? '#ff3b3b' : 'var(--text-muted)', lineHeight: 1.5 }}>
                  {item.detail}
                </div>
              </div>

              {item.actionLabel && (
                item.actionHref ? (
                  <a href={item.actionHref} target={item.actionHref.startsWith('http') ? '_blank' : undefined}
                    className="btn btn-ghost btn-sm" style={{ flexShrink: 0 }}>
                    {item.actionLabel}
                  </a>
                ) : item.onAction ? (
                  <button className="btn btn-ghost btn-sm" style={{ flexShrink: 0 }}
                    disabled={isActing} onClick={item.onAction}>
                    {item.actionLabel}
                  </button>
                ) : null
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
