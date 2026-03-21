import React, { useState } from 'react';

type TestResult = {
  success: boolean;
  message?: string;
  error?: string;
  hint?: string;
  recipient?: string;
  sender?: string;
  sentAt?: string;
  chatId?: string;
};

function ResultBox({ result }: { result: TestResult }) {
  const color = result.success ? '#2ecc71' : 'var(--red-critical)';
  const bg    = result.success ? 'rgba(46,204,113,0.08)' : 'rgba(255,59,59,0.08)';
  const border= result.success ? 'rgba(46,204,113,0.3)' : 'rgba(255,59,59,0.3)';

  return (
    <div style={{ padding: '14px 16px', borderRadius: 'var(--radius-md)', border: `1px solid ${border}`, background: bg, marginTop: 12 }}>
      {result.success ? (
        <>
          <div style={{ color: '#2ecc71', fontWeight: 700, marginBottom: 8 }}>✅ {result.message}</div>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: 3 }}>
            {result.recipient && <div><span style={{ color: 'var(--text-muted)' }}>To:</span> {result.recipient}</div>}
            {result.sender    && <div><span style={{ color: 'var(--text-muted)' }}>From:</span> {result.sender}</div>}
            {result.chatId    && <div><span style={{ color: 'var(--text-muted)' }}>Chat ID:</span> {result.chatId}</div>}
            {result.sentAt    && <div><span style={{ color: 'var(--text-muted)' }}>Sent:</span> {new Date(result.sentAt).toLocaleString()}</div>}
          </div>
        </>
      ) : (
        <>
          <div style={{ color: 'var(--red-critical)', fontWeight: 700, marginBottom: 6 }}>❌ {result.error}</div>
          {result.hint && (
            <div style={{ fontSize: 11, color: 'var(--text-muted)', background: 'rgba(0,0,0,0.2)', padding: '8px 10px', borderRadius: 4, fontFamily: 'var(--font-mono)', marginTop: 6 }}>
              💡 {result.hint}
            </div>
          )}
        </>
      )}
    </div>
  );
}

export default function TestMailPanel() {
  const [emailTo, setEmailTo] = useState('');
  const [emailLoading, setEmailLoading] = useState(false);
  const [emailResult, setEmailResult] = useState<TestResult | null>(null);

  const [telegramLoading, setTelegramLoading] = useState(false);
  const [telegramResult, setTelegramResult] = useState<TestResult | null>(null);

  const testEmail = async () => {
    setEmailLoading(true);
    setEmailResult(null);
    try {
      const res  = await fetch('/api/mock/test-mail', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ to: emailTo.trim() || undefined })
      });
      setEmailResult(await res.json());
    } catch (err: any) {
      setEmailResult({ success: false, error: 'Request failed: ' + err.message });
    } finally { setEmailLoading(false); }
  };

  const testTelegram = async () => {
    setTelegramLoading(true);
    setTelegramResult(null);
    try {
      const res  = await fetch('/api/mock/test-telegram', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include'
      });
      setTelegramResult(await res.json());
    } catch (err: any) {
      setTelegramResult({ success: false, error: 'Request failed: ' + err.message });
    } finally { setTelegramLoading(false); }
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 20 }}>

      {/* ── Email Test ──────────────────────────────────────────────────── */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">📧 Test Email Alert</div>
        </div>
        <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 16, lineHeight: 1.6 }}>
          Send a test alert email via Graph API to verify <span className="mono" style={{ color: 'var(--amber-400)', fontSize: 11 }}>Mail.Send</span> is working.
        </p>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <input
            className="filter-input"
            style={{ flex: 1, minWidth: 160 }}
            placeholder="Recipient (default: ALERT_ADMIN_EMAIL)"
            value={emailTo}
            onChange={e => setEmailTo(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && testEmail()}
            type="email"
          />
          <button className="btn btn-primary" onClick={testEmail} disabled={emailLoading} style={{ flexShrink: 0 }}>
            {emailLoading ? <><span className="spin">⟳</span> Sending...</> : '📤 Send Test'}
          </button>
        </div>
        {emailResult && <ResultBox result={emailResult} />}
        <div style={{ marginTop: 12, fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.6 }}>
          Requires: <span className="mono" style={{ color: 'var(--amber-400)' }}>ALERT_SENDER_EMAIL</span> · <span className="mono" style={{ color: 'var(--amber-400)' }}>ALERT_ADMIN_EMAIL</span> · <span className="mono" style={{ color: 'var(--amber-400)' }}>Mail.Send</span> permission
        </div>
      </div>

      {/* ── Telegram Test ───────────────────────────────────────────────── */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">🤖 Test Telegram Bot</div>
        </div>
        <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 16, lineHeight: 1.6 }}>
          Send a realistic mock alert to Telegram with interactive action buttons to verify bot integration.
        </p>
        <button className="btn btn-primary" onClick={testTelegram} disabled={telegramLoading} style={{ width: '100%', justifyContent: 'center' }}>
          {telegramLoading ? <><span className="spin">⟳</span> Sending...</> : '📲 Send Test Alert to Telegram'}
        </button>
        {telegramResult && <ResultBox result={telegramResult} />}
        <div style={{ marginTop: 12, fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.6 }}>
          Requires: <span className="mono" style={{ color: 'var(--amber-400)' }}>TELEGRAM_BOT_TOKEN</span> · <span className="mono" style={{ color: 'var(--amber-400)' }}>TELEGRAM_CHAT_ID</span>
        </div>
      </div>

    </div>
  );
}
