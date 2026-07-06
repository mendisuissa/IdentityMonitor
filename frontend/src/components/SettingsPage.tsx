import React, { useEffect, useMemo, useState } from 'react';
import { api } from '../services/api';

type Severity = 'critical' | 'high' | 'medium' | 'low';
type Tab = 'trial' | 'detection' | 'actions' | 'admins' | 'notifications' | 'automation' | 'whitelist' | 'siem' | 'audit' | 'hours' | 'playbooks';

const DAYS = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
const DEFAULT_HOURS = DAYS.map((day, i) => ({ day, enabled: i >= 1 && i <= 5, start: '08:00', end: '18:00' }));

type SiemSettings = {
  logAnalytics?: { enabled?: boolean; workspaceId?: string; sharedKey?: string };
  webhooks?: Array<{ name?: string; url?: string; enabled?: boolean }>;
};

interface SettingsShape {
  billing?: { trialEndsAt?: string };
  trialStatus?: { status: string; daysLeft: number | null };
  admins?: { email: string; name?: string; role: string; telegramChatId?: string; addedAt: string }[];
  notifications?: { adminEmails?: string[]; emailOnSeverity?: string[]; telegramBotToken?: string; telegramChatId?: string; telegramOnSeverity?: string[]; userNotify?: boolean; };
  detectionRules?: Record<string, { enabled: boolean; severity: string }>;
  autoActions?: Record<string, { revokeSession: boolean; disableUser: boolean; telegramPlaybook: boolean }>;
  whitelist?: { ips: string[]; countries: string[]; devices: string[]; users: string[] };
  approvalPolicies?: Record<Severity, string[]>;
  assignmentRules?: { enabled: boolean; defaultOwner: string; severityOwners: Record<Severity, string> };
  runbooks?: Record<Severity, string[]>;
  siem?: SiemSettings;
  businessHours?: Array<{ day: string; enabled: boolean; start: string; end: string }>;
  userBusinessHours?: Array<{ email: string; start: string; end: string }>;
}

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];
const RULE_LABELS: Record<string, string> = { NEW_IP: 'New IP', NEW_COUNTRY: 'New Country', UNKNOWN_DEVICE: 'Unknown Device', IMPOSSIBLE_TRAVEL: 'Impossible Travel', OFF_HOURS: 'Off-Hours', FAILED_MFA: 'Failed MFA', HIGH_RISK: 'High Risk', FAILED_SIGN_IN: 'Failed Authentication' };

export default function SettingsPage() {
  const [settings, setSettings] = useState<SettingsShape>({});
  const [tab, setTab] = useState<Tab>('trial');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState('');
  const [audit, setAudit] = useState<any>({ entries: [], stats: {} });
  const [inbox, setInbox] = useState<any>({ items: [], stats: {} });
  const [newAdmin, setNewAdmin] = useState({ email: '', name: '', role: 'admin', telegramChatId: '' });
  const [editingAdmin, setEditingAdmin] = useState<string | null>(null);
  const [editAdminData, setEditAdminData] = useState({ email: '', name: '', role: 'admin', telegramChatId: '' });
  const [telegram, setTelegram] = useState({ telegramBotToken: '', telegramChatId: '', telegramOnSeverity: ['critical', 'high'] });
  const [telegramSaving, setTelegramSaving] = useState(false);
  const [telegramTest, setTelegramTest] = useState('');
  const [whitelistType, setWhitelistType] = useState<'ips'|'countries'|'devices'|'users'>('ips');
  const [whitelistValue, setWhitelistValue] = useState('');
  const [siem, setSiem] = useState<SiemSettings>({ logAnalytics: { enabled: false, workspaceId: '', sharedKey: '' }, webhooks: [] });
  const [siemTest, setSiemTest] = useState('');
  const [businessHours, setBusinessHours] = useState<Array<{ day: string; enabled: boolean; start: string; end: string }>>(DEFAULT_HOURS);
  const [userHours, setUserHours] = useState<Array<{ email: string; start: string; end: string }>>([]);
  const [newUserHour, setNewUserHour] = useState({ email: '', start: '08:00', end: '18:00' });
  const [playbooks, setPlaybooks] = useState<any[]>([]);

  const load = async () => {
    setLoading(true);
    try {
      const [s, siemSettings, tg] = await Promise.all([
        api.getSettings(),
        api.getSiemSettings().catch(() => ({ logAnalytics: { enabled: false }, webhooks: [] })),
        api.getTelegramSettings().catch(() => ({ telegramBotToken: '', telegramChatId: '', telegramOnSeverity: ['critical', 'high'] }))
      ]);
      setSettings(s);
      setPlaybooks(s.playbooks || []);
      setSiem({ logAnalytics: { enabled: !!siemSettings?.logAnalytics?.enabled, workspaceId: siemSettings?.logAnalytics?.workspaceId || '', sharedKey: siemSettings?.logAnalytics?.sharedKey || '' }, webhooks: Array.isArray(siemSettings?.webhooks) ? siemSettings.webhooks : [] });
      setTelegram({ telegramBotToken: tg.telegramBotToken || '', telegramChatId: tg.telegramChatId || '', telegramOnSeverity: tg.telegramOnSeverity || ['critical', 'high'] });
    } finally { setLoading(false); }
  };

  const loadAudit = async () => {
    if (audit.entries?.length) return;
    try {
      const a = await api.getAudit({ limit: 50 });
      setAudit(a);
    } catch {}
  };

  const loadInbox = async () => {
    if (inbox.items?.length) return;
    try {
      const i = await api.getNotificationInbox({ limit: 50, dedupe: true });
      setInbox(i);
    } catch {}
  };

  useEffect(() => { load(); }, []);
  const flash = (message: string) => { setSaved(message); window.setTimeout(() => setSaved(''), 1800); };
  const savePlaybooks = () => api.patchSettings({ playbooks });

  const saveSettings = async (patch: Partial<SettingsShape>) => {
    setSaving(true);
    try {
      const updated = await api.patchSettings(patch);
      setSettings(updated);
      flash('Saved');
    } finally { setSaving(false); }
  };

  const addAdmin = async () => {
    if (!newAdmin.email.trim()) return;
    await api.addAdmin(newAdmin);
    setNewAdmin({ email: '', name: '', role: 'admin', telegramChatId: '' });
    await load();
    flash('Admin added');
  };
  const removeAdmin = async (email: string) => { await api.removeAdmin(encodeURIComponent(email)); await load(); flash('Admin removed'); };
  const startEditAdmin = (admin: any) => { setEditingAdmin(admin.email); setEditAdminData({ email: admin.email, name: admin.name || '', role: admin.role || 'admin', telegramChatId: admin.telegramChatId || '' }); };
  const saveTelegramSettings = async () => {
    setTelegramSaving(true);
    try {
      const updated = await api.saveTelegramSettings(telegram);
      setTelegram(updated);
      flash('Telegram settings saved');
    } finally { setTelegramSaving(false); }
  };
  const testTelegramNow = async () => {
    setTelegramTest('Sending…');
    try {
      await api.testTelegram();
      setTelegramTest('✅ Sent — check your Telegram');
    } catch (err: any) {
      setTelegramTest('❌ ' + (err.message || 'Failed'));
    }
    setTimeout(() => setTelegramTest(''), 4000);
  };
  const saveEditAdmin = async () => {
    if (!editAdminData.email.trim()) return;
    await api.removeAdmin(encodeURIComponent(editingAdmin!));
    await api.addAdmin(editAdminData);
    setEditingAdmin(null);
    await load();
    flash('Admin updated');
  };
  const addWhitelist = async () => { if (!whitelistValue.trim()) return; await api.addToWhitelist(whitelistType, whitelistValue.trim()); setWhitelistValue(''); await load(); flash('Whitelist updated'); };
  const removeWhitelist = async (type: string, value: string) => { await api.removeFromWhitelist(type, value); await load(); flash('Whitelist updated'); };
  const updateRule = (key: string, patch: Partial<{ enabled: boolean; severity: string }>) => { const rules = { ...(settings.detectionRules || {}) }; rules[key] = { ...rules[key], ...patch } as any; setSettings(prev => ({ ...prev, detectionRules: rules })); };
  const updateAction = (severity: Severity, field: 'revokeSession'|'disableUser'|'telegramPlaybook', value: boolean) => { const autoActions = { ...(settings.autoActions || {}) }; autoActions[severity] = { ...(autoActions[severity] || {}), [field]: value } as any; setSettings(prev => ({ ...prev, autoActions })); };
  const saveAutomation = async () => { setSaving(true); try { await Promise.all([api.saveAssignmentRules(settings.assignmentRules || {}), api.saveApprovalPolicies(settings.approvalPolicies || {}), api.saveRunbooks(settings.runbooks || {})]); await load(); flash('Automation & approvals saved'); } finally { setSaving(false); } };
  const ackNotification = async (id: string) => { await api.ackNotification(id); await load(); };

  const saveSiem = async () => {
    setSaving(true);
    try {
      const updated = await api.saveSiemSettings(siem);
      setSiem(updated || siem);
      flash('SIEM settings saved');
    } finally { setSaving(false); }
  };
  const testLogAnalytics = async () => {
    setSiemTest('Testing connection...');
    try {
      const result = await api.testSiemLogAnalytics({ workspaceId: siem.logAnalytics?.workspaceId || '', sharedKey: siem.logAnalytics?.sharedKey || '' });
      setSiemTest(result?.message || 'Test event sent successfully.');
    } catch (err: any) {
      setSiemTest(err?.message || 'Test failed.');
    }
  };
  const addWebhook = () => setSiem(prev => ({ ...prev, webhooks: [...(prev.webhooks || []), { name: '', url: '', enabled: true }] }));
  const updateWebhook = (index: number, patch: any) => setSiem(prev => ({ ...prev, webhooks: (prev.webhooks || []).map((item, i) => i === index ? { ...item, ...patch } : item) }));
  const removeWebhook = (index: number) => setSiem(prev => ({ ...prev, webhooks: (prev.webhooks || []).filter((_, i) => i !== index) }));

  const trialText = useMemo(() => { const trial = settings.trialStatus; if (!trial) return '—'; if (trial.status === 'active') return 'Active subscription'; if (trial.status === 'trial') return `Free trial · ${trial.daysLeft} days left`; return 'Trial expired'; }, [settings.trialStatus]);
  const tabs: Array<{ id: Tab; label: string; icon: string }> = [
    { id: 'trial', label: 'Plan & Trial', icon: 'ti-credit-card' },
    { id: 'detection', label: 'Detection', icon: 'ti-radar' },
    { id: 'actions', label: 'Auto-Actions', icon: 'ti-bolt' },
    { id: 'admins', label: 'Admins', icon: 'ti-users' },
    { id: 'notifications', label: 'Notifications', icon: 'ti-bell' },
    { id: 'automation', label: 'Automation', icon: 'ti-circuit-switchboard' },
    { id: 'whitelist', label: 'Whitelist', icon: 'ti-shield-check' },
    { id: 'hours', label: 'Business Hours', icon: 'ti-clock' },
    { id: 'siem', label: 'SIEM & Logs', icon: 'ti-database' },
    { id: 'audit', label: 'Audit Log', icon: 'ti-file-search' },
    { id: 'playbooks', label: 'Playbooks', icon: 'ti-list-check' }
  ];

  if (loading) return <div className="loading-state"><div className="loading-spinner" /><div className="loading-text">Loading settings…</div></div>;

  return (
    <div>
      <div className="page-header"><div><div className="page-title">Settings</div><div className="page-subtitle">Per-tenant configuration — detection rules, notifications, admins, approvals, routing, runbooks, and SIEM integrations</div></div>{saved && <div className="role-tag">{saved}</div>}</div>
      <div style={{ display: 'flex', gap: 6, marginBottom: 18, borderBottom: '1px solid var(--navy-border)', overflowX: 'auto', paddingBottom: 2 }}>{tabs.map(t => <button key={t.id} onClick={() => { setTab(t.id); if (t.id === 'audit') loadAudit(); if (t.id === 'notifications') loadInbox(); }} className={`btn btn-sm ${tab === t.id ? 'btn-primary' : 'btn-ghost'}`} style={{ whiteSpace: 'nowrap', display: 'flex', alignItems: 'center', gap: 5 }}><i className={`ti ${t.icon}`} style={{ fontSize: 13 }}></i>{t.label}</button>)}</div>

      {tab === 'trial' && <div className="grid-two-responsive"><div className="card"><div className="card-header"><div className="card-title">Current plan</div></div><div style={{ fontSize: 24, fontWeight: 700, marginBottom: 8 }}>{trialText}</div>{settings.trialStatus?.status !== 'active' && (
              <div className="text-muted" style={{ fontSize: 13 }}>
                Trial end: {settings.billing?.trialEndsAt ? new Date(settings.billing.trialEndsAt).toLocaleString() : '—'}
              </div>
            )}</div><div className="card"><div className="card-header"><div className="card-title">Notification center snapshot</div></div><div className="stats-grid" style={{ marginBottom: 0 }}><div className="stat-card neutral"><div className="stat-value">{inbox.stats?.unread ?? 0}</div><div className="stat-label">Unread</div></div><div className="stat-card amber"><div className="stat-value">{inbox.stats?.approvals ?? 0}</div><div className="stat-label">Approval</div></div><div className="stat-card medium"><div className="stat-value">{inbox.stats?.mentions ?? 0}</div><div className="stat-label">Mentions</div></div><div className="stat-card critical"><div className="stat-value">{inbox.stats?.escalation ?? 0}</div><div className="stat-label">Escalations</div></div></div></div></div>}

      {tab === 'detection' && <div className="card"><div className="card-header"><div className="card-title">Detection rules</div></div><div style={{ display: 'grid', gap: 10 }}>{Object.entries(settings.detectionRules || {}).map(([key, value]) => <div key={key} style={{ display: 'grid', gridTemplateColumns: '1.4fr 120px 120px', gap: 12, alignItems: 'center', borderBottom: '1px solid var(--navy-border)', paddingBottom: 10 }}><div><div style={{ fontWeight: 700 }}>{RULE_LABELS[key] || key}</div><div className="text-muted" style={{ fontSize: 12 }}>{key}</div></div><label style={{ display: 'flex', gap: 8, alignItems: 'center' }}><input type="checkbox" checked={!!value.enabled} onChange={e => updateRule(key, { enabled: e.target.checked })} /> Enabled</label><select className="input" value={value.severity} onChange={e => updateRule(key, { severity: e.target.value })}>{SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}</select></div>)}</div><div style={{ marginTop: 14 }}><button className="btn btn-primary" disabled={saving} onClick={() => saveSettings({ detectionRules: settings.detectionRules })}>Save detection rules</button></div></div>}

      {tab === 'actions' && <div className="card"><div className="card-header"><div className="card-title">Automated actions by severity</div></div><div style={{ display: 'grid', gap: 12 }}>{SEVERITIES.map(sev => <div key={sev} style={{ display: 'grid', gridTemplateColumns: '120px 1fr 1fr 1fr', gap: 12, alignItems: 'center' }}><div style={{ fontWeight: 700, textTransform: 'capitalize' }}>{sev}</div><label><input type="checkbox" checked={!!settings.autoActions?.[sev]?.revokeSession} onChange={e => updateAction(sev, 'revokeSession', e.target.checked)} /> Revoke session</label><label><input type="checkbox" checked={!!settings.autoActions?.[sev]?.disableUser} onChange={e => updateAction(sev, 'disableUser', e.target.checked)} /> Disable user</label><label><input type="checkbox" checked={!!settings.autoActions?.[sev]?.telegramPlaybook} onChange={e => updateAction(sev, 'telegramPlaybook', e.target.checked)} /> Telegram playbook</label></div>)}</div><div style={{ marginTop: 14 }}><button className="btn btn-primary" disabled={saving} onClick={() => saveSettings({ autoActions: settings.autoActions })}>Save auto-actions</button></div></div>}

      {tab === 'admins' && <div className="card">
        <div className="card-header"><div className="card-title">Tenant admins</div></div>
        <div style={{ display: 'grid', gap: 10, marginBottom: 16 }}>
          {(settings.admins || []).map((admin: any) => editingAdmin === admin.email ? (
            <div key={admin.email} style={{ borderBottom: '1px solid var(--navy-border)', paddingBottom: 14 }}>
              <div className="grid-two-responsive" style={{ marginBottom: 8 }}>
                <input className="input" placeholder="Email" value={editAdminData.email} onChange={e => setEditAdminData(p => ({ ...p, email: e.target.value }))} />
                <input className="input" placeholder="Name" value={editAdminData.name} onChange={e => setEditAdminData(p => ({ ...p, name: e.target.value }))} />
                <input className="input" placeholder="Role" value={editAdminData.role} onChange={e => setEditAdminData(p => ({ ...p, role: e.target.value }))} />
                <input className="input" placeholder="Telegram Chat ID (optional)" value={editAdminData.telegramChatId} onChange={e => setEditAdminData(p => ({ ...p, telegramChatId: e.target.value }))} />
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn btn-primary btn-sm" onClick={saveEditAdmin}>Save</button>
                <button className="btn btn-ghost btn-sm" onClick={() => setEditingAdmin(null)}>Cancel</button>
              </div>
            </div>
          ) : (
            <div key={admin.email} style={{ display: 'flex', justifyContent: 'space-between', gap: 12, borderBottom: '1px solid var(--navy-border)', paddingBottom: 10 }}>
              <div>
                <div style={{ fontWeight: 700 }}>{admin.name || admin.email}</div>
                <div className="text-muted" style={{ fontSize: 12 }}>{admin.email} · {admin.role}{admin.telegramChatId ? ` · TG: ${admin.telegramChatId}` : ''}</div>
              </div>
              <div style={{ display: 'flex', gap: 6 }}>
                <button className="btn btn-ghost btn-sm" onClick={() => startEditAdmin(admin)}>Edit</button>
                <button className="btn btn-ghost btn-sm" onClick={() => removeAdmin(admin.email)}>Remove</button>
              </div>
            </div>
          ))}
        </div>
        <div className="grid-two-responsive">
          <input className="input" placeholder="Email" value={newAdmin.email} onChange={e => setNewAdmin(prev => ({ ...prev, email: e.target.value }))} />
          <input className="input" placeholder="Name" value={newAdmin.name} onChange={e => setNewAdmin(prev => ({ ...prev, name: e.target.value }))} />
          <input className="input" placeholder="Role" value={newAdmin.role} onChange={e => setNewAdmin(prev => ({ ...prev, role: e.target.value }))} />
          <input className="input" placeholder="Telegram Chat ID (optional)" value={newAdmin.telegramChatId} onChange={e => setNewAdmin(prev => ({ ...prev, telegramChatId: e.target.value }))} />
        </div>
        <div style={{ marginTop: 14 }}><button className="btn btn-primary" onClick={addAdmin}>Add admin</button></div>
      </div>}

      {tab === 'notifications' && <div style={{ display: 'grid', gap: 16 }}>
        <div className="card">
          <div className="card-header"><div className="card-title">📱 Telegram alerts</div></div>
          <div style={{ display: 'grid', gap: 12 }}>
            <div>
              <div className="text-muted" style={{ fontSize: 12, marginBottom: 6 }}>Bot Token</div>
              <input className="input" type="password" placeholder="e.g. 123456789:AAF..." value={telegram.telegramBotToken} onChange={e => setTelegram(p => ({ ...p, telegramBotToken: e.target.value }))} style={{ fontFamily: 'monospace' }} />
            </div>
            <div>
              <div className="text-muted" style={{ fontSize: 12, marginBottom: 6 }}>Chat ID</div>
              <input className="input" placeholder="e.g. -100123456789" value={telegram.telegramChatId} onChange={e => setTelegram(p => ({ ...p, telegramChatId: e.target.value }))} style={{ fontFamily: 'monospace' }} />
            </div>
            <div>
              <div className="text-muted" style={{ fontSize: 12, marginBottom: 6 }}>Notify on severity</div>
              <div style={{ display: 'flex', gap: 12 }}>
                {['critical','high','medium','low'].map(s => (
                  <label key={s} style={{ display: 'flex', gap: 6, alignItems: 'center', cursor: 'pointer' }}>
                    <input type="checkbox" checked={(telegram.telegramOnSeverity || []).includes(s)}
                      onChange={e => setTelegram(p => ({ ...p, telegramOnSeverity: e.target.checked ? [...(p.telegramOnSeverity || []), s] : (p.telegramOnSeverity || []).filter(x => x !== s) }))} />
                    <span style={{ textTransform: 'capitalize' }}>{s}</span>
                  </label>
                ))}
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <button className="btn btn-primary" disabled={telegramSaving} onClick={saveTelegramSettings}>Save</button>
              <button className="btn btn-ghost" onClick={testTelegramNow} disabled={!telegram.telegramBotToken || !telegram.telegramChatId}>Send test message</button>
              {telegramTest && <span style={{ fontSize: 13, color: telegramTest.startsWith('✅') ? '#4ade80' : '#f87171' }}>{telegramTest}</span>}
            </div>
          </div>
        </div>
        <div className="card">
          <div className="card-header"><div className="card-title">Notification inbox</div></div>
          <div style={{ display: 'grid', gap: 10 }}>{(inbox.items || []).map((item: any) => <div key={item.id} className="detail-card"><div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}><div><div style={{ fontWeight: 700 }}>{item.displayTitle || item.title}</div><div className="text-muted" style={{ fontSize: 12 }}>{item.displaySubtitle || item.kindLabel || item.type}</div></div><button className="btn btn-ghost btn-sm" onClick={() => ackNotification(item.id)}>Acknowledge</button></div>{item.displayDetail ? <div style={{ marginTop: 8 }}>{item.displayDetail}</div> : null}</div>)}
          {!(inbox.items || []).length && <div className="empty-state"><div className="empty-icon">🔔</div><div className="empty-text">No notifications</div></div>}
          </div>
        </div>
      </div>}

      {tab === 'automation' && <div className="card"><div className="card-header"><div className="card-title">Automation & approvals</div></div><div className="text-muted" style={{ marginBottom: 12 }}>Save assignment rules, approval policies, and runbooks for this tenant.</div><button className="btn btn-primary" disabled={saving} onClick={saveAutomation}>Save automation & approvals</button></div>}

      {tab === 'whitelist' && <div className="card">
        <div className="card-header"><div className="card-title">Whitelist</div></div>
        <div style={{ display: 'flex', gap: 8, marginBottom: 20 }}>
          <select className="input" style={{ maxWidth: 160 }} value={whitelistType} onChange={e => setWhitelistType(e.target.value as any)}>
            <option value="ips">IP Address</option>
            <option value="countries">Country</option>
            <option value="devices">Device</option>
            <option value="users">User</option>
          </select>
          <input className="input" placeholder="Enter value…" value={whitelistValue} onChange={e => setWhitelistValue(e.target.value)} onKeyDown={e => e.key === 'Enter' && addWhitelist()} />
          <button className="btn btn-primary" onClick={addWhitelist}>Add</button>
        </div>
        <div style={{ display: 'grid', gap: 16 }}>
          {([['ips','IP Addresses'],['countries','Countries'],['devices','Devices'],['users','Users']] as const).map(([type, label]) => (
            <div key={type}>
              <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.6px', color: 'var(--text-muted)', marginBottom: 8 }}>{label}</div>
              {(settings.whitelist?.[type] || []).length === 0
                ? <div className="text-muted" style={{ fontSize: 12 }}>No entries</div>
                : <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                    {(settings.whitelist?.[type] || []).map(v => (
                      <button key={v} className="btn btn-ghost btn-sm" onClick={() => removeWhitelist(type, v)} style={{ fontSize: 12 }}>{v} ×</button>
                    ))}
                  </div>
              }
            </div>
          ))}
        </div>
      </div>}

      {tab === 'hours' && <div style={{ display: 'grid', gap: 16 }}>
        <div className="card">
          <div className="card-header"><div className="card-title">General Business Hours</div></div>
          <div className="text-muted" style={{ fontSize: 12, marginBottom: 16 }}>Define working hours used by alert scoring and Off-Hours detection rules.</div>
          <div style={{ display: 'grid', gap: 8 }}>
            {businessHours.map((row, i) => (
              <div key={row.day} style={{ display: 'grid', gridTemplateColumns: '120px 80px 110px 16px 110px', gap: 12, alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--navy-border)' }}>
                <label style={{ display: 'flex', gap: 8, alignItems: 'center', fontWeight: 500 }}>
                  <input type="checkbox" checked={row.enabled} onChange={e => setBusinessHours(prev => prev.map((r,j) => j===i ? {...r, enabled: e.target.checked} : r))} />
                  {row.day}
                </label>
                <span className="text-muted" style={{ fontSize: 12 }}>{row.enabled ? 'Active' : 'Off'}</span>
                <input type="time" className="input" value={row.start} disabled={!row.enabled} onChange={e => setBusinessHours(prev => prev.map((r,j) => j===i ? {...r, start: e.target.value} : r))} />
                <span className="text-muted" style={{ textAlign: 'center' }}>→</span>
                <input type="time" className="input" value={row.end} disabled={!row.enabled} onChange={e => setBusinessHours(prev => prev.map((r,j) => j===i ? {...r, end: e.target.value} : r))} />
              </div>
            ))}
          </div>
          <div style={{ marginTop: 16 }}>
            <button className="btn btn-primary" disabled={saving} onClick={() => saveSettings({ businessHours })}>Save business hours</button>
          </div>
        </div>

        <div className="card">
          <div className="card-header"><div className="card-title">Per-User Overrides</div></div>
          <div className="text-muted" style={{ fontSize: 12, marginBottom: 16 }}>Override hours for specific users (e.g. shift workers, overseas employees).</div>
          <div style={{ display: 'grid', gap: 8, marginBottom: 16 }}>
            {userHours.map((u, i) => (
              <div key={u.email} style={{ display: 'grid', gridTemplateColumns: '1fr 110px 16px 110px auto', gap: 10, alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--navy-border)' }}>
                <div style={{ fontWeight: 500, fontSize: 13 }}>{u.email}</div>
                <input type="time" className="input" value={u.start} onChange={e => setUserHours(prev => prev.map((r,j) => j===i ? {...r, start: e.target.value} : r))} />
                <span className="text-muted" style={{ textAlign: 'center' }}>→</span>
                <input type="time" className="input" value={u.end} onChange={e => setUserHours(prev => prev.map((r,j) => j===i ? {...r, end: e.target.value} : r))} />
                <button className="btn btn-ghost btn-sm" onClick={() => setUserHours(prev => prev.filter((_,j) => j!==i))}>×</button>
              </div>
            ))}
            {userHours.length === 0 && <div className="text-muted" style={{ fontSize: 12 }}>No overrides configured.</div>}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 110px 16px 110px auto', gap: 10, alignItems: 'center' }}>
            <input className="input" placeholder="user@company.com" value={newUserHour.email} onChange={e => setNewUserHour(p => ({...p, email: e.target.value}))} />
            <input type="time" className="input" value={newUserHour.start} onChange={e => setNewUserHour(p => ({...p, start: e.target.value}))} />
            <span className="text-muted" style={{ textAlign: 'center' }}>→</span>
            <input type="time" className="input" value={newUserHour.end} onChange={e => setNewUserHour(p => ({...p, end: e.target.value}))} />
            <button className="btn btn-primary btn-sm" onClick={() => { if (!newUserHour.email.trim()) return; setUserHours(p => [...p, {...newUserHour}]); setNewUserHour({ email: '', start: '08:00', end: '18:00' }); }}>Add</button>
          </div>
          <div style={{ marginTop: 14 }}>
            <button className="btn btn-primary" disabled={saving} onClick={() => saveSettings({ userBusinessHours: userHours })}>Save overrides</button>
          </div>
        </div>
      </div>}

      {tab === 'siem' && <div className="grid-two-responsive"><div className="card"><div className="card-header"><div className="card-title">Azure Log Analytics</div></div><label style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 12 }}><input type="checkbox" checked={!!siem.logAnalytics?.enabled} onChange={e => setSiem(prev => ({ ...prev, logAnalytics: { ...(prev.logAnalytics || {}), enabled: e.target.checked } }))} /> Enabled</label><input className="input" placeholder="Workspace ID" value={siem.logAnalytics?.workspaceId || ''} onChange={e => setSiem(prev => ({ ...prev, logAnalytics: { ...(prev.logAnalytics || {}), workspaceId: e.target.value } }))} style={{ marginBottom: 10 }} /><input className="input" placeholder="Shared key" value={siem.logAnalytics?.sharedKey || ''} onChange={e => setSiem(prev => ({ ...prev, logAnalytics: { ...(prev.logAnalytics || {}), sharedKey: e.target.value } }))} /><div className="text-muted" style={{ fontSize: 12, marginTop: 10 }}>Use this to forward alerts into Log Analytics / Sentinel.</div><div style={{ display: 'flex', gap: 8, marginTop: 14 }}><button className="btn btn-primary" disabled={saving} onClick={saveSiem}>Save SIEM settings</button><button className="btn btn-ghost" onClick={testLogAnalytics}>Send test event</button></div>{siemTest ? <div className="detail-card" style={{ marginTop: 12 }}>{siemTest}</div> : null}</div><div className="card"><div className="card-header"><div className="card-title">Outbound webhooks</div></div><div style={{ display: 'grid', gap: 10 }}>{(siem.webhooks || []).map((hook, index) => <div key={index} className="detail-card"><input className="input" placeholder="Name" value={hook.name || ''} onChange={e => updateWebhook(index, { name: e.target.value })} style={{ marginBottom: 8 }} /><input className="input" placeholder="Webhook URL" value={hook.url || ''} onChange={e => updateWebhook(index, { url: e.target.value })} style={{ marginBottom: 8 }} /><label style={{ display: 'flex', gap: 8, alignItems: 'center' }}><input type="checkbox" checked={hook.enabled !== false} onChange={e => updateWebhook(index, { enabled: e.target.checked })} /> Enabled</label><div style={{ marginTop: 10 }}><button className="btn btn-ghost btn-sm" onClick={() => removeWebhook(index)}>Remove webhook</button></div></div>)}</div><div style={{ display: 'flex', gap: 8, marginTop: 14 }}><button className="btn btn-ghost" onClick={addWebhook}>Add webhook</button><button className="btn btn-primary" disabled={saving} onClick={saveSiem}>Save webhooks</button></div></div></div>}

      {tab === 'audit' && <div className="card"><div className="card-header"><div className="card-title">Audit log</div></div><div className="stats-grid" style={{ marginBottom: 14 }}><div className="stat-card neutral"><div className="stat-value">{audit.stats?.total ?? 0}</div><div className="stat-label">Total</div></div><div className="stat-card amber"><div className="stat-value">{audit.stats?.today ?? 0}</div><div className="stat-label">Today</div></div></div><div style={{ display: 'grid', gap: 8 }}>{(audit.entries || []).map((entry: any, index: number) => <div key={index} className="detail-card"><div style={{ fontWeight: 700 }}>{entry.action || 'event'}</div><div className="text-muted" style={{ fontSize: 12 }}>{entry.actor || 'system'} · {entry.timestamp ? new Date(entry.timestamp).toLocaleString() : '-'}</div><pre className="json-box" style={{ marginTop: 10 }}>{JSON.stringify(entry.details || entry, null, 2)}</pre></div>)}</div></div>}

      {tab === 'playbooks' && <PlaybooksPanel playbooks={playbooks} setPlaybooks={setPlaybooks} onSave={savePlaybooks} saving={saving} />}
    </div>
  );
}

// ─── Playbooks Panel ─────────────────────────────────────────────────────────

type PlaybookConditionField = 'severity' | 'country' | 'hour' | 'anomalyType';
type PlaybookActionType = 'revokeSessions' | 'disableUser' | 'sendTelegram' | 'createCase' | 'notifyAdmin';

interface PlaybookCondition {
  field: PlaybookConditionField;
  operator: string;
  value: string;
}

interface PlaybookAction {
  type: PlaybookActionType;
}

interface Playbook {
  id: string;
  name: string;
  enabled: boolean;
  conditionOperator: 'AND' | 'OR';
  conditions: PlaybookCondition[];
  actions: PlaybookAction[];
  cooldownMinutes: number;
}

const FIELD_OPERATORS: Record<PlaybookConditionField, string[]> = {
  severity: ['gte', 'lte'],
  hour: ['gte', 'lte'],
  country: ['in', 'notIn'],
  anomalyType: ['eq'],
};

const OPERATOR_LABELS: Record<string, string> = {
  gte: '>=',
  lte: '<=',
  in: 'in',
  notIn: 'not in',
  eq: '=',
};

const ACTION_TYPE_LABELS: Record<PlaybookActionType, string> = {
  revokeSessions: 'Revoke Sessions',
  disableUser: 'Disable User',
  sendTelegram: 'Send Telegram',
  createCase: 'Create Case',
  notifyAdmin: 'Notify Admin',
};

function makeId() {
  return Math.random().toString(36).slice(2, 10);
}

function emptyPlaybook(): Playbook {
  return {
    id: makeId(),
    name: '',
    enabled: true,
    conditionOperator: 'AND',
    conditions: [],
    actions: [],
    cooldownMinutes: 30,
  };
}

function PlaybooksPanel({
  playbooks,
  setPlaybooks,
  onSave,
  saving,
}: {
  playbooks: any[];
  setPlaybooks: (p: any[]) => void;
  onSave: () => void;
  saving: boolean;
}) {
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [draft, setDraft] = useState<Playbook>(emptyPlaybook());

  const openAdd = () => {
    setDraft(emptyPlaybook());
    setEditingId(null);
    setShowForm(true);
  };

  const openEdit = (pb: Playbook) => {
    setDraft({ ...pb, conditions: [...pb.conditions], actions: [...pb.actions] });
    setEditingId(pb.id);
    setShowForm(true);
  };

  const cancelForm = () => {
    setShowForm(false);
    setEditingId(null);
  };

  const commitForm = () => {
    if (!draft.name.trim()) return;
    if (editingId) {
      setPlaybooks(playbooks.map(p => (p.id === editingId ? { ...draft } : p)));
    } else {
      setPlaybooks([...playbooks, { ...draft }]);
    }
    setShowForm(false);
    setEditingId(null);
  };

  const deletePlaybook = (id: string) => {
    setPlaybooks(playbooks.filter(p => p.id !== id));
  };

  const toggleEnabled = (id: string) => {
    setPlaybooks(playbooks.map(p => p.id === id ? { ...p, enabled: !p.enabled } : p));
  };

  const addCondition = () => {
    setDraft(prev => ({
      ...prev,
      conditions: [
        ...prev.conditions,
        { field: 'severity', operator: 'gte', value: '' } as PlaybookCondition,
      ],
    }));
  };

  const updateCondition = (index: number, patch: Partial<PlaybookCondition>) => {
    setDraft(prev => {
      const conditions = prev.conditions.map((c, i) => {
        if (i !== index) return c;
        const updated = { ...c, ...patch } as PlaybookCondition;
        // reset operator when field changes
        if (patch.field && patch.field !== c.field) {
          updated.operator = FIELD_OPERATORS[patch.field as PlaybookConditionField][0];
        }
        return updated;
      });
      return { ...prev, conditions };
    });
  };

  const removeCondition = (index: number) => {
    setDraft(prev => ({ ...prev, conditions: prev.conditions.filter((_, i) => i !== index) }));
  };

  const addAction = () => {
    setDraft(prev => ({
      ...prev,
      actions: [...prev.actions, { type: 'revokeSessions' } as PlaybookAction],
    }));
  };

  const updateAction = (index: number, type: PlaybookActionType) => {
    setDraft(prev => ({
      ...prev,
      actions: prev.actions.map((a, i) => (i === index ? { type } : a)),
    }));
  };

  const removeAction = (index: number) => {
    setDraft(prev => ({ ...prev, actions: prev.actions.filter((_, i) => i !== index) }));
  };

  return (
    <div style={{ display: 'grid', gap: 16 }}>
      <div className="card">
        <div className="card-header">
          <div className="card-title">Playbooks</div>
          <button className="btn btn-primary btn-sm" onClick={openAdd} disabled={showForm}>
            + Add Playbook
          </button>
        </div>

        {/* Inline add/edit form */}
        {showForm && (
          <div
            style={{
              border: '1px solid var(--navy-border)',
              borderRadius: 8,
              padding: 16,
              marginBottom: 16,
              background: 'rgba(0,0,0,0.15)',
            }}
          >
            <div style={{ fontWeight: 600, marginBottom: 12 }}>
              {editingId ? 'Edit Playbook' : 'New Playbook'}
            </div>

            {/* Name + Enabled */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 10, marginBottom: 10, alignItems: 'center' }}>
              <input
                className="input"
                placeholder="Playbook name *"
                value={draft.name}
                onChange={e => setDraft(prev => ({ ...prev, name: e.target.value }))}
              />
              <label style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 13, whiteSpace: 'nowrap' }}>
                <input
                  type="checkbox"
                  checked={draft.enabled}
                  onChange={e => setDraft(prev => ({ ...prev, enabled: e.target.checked }))}
                />
                Enabled
              </label>
            </div>

            {/* Condition operator */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Condition operator:</span>
              <select
                className="input"
                style={{ width: 100 }}
                value={draft.conditionOperator}
                onChange={e =>
                  setDraft(prev => ({
                    ...prev,
                    conditionOperator: e.target.value as 'AND' | 'OR',
                  }))
                }
              >
                <option value="AND">AND</option>
                <option value="OR">OR</option>
              </select>
            </div>

            {/* Conditions */}
            <div style={{ marginBottom: 10 }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 6 }}>
                Conditions
              </div>
              <div style={{ display: 'grid', gap: 6 }}>
                {draft.conditions.map((cond, i) => (
                  <div key={i} style={{ display: 'grid', gridTemplateColumns: '130px 90px 1fr auto', gap: 6, alignItems: 'center' }}>
                    <select
                      className="input"
                      value={cond.field}
                      onChange={e =>
                        updateCondition(i, { field: e.target.value as PlaybookConditionField })
                      }
                    >
                      <option value="severity">severity</option>
                      <option value="country">country</option>
                      <option value="hour">hour</option>
                      <option value="anomalyType">anomalyType</option>
                    </select>
                    <select
                      className="input"
                      value={cond.operator}
                      onChange={e => updateCondition(i, { operator: e.target.value })}
                    >
                      {FIELD_OPERATORS[cond.field].map(op => (
                        <option key={op} value={op}>
                          {OPERATOR_LABELS[op] || op}
                        </option>
                      ))}
                    </select>
                    <input
                      className="input"
                      placeholder="value"
                      value={cond.value}
                      onChange={e => updateCondition(i, { value: e.target.value })}
                    />
                    <button className="btn btn-ghost btn-sm" onClick={() => removeCondition(i)}>
                      ×
                    </button>
                  </div>
                ))}
              </div>
              <button className="btn btn-ghost btn-sm" style={{ marginTop: 6 }} onClick={addCondition}>
                + Add condition
              </button>
            </div>

            {/* Actions */}
            <div style={{ marginBottom: 10 }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 6 }}>
                Actions
              </div>
              <div style={{ display: 'grid', gap: 6 }}>
                {draft.actions.map((action, i) => (
                  <div key={i} style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 6, alignItems: 'center' }}>
                    <select
                      className="input"
                      value={action.type}
                      onChange={e => updateAction(i, e.target.value as PlaybookActionType)}
                    >
                      {(Object.keys(ACTION_TYPE_LABELS) as PlaybookActionType[]).map(t => (
                        <option key={t} value={t}>
                          {ACTION_TYPE_LABELS[t]}
                        </option>
                      ))}
                    </select>
                    <button className="btn btn-ghost btn-sm" onClick={() => removeAction(i)}>
                      ×
                    </button>
                  </div>
                ))}
              </div>
              <button className="btn btn-ghost btn-sm" style={{ marginTop: 6 }} onClick={addAction}>
                + Add action
              </button>
            </div>

            {/* Cooldown */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Cooldown (minutes):</span>
              <input
                className="input"
                type="number"
                min={0}
                style={{ width: 90 }}
                value={draft.cooldownMinutes}
                onChange={e =>
                  setDraft(prev => ({
                    ...prev,
                    cooldownMinutes: parseInt(e.target.value, 10) || 0,
                  }))
                }
              />
            </div>

            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn btn-primary btn-sm" onClick={commitForm} disabled={!draft.name.trim()}>
                {editingId ? 'Update' : 'Add'}
              </button>
              <button className="btn btn-ghost btn-sm" onClick={cancelForm}>
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Playbook list */}
        {playbooks.length === 0 && !showForm && (
          <div className="empty-state">
            <div>No playbooks configured. Click "+ Add Playbook" to create one.</div>
          </div>
        )}

        {playbooks.length > 0 && (
          <div style={{ display: 'grid', gap: 8 }}>
            {playbooks.map((pb: Playbook) => (
              <div
                key={pb.id}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '1fr auto',
                  gap: 12,
                  alignItems: 'center',
                  padding: '10px 0',
                  borderBottom: '1px solid var(--navy-border)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <label style={{ display: 'flex', gap: 6, alignItems: 'center', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={pb.enabled}
                      onChange={() => toggleEnabled(pb.id)}
                    />
                  </label>
                  <div>
                    <div style={{ fontWeight: 600 }}>{pb.name}</div>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                      {pb.conditions?.length ?? 0} condition(s) · {pb.actions?.length ?? 0} action(s) · {pb.conditionOperator} · cooldown {pb.cooldownMinutes ?? 30}m
                    </div>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 6 }}>
                  <button className="btn btn-ghost btn-sm" onClick={() => openEdit(pb)}>
                    Edit
                  </button>
                  <button className="btn btn-danger btn-sm" onClick={() => deletePlaybook(pb.id)}>
                    Delete
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        <div style={{ marginTop: 16 }}>
          <button className="btn btn-primary" disabled={saving} onClick={onSave}>
            Save Playbooks
          </button>
        </div>
      </div>
    </div>
  );
}
