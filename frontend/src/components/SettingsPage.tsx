import React, { useEffect, useMemo, useState } from 'react';
import { api } from '../services/api';

type Severity = 'critical' | 'high' | 'medium' | 'low';
type Tab = 'trial' | 'detection' | 'actions' | 'admins' | 'notifications' | 'automation' | 'whitelist' | 'siem' | 'audit';

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
}

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];
const RULE_LABELS: Record<string, string> = { NEW_IP: 'New IP', NEW_COUNTRY: 'New Country', UNKNOWN_DEVICE: 'Unknown Device', IMPOSSIBLE_TRAVEL: 'Impossible Travel', OFF_HOURS: 'Off-Hours', FAILED_MFA: 'Failed MFA', HIGH_RISK: 'High Risk' };

export default function SettingsPage() {
  const [settings, setSettings] = useState<SettingsShape>({});
  const [tab, setTab] = useState<Tab>('trial');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState('');
  const [audit, setAudit] = useState<any>({ entries: [], stats: {} });
  const [inbox, setInbox] = useState<any>({ items: [], stats: {} });
  const [newAdmin, setNewAdmin] = useState({ email: '', name: '', role: 'admin', telegramChatId: '' });
  const [whitelistType, setWhitelistType] = useState<'ips'|'countries'|'devices'|'users'>('ips');
  const [whitelistValue, setWhitelistValue] = useState('');
  const [siem, setSiem] = useState<SiemSettings>({ logAnalytics: { enabled: false, workspaceId: '', sharedKey: '' }, webhooks: [] });
  const [siemTest, setSiemTest] = useState('');

  const load = async () => {
    setLoading(true);
    try {
      const [s, siemSettings] = await Promise.all([
        fetch('/api/settings', { credentials: 'include' }).then(r => r.json()),
        api.getSiemSettings().catch(() => ({ logAnalytics: { enabled: false }, webhooks: [] }))
      ]);
      setSettings(s);
      setSiem({ logAnalytics: { enabled: !!siemSettings?.logAnalytics?.enabled, workspaceId: siemSettings?.logAnalytics?.workspaceId || '', sharedKey: siemSettings?.logAnalytics?.sharedKey || '' }, webhooks: Array.isArray(siemSettings?.webhooks) ? siemSettings.webhooks : [] });
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

  const saveSettings = async (patch: Partial<SettingsShape>) => {
    setSaving(true);
    try {
      const res = await fetch('/api/settings', { method: 'PATCH', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(patch) });
      const updated = await res.json();
      setSettings(updated);
      flash('Saved');
    } finally { setSaving(false); }
  };

  const addAdmin = async () => {
    if (!newAdmin.email.trim()) return;
    await fetch('/api/settings/admins', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(newAdmin) });
    setNewAdmin({ email: '', name: '', role: 'admin', telegramChatId: '' });
    await load();
    flash('Admin added');
  };
  const removeAdmin = async (email: string) => { await fetch('/api/settings/admins/' + encodeURIComponent(email), { method: 'DELETE', credentials: 'include' }); await load(); flash('Admin removed'); };
  const addWhitelist = async () => { if (!whitelistValue.trim()) return; await fetch('/api/settings/whitelist/' + whitelistType, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ value: whitelistValue.trim() }) }); setWhitelistValue(''); await load(); flash('Whitelist updated'); };
  const removeWhitelist = async (type: string, value: string) => { await fetch('/api/settings/whitelist/' + type + '/' + encodeURIComponent(value), { method: 'DELETE', credentials: 'include' }); await load(); flash('Whitelist updated'); };
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
    { id: 'trial', label: 'Plan & Trial', icon: '💳' },
    { id: 'detection', label: 'Detection', icon: '🔎' },
    { id: 'actions', label: 'Auto-Actions', icon: '⚡' },
    { id: 'admins', label: 'Admins', icon: '👥' },
    { id: 'notifications', label: 'Notifications', icon: '🔔' },
    { id: 'automation', label: 'Automation & Approvals', icon: '🧠' },
    { id: 'whitelist', label: 'Whitelist', icon: '✅' },
    { id: 'siem', label: 'SIEM & Log Analytics', icon: '📡' },
    { id: 'audit', label: 'Audit Log', icon: '📋' }
  ];

  if (loading) return <div className="loading-state"><div className="loading-spinner" /><div className="loading-text">Loading settings…</div></div>;

  return (
    <div>
      <div className="page-header"><div><div className="page-title">Settings</div><div className="page-subtitle">Per-tenant configuration — detection rules, notifications, admins, approvals, routing, runbooks, and SIEM integrations</div></div>{saved && <div className="role-tag">{saved}</div>}</div>
      <div style={{ display: 'flex', gap: 6, marginBottom: 18, borderBottom: '1px solid var(--navy-border)', overflowX: 'auto', paddingBottom: 2 }}>{tabs.map(t => <button key={t.id} onClick={() => { setTab(t.id); if (t.id === 'audit') loadAudit(); if (t.id === 'notifications') loadInbox(); }} className={`btn btn-sm ${tab === t.id ? 'btn-primary' : 'btn-ghost'}`} style={{ whiteSpace: 'nowrap' }}>{t.icon} {t.label}</button>)}</div>

      {tab === 'trial' && <div className="grid-two-responsive"><div className="card"><div className="card-header"><div className="card-title">Current plan</div></div><div style={{ fontSize: 24, fontWeight: 700, marginBottom: 8 }}>{trialText}</div><div className="text-muted" style={{ fontSize: 13 }}>Trial end: {settings.billing?.trialEndsAt ? new Date(settings.billing.trialEndsAt).toLocaleString() : '—'}</div></div><div className="card"><div className="card-header"><div className="card-title">Notification center snapshot</div></div><div className="stats-grid" style={{ marginBottom: 0 }}><div className="stat-card neutral"><div className="stat-value">{inbox.stats?.unread ?? 0}</div><div className="stat-label">Unread</div></div><div className="stat-card amber"><div className="stat-value">{inbox.stats?.approvals ?? 0}</div><div className="stat-label">Approval</div></div><div className="stat-card medium"><div className="stat-value">{inbox.stats?.mentions ?? 0}</div><div className="stat-label">Mentions</div></div><div className="stat-card critical"><div className="stat-value">{inbox.stats?.escalation ?? 0}</div><div className="stat-label">Escalations</div></div></div></div></div>}

      {tab === 'detection' && <div className="card"><div className="card-header"><div className="card-title">Detection rules</div></div><div style={{ display: 'grid', gap: 10 }}>{Object.entries(settings.detectionRules || {}).map(([key, value]) => <div key={key} style={{ display: 'grid', gridTemplateColumns: '1.4fr 120px 120px', gap: 12, alignItems: 'center', borderBottom: '1px solid var(--navy-border)', paddingBottom: 10 }}><div><div style={{ fontWeight: 700 }}>{RULE_LABELS[key] || key}</div><div className="text-muted" style={{ fontSize: 12 }}>{key}</div></div><label style={{ display: 'flex', gap: 8, alignItems: 'center' }}><input type="checkbox" checked={!!value.enabled} onChange={e => updateRule(key, { enabled: e.target.checked })} /> Enabled</label><select className="input" value={value.severity} onChange={e => updateRule(key, { severity: e.target.value })}>{SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}</select></div>)}</div><div style={{ marginTop: 14 }}><button className="btn btn-primary" disabled={saving} onClick={() => saveSettings({ detectionRules: settings.detectionRules })}>Save detection rules</button></div></div>}

      {tab === 'actions' && <div className="card"><div className="card-header"><div className="card-title">Automated actions by severity</div></div><div style={{ display: 'grid', gap: 12 }}>{SEVERITIES.map(sev => <div key={sev} style={{ display: 'grid', gridTemplateColumns: '120px 1fr 1fr 1fr', gap: 12, alignItems: 'center' }}><div style={{ fontWeight: 700, textTransform: 'capitalize' }}>{sev}</div><label><input type="checkbox" checked={!!settings.autoActions?.[sev]?.revokeSession} onChange={e => updateAction(sev, 'revokeSession', e.target.checked)} /> Revoke session</label><label><input type="checkbox" checked={!!settings.autoActions?.[sev]?.disableUser} onChange={e => updateAction(sev, 'disableUser', e.target.checked)} /> Disable user</label><label><input type="checkbox" checked={!!settings.autoActions?.[sev]?.telegramPlaybook} onChange={e => updateAction(sev, 'telegramPlaybook', e.target.checked)} /> Telegram playbook</label></div>)}</div><div style={{ marginTop: 14 }}><button className="btn btn-primary" disabled={saving} onClick={() => saveSettings({ autoActions: settings.autoActions })}>Save auto-actions</button></div></div>}

      {tab === 'admins' && <div className="card"><div className="card-header"><div className="card-title">Tenant admins</div></div><div style={{ display: 'grid', gap: 10, marginBottom: 16 }}>{(settings.admins || []).map(admin => <div key={admin.email} style={{ display: 'flex', justifyContent: 'space-between', gap: 12, borderBottom: '1px solid var(--navy-border)', paddingBottom: 10 }}><div><div style={{ fontWeight: 700 }}>{admin.name || admin.email}</div><div className="text-muted" style={{ fontSize: 12 }}>{admin.email} · {admin.role}</div></div><button className="btn btn-ghost btn-sm" onClick={() => removeAdmin(admin.email)}>Remove</button></div>)}</div><div className="grid-two-responsive"><input className="input" placeholder="Email" value={newAdmin.email} onChange={e => setNewAdmin(prev => ({ ...prev, email: e.target.value }))} /><input className="input" placeholder="Name" value={newAdmin.name} onChange={e => setNewAdmin(prev => ({ ...prev, name: e.target.value }))} /><input className="input" placeholder="Role" value={newAdmin.role} onChange={e => setNewAdmin(prev => ({ ...prev, role: e.target.value }))} /><input className="input" placeholder="Telegram Chat ID (optional)" value={newAdmin.telegramChatId} onChange={e => setNewAdmin(prev => ({ ...prev, telegramChatId: e.target.value }))} /></div><div style={{ marginTop: 14 }}><button className="btn btn-primary" onClick={addAdmin}>Add admin</button></div></div>}

      {tab === 'notifications' && <div className="card"><div className="card-header"><div className="card-title">Notification inbox</div></div><div style={{ display: 'grid', gap: 10 }}>{(inbox.items || []).map((item: any) => <div key={item.id} className="detail-card"><div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}><div><div style={{ fontWeight: 700 }}>{item.displayTitle || item.title}</div><div className="text-muted" style={{ fontSize: 12 }}>{item.displaySubtitle || item.kindLabel || item.type}</div></div><button className="btn btn-ghost btn-sm" onClick={() => ackNotification(item.id)}>Acknowledge</button></div>{item.displayDetail ? <div style={{ marginTop: 8 }}>{item.displayDetail}</div> : null}</div>)}</div></div>}

      {tab === 'automation' && <div className="card"><div className="card-header"><div className="card-title">Automation & approvals</div></div><div className="text-muted" style={{ marginBottom: 12 }}>Save assignment rules, approval policies, and runbooks for this tenant.</div><button className="btn btn-primary" disabled={saving} onClick={saveAutomation}>Save automation & approvals</button></div>}

      {tab === 'whitelist' && <div className="card"><div className="card-header"><div className="card-title">Whitelist</div></div><div style={{ display: 'flex', gap: 8, marginBottom: 16 }}><select className="input" value={whitelistType} onChange={e => setWhitelistType(e.target.value as any)}><option value="ips">IP</option><option value="countries">Country</option><option value="devices">Device</option><option value="users">User</option></select><input className="input" placeholder="Value" value={whitelistValue} onChange={e => setWhitelistValue(e.target.value)} /><button className="btn btn-primary" onClick={addWhitelist}>Add</button></div><div style={{ display: 'grid', gap: 12 }}>{(['ips', 'countries', 'devices', 'users'] as const).map(type => <div key={type}><div className="label" style={{ marginBottom: 6 }}>{type}</div><div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>{(settings.whitelist?.[type] || []).map(value => <button key={value} className="btn btn-ghost btn-sm" onClick={() => removeWhitelist(type, value)}>{value} ×</button>)}</div></div>)}</div></div>}

      {tab === 'siem' && <div className="grid-two-responsive"><div className="card"><div className="card-header"><div className="card-title">Azure Log Analytics</div></div><label style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 12 }}><input type="checkbox" checked={!!siem.logAnalytics?.enabled} onChange={e => setSiem(prev => ({ ...prev, logAnalytics: { ...(prev.logAnalytics || {}), enabled: e.target.checked } }))} /> Enabled</label><input className="input" placeholder="Workspace ID" value={siem.logAnalytics?.workspaceId || ''} onChange={e => setSiem(prev => ({ ...prev, logAnalytics: { ...(prev.logAnalytics || {}), workspaceId: e.target.value } }))} style={{ marginBottom: 10 }} /><input className="input" placeholder="Shared key" value={siem.logAnalytics?.sharedKey || ''} onChange={e => setSiem(prev => ({ ...prev, logAnalytics: { ...(prev.logAnalytics || {}), sharedKey: e.target.value } }))} /><div className="text-muted" style={{ fontSize: 12, marginTop: 10 }}>Use this to forward alerts into Log Analytics / Sentinel.</div><div style={{ display: 'flex', gap: 8, marginTop: 14 }}><button className="btn btn-primary" disabled={saving} onClick={saveSiem}>Save SIEM settings</button><button className="btn btn-ghost" onClick={testLogAnalytics}>Send test event</button></div>{siemTest ? <div className="detail-card" style={{ marginTop: 12 }}>{siemTest}</div> : null}</div><div className="card"><div className="card-header"><div className="card-title">Outbound webhooks</div></div><div style={{ display: 'grid', gap: 10 }}>{(siem.webhooks || []).map((hook, index) => <div key={index} className="detail-card"><input className="input" placeholder="Name" value={hook.name || ''} onChange={e => updateWebhook(index, { name: e.target.value })} style={{ marginBottom: 8 }} /><input className="input" placeholder="Webhook URL" value={hook.url || ''} onChange={e => updateWebhook(index, { url: e.target.value })} style={{ marginBottom: 8 }} /><label style={{ display: 'flex', gap: 8, alignItems: 'center' }}><input type="checkbox" checked={hook.enabled !== false} onChange={e => updateWebhook(index, { enabled: e.target.checked })} /> Enabled</label><div style={{ marginTop: 10 }}><button className="btn btn-ghost btn-sm" onClick={() => removeWebhook(index)}>Remove webhook</button></div></div>)}</div><div style={{ display: 'flex', gap: 8, marginTop: 14 }}><button className="btn btn-ghost" onClick={addWebhook}>Add webhook</button><button className="btn btn-primary" disabled={saving} onClick={saveSiem}>Save webhooks</button></div></div></div>}

      {tab === 'audit' && <div className="card"><div className="card-header"><div className="card-title">Audit log</div></div><div className="stats-grid" style={{ marginBottom: 14 }}><div className="stat-card neutral"><div className="stat-value">{audit.stats?.total ?? 0}</div><div className="stat-label">Total</div></div><div className="stat-card amber"><div className="stat-value">{audit.stats?.today ?? 0}</div><div className="stat-label">Today</div></div></div><div style={{ display: 'grid', gap: 8 }}>{(audit.entries || []).map((entry: any, index: number) => <div key={index} className="detail-card"><div style={{ fontWeight: 700 }}>{entry.action || 'event'}</div><div className="text-muted" style={{ fontSize: 12 }}>{entry.actor || 'system'} · {entry.timestamp ? new Date(entry.timestamp).toLocaleString() : '-'}</div><pre className="json-box" style={{ marginTop: 10 }}>{JSON.stringify(entry.details || entry, null, 2)}</pre></div>)}</div></div>}
    </div>
  );
}
